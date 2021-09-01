// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"regexp"

	cwgrpc "github.com/GoogleCloudPlatform/stet/proto/confidential_wrap_go_proto"
	cwpb "github.com/GoogleCloudPlatform/stet/proto/confidential_wrap_go_proto"
	ssgrpc "github.com/GoogleCloudPlatform/stet/proto/secure_session_go_proto"
	sspb "github.com/GoogleCloudPlatform/stet/proto/secure_session_go_proto"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	beginSessionEndpoint         = "/v0/session/begin-session"
	handshakeEndpoint            = "/v0/session/handshake"
	negotiateAttestationEndpoint = "/v0/session/negotiate-attestations"
	finalizeEndpoint             = "/v0/session/finalize"
	endSessionEndpoint           = "/v0/session/end-session"
	confidentialWrapEndpoint     = "/v0/.*:confidential-wrap"
	confidentialUnwrapEndpoint   = "/v0/.*:confidential-unwrap"
)

// ekmToken is a struct that implements credentials.PerRPCCredentials to
// store a bearer token for authenticating requests to the EKM.
type ekmToken struct {
	token string
}

func (t ekmToken) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", t.token),
	}, nil
}

func (ekmToken) RequireTransportSecurity() bool {
	return false
}

// SecureSessionHTTPService is an HTTP-to-gRPC proxy for SecureSessionService, to be used for local testing only.
type SecureSessionHTTPService struct {
	grpcService   *SecureSessionService
	sessionClient ssgrpc.ConfidentialEkmSessionEstablishmentServiceClient
	wrapClient    cwgrpc.ConfidentialWrapUnwrapServiceClient
	httpServer    *httptest.Server
	url           string

	// Fake service clients for unit tests.
	fakeSessionClient ssgrpc.ConfidentialEkmSessionEstablishmentServiceClient
	fakeWrapClient    cwgrpc.ConfidentialWrapUnwrapServiceClient
}

// NewSecureSessionHTTPService creates and returns an instance of SecureSessionHTTPService.
// The Caller should Close using SecureSessionHTTPService.Close() when finished.
func NewSecureSessionHTTPService(address, authToken string) (*SecureSessionHTTPService, error) {
	return NewSecureSessionHTTPServiceWithFakeClients(address, authToken, nil, nil)
}

// NewSecureSessionHTTPServiceWithFakeClients creates and returns an instance of SecureSessionHTTPService
// with the provided fake clients.
// The Caller should Close using SecureSessionHTTPService.Close() when finished.
func NewSecureSessionHTTPServiceWithFakeClients(address, authToken string, sessionClient ssgrpc.ConfidentialEkmSessionEstablishmentServiceClient, wrapClient cwgrpc.ConfidentialWrapUnwrapServiceClient) (*SecureSessionHTTPService, error) {
	if (sessionClient == nil) != (wrapClient == nil) {
		return nil, fmt.Errorf("only one fake client provided, must specify both or neither")
	}

	srv := &SecureSessionHTTPService{
		fakeSessionClient: sessionClient,
		fakeWrapClient:    wrapClient,
	}

	if err := srv.connectToGRPCServer(address, authToken); err != nil {
		return nil, fmt.Errorf("error initializing test server: %w", err)
	}

	return srv, nil
}

func processHTTPRequest(httpReq *http.Request, protoReq proto.Message) error {
	defer httpReq.Body.Close()
	reqBody, err := ioutil.ReadAll(httpReq.Body)
	if err != nil {
		return fmt.Errorf("unable to read HTTP request body: %w", err)
	}

	if err = protojson.Unmarshal(reqBody, protoReq); err != nil {
		return fmt.Errorf("unable to unmarshal HTTP request body: %w", err)
	}

	return nil
}

func (s *SecureSessionHTTPService) handleBeginSession(w http.ResponseWriter, r *http.Request) {
	req := &sspb.BeginSessionRequest{}
	if err := processHTTPRequest(r, req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
	}

	resp, err := s.sessionClient.BeginSession(r.Context(), req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}

	marshaled, err := protojson.Marshal(resp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}

	w.Write(marshaled)
}

func (s *SecureSessionHTTPService) handleHandshake(w http.ResponseWriter, r *http.Request) {
	req := &sspb.HandshakeRequest{}
	if err := processHTTPRequest(r, req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
	}

	resp, err := s.sessionClient.Handshake(r.Context(), req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}

	marshaled, err := protojson.Marshal(resp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}

	w.Write(marshaled)
}

func (s *SecureSessionHTTPService) handleNegotiateAttestation(w http.ResponseWriter, r *http.Request) {
	req := &sspb.NegotiateAttestationRequest{}
	if err := processHTTPRequest(r, req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	resp, err := s.sessionClient.NegotiateAttestation(r.Context(), req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}

	marshaled, err := protojson.Marshal(resp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}

	w.Write(marshaled)
}

func (s *SecureSessionHTTPService) handleFinalize(w http.ResponseWriter, r *http.Request) {
	req := &sspb.FinalizeRequest{}
	if err := processHTTPRequest(r, req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	resp, err := s.sessionClient.Finalize(r.Context(), req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}

	marshaled, err := protojson.Marshal(resp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}

	w.Write(marshaled)
}

func (s *SecureSessionHTTPService) handleEndSession(w http.ResponseWriter, r *http.Request) {
	req := &sspb.EndSessionRequest{}
	if err := processHTTPRequest(r, req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	resp, err := s.sessionClient.EndSession(r.Context(), req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}

	marshaled, err := protojson.Marshal(resp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}

	w.Write(marshaled)
}

func (s *SecureSessionHTTPService) handleConfidentialWrap(w http.ResponseWriter, r *http.Request) {
	req := &cwpb.ConfidentialWrapRequest{}
	if err := processHTTPRequest(r, req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	resp, err := s.wrapClient.ConfidentialWrap(r.Context(), req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}

	marshaled, err := protojson.Marshal(resp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}

	w.Write(marshaled)
}

func (s *SecureSessionHTTPService) handleConfidentialUnwrap(w http.ResponseWriter, r *http.Request) {
	req := &cwpb.ConfidentialUnwrapRequest{}
	if err := processHTTPRequest(r, req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	resp, err := s.wrapClient.ConfidentialUnwrap(r.Context(), req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}

	marshaled, err := protojson.Marshal(resp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	}

	w.Write(marshaled)
}

func (s *SecureSessionHTTPService) handlerfunc(w http.ResponseWriter, r *http.Request) {
	switch endpoint := r.URL.String(); endpoint {
	case beginSessionEndpoint:
		s.handleBeginSession(w, r)

	case handshakeEndpoint:
		s.handleHandshake(w, r)

	case negotiateAttestationEndpoint:
		s.handleNegotiateAttestation(w, r)

	case finalizeEndpoint:
		s.handleFinalize(w, r)

	case endSessionEndpoint:
		s.handleEndSession(w, r)

	default:
		match, err := regexp.MatchString(confidentialWrapEndpoint, endpoint)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else if match {
			s.handleConfidentialWrap(w, r)
			return
		}

		match, err = regexp.MatchString(confidentialUnwrapEndpoint, endpoint)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else if match {
			s.handleConfidentialUnwrap(w, r)
			return
		}

		// If no match found, respond with error.
		w.WriteHeader(http.StatusBadRequest)
	}
}

// Initializes gRPC clients and connects to services at given address. Creates and returns httptest server.
func (s *SecureSessionHTTPService) connectToGRPCServer(address, authToken string) error {
	if s.fakeSessionClient != nil && s.fakeWrapClient != nil {
		s.sessionClient = s.fakeSessionClient
		s.wrapClient = s.fakeWrapClient
	} else {
		grpcOpts := []grpc.DialOption{grpc.WithInsecure()}

		// Add bearer token to requests if present.
		if authToken != "" {
			grpcOpts = append(grpcOpts, grpc.WithPerRPCCredentials(ekmToken{token: authToken}))
		}

		conn, err := grpc.Dial(address, grpcOpts...)
		if err != nil {
			return fmt.Errorf("error creating gRPC client connection: %w", err)
		}

		s.sessionClient = ssgrpc.NewConfidentialEkmSessionEstablishmentServiceClient(conn)
		s.wrapClient = cwgrpc.NewConfidentialWrapUnwrapServiceClient(conn)
	}
	s.httpServer = httptest.NewTLSServer(http.HandlerFunc(s.handlerfunc))

	return nil
}

// Cert returns the certificate of the httptest server.
func (s *SecureSessionHTTPService) Cert() *x509.Certificate {
	return s.httpServer.Certificate()
}

// URL returns the URL of the httptest server.
func (s *SecureSessionHTTPService) URL() string {
	return s.httpServer.URL
}

// Close closes the httptest server.
func (s *SecureSessionHTTPService) Close() {
	s.httpServer.Close()
}
