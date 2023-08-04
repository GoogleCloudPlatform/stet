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
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	cwgrpc "github.com/GoogleCloudPlatform/stet/proto/confidential_wrap_go_proto"
	cwpb "github.com/GoogleCloudPlatform/stet/proto/confidential_wrap_go_proto"
	ssgrpc "github.com/GoogleCloudPlatform/stet/proto/secure_session_go_proto"
	sspb "github.com/GoogleCloudPlatform/stet/proto/secure_session_go_proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	beginSessionEndpoint         = "/session/beginsession"
	handshakeEndpoint            = "/session/handshake"
	negotiateAttestationEndpoint = "/session/negotiateattestation"
	finalizeEndpoint             = "/session/finalize"
	endSessionEndpoint           = "/session/endsession"
	confidentialWrapEndpoint     = ":confidentialwrap"
	confidentialUnwrapEndpoint   = ":confidentialunwrap"
)

// ekmToken is a struct that implements credentials.PerRPCCredentials to
// store a bearer token for authenticating requests to the EKM.
type ekmToken struct {
	token string
}

func (t ekmToken) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{
		TokenMetadataKey: fmt.Sprintf("%s%s", TokenPrefix, t.token),
	}, nil
}

func (ekmToken) RequireTransportSecurity() bool {
	return false
}

// SecureSessionHTTPService is an HTTP-to-gRPC proxy for SecureSessionService, to be used for local testing only.
type SecureSessionHTTPService struct {
	sessionClient ssgrpc.ConfidentialEkmSessionEstablishmentServiceClient
	wrapClient    cwgrpc.ConfidentialWrapUnwrapServiceClient
}

// NewSecureSessionHTTPService creates and returns an instance of SecureSessionHTTPService.
// The Caller should Close using SecureSessionHTTPService.Close() when finished.
func NewSecureSessionHTTPService(address, authToken string) (*SecureSessionHTTPService, error) {
	srv := &SecureSessionHTTPService{}

	if err := srv.connectToGRPCServer(address, authToken); err != nil {
		return nil, fmt.Errorf("error initializing test server: %w", err)
	}

	return srv, nil
}

// NewSecureSessionHTTPServiceWithFakeClients creates and returns an instance of SecureSessionHTTPService
// with the provided fake clients.
// The Caller should Close using SecureSessionHTTPService.Close() when finished.
func NewSecureSessionHTTPServiceWithFakeClients(address, authToken string, sessionClient ssgrpc.ConfidentialEkmSessionEstablishmentServiceClient, wrapClient cwgrpc.ConfidentialWrapUnwrapServiceClient) (*SecureSessionHTTPService, error) {
	if (sessionClient == nil) != (wrapClient == nil) {
		return nil, fmt.Errorf("only one fake client provided, must specify both or neither")
	}

	srv := &SecureSessionHTTPService{
		sessionClient: sessionClient,
		wrapClient:    wrapClient,
	}

	return srv, nil
}

func processHTTPRequest(ctx context.Context, httpReq *http.Request, protoReq proto.Message) (context.Context, error) {
	defer httpReq.Body.Close()
	reqBody, err := ioutil.ReadAll(httpReq.Body)
	if err != nil {
		return ctx, fmt.Errorf("unable to read HTTP request body: %w", err)
	}

	if err = protojson.Unmarshal(reqBody, protoReq); err != nil {
		return ctx, fmt.Errorf("unable to unmarshal HTTP request body: %w", err)
	}

	return metadata.AppendToOutgoingContext(ctx, TokenMetadataKey, httpReq.Header.Get(TokenMetadataKey)), nil
}

func (s *SecureSessionHTTPService) handleBeginSession(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	req := &sspb.BeginSessionRequest{}
	reqCtx, err := processHTTPRequest(ctx, r, req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
	}

	resp, err := s.sessionClient.BeginSession(reqCtx, req)
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

func (s *SecureSessionHTTPService) handleHandshake(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	req := &sspb.HandshakeRequest{}
	reqCtx, err := processHTTPRequest(ctx, r, req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
	}

	resp, err := s.sessionClient.Handshake(reqCtx, req)
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

func (s *SecureSessionHTTPService) handleNegotiateAttestation(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	req := &sspb.NegotiateAttestationRequest{}
	reqCtx, err := processHTTPRequest(ctx, r, req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	resp, err := s.sessionClient.NegotiateAttestation(reqCtx, req)
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

func (s *SecureSessionHTTPService) handleFinalize(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	req := &sspb.FinalizeRequest{}
	reqCtx, err := processHTTPRequest(ctx, r, req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	resp, err := s.sessionClient.Finalize(reqCtx, req)
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

func (s *SecureSessionHTTPService) handleEndSession(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	req := &sspb.EndSessionRequest{}
	reqCtx, err := processHTTPRequest(ctx, r, req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	resp, err := s.sessionClient.EndSession(reqCtx, req)
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

func (s *SecureSessionHTTPService) handleConfidentialWrap(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	req := &cwpb.ConfidentialWrapRequest{}
	reqCtx, err := processHTTPRequest(ctx, r, req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	resp, err := s.wrapClient.ConfidentialWrap(reqCtx, req)
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

func (s *SecureSessionHTTPService) handleConfidentialUnwrap(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	req := &cwpb.ConfidentialUnwrapRequest{}
	reqCtx, err := processHTTPRequest(ctx, r, req)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	resp, err := s.wrapClient.ConfidentialUnwrap(reqCtx, req)
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

// Handler acts as a HandlerFunc for HTTP servers.
func (s *SecureSessionHTTPService) Handler(w http.ResponseWriter, r *http.Request) {
	endpoint := r.URL.String()

	ctx := r.Context()
	if strings.HasSuffix(endpoint, beginSessionEndpoint) {
		s.handleBeginSession(ctx, w, r)
	} else if strings.HasSuffix(endpoint, handshakeEndpoint) {
		s.handleHandshake(ctx, w, r)
	} else if strings.HasSuffix(endpoint, negotiateAttestationEndpoint) {
		s.handleNegotiateAttestation(ctx, w, r)
	} else if strings.HasSuffix(endpoint, finalizeEndpoint) {
		s.handleFinalize(ctx, w, r)
	} else if strings.HasSuffix(endpoint, endSessionEndpoint) {
		s.handleEndSession(ctx, w, r)
	} else if strings.HasSuffix(endpoint, confidentialWrapEndpoint) {
		s.handleConfidentialWrap(ctx, w, r)
	} else if strings.HasSuffix(endpoint, confidentialUnwrapEndpoint) {
		s.handleConfidentialUnwrap(ctx, w, r)
	} else {
		// If no match found, respond with error.
		w.WriteHeader(http.StatusBadRequest)
	}
}

// Initializes gRPC clients and connects to services at given address. Creates and returns httptest server.
func (s *SecureSessionHTTPService) connectToGRPCServer(address, authToken string) error {
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

	return nil
}
