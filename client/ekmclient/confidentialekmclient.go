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

// Package ekmclient defines an HTTP client for contacting Confidential EKM services.
package ekmclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	cwpb "github.com/GoogleCloudPlatform/stet/proto/confidential_wrap_go_proto"
	sspb "github.com/GoogleCloudPlatform/stet/proto/secure_session_go_proto"
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
	tlsAlertRecord               = 21
)

// ConfidentialEKMClient is an HTTP client that has methods for making
// requests to a server implementing the EKM UDE protocol.
type ConfidentialEKMClient struct {
	URI       string
	AuthToken string
	CertPool  *x509.CertPool
}

// NewConfidentialEKMClient constructs a new ConfidentialEKMClient against
// the given URI.
func NewConfidentialEKMClient(uri string) ConfidentialEKMClient {
	return ConfidentialEKMClient{URI: uri}
}

// Removes the last two path component from the key URI.
func removeEndpointPathComponent(url string) string {
	for i := 0; i < 2; i++ {
		substrIndex := strings.LastIndex(url, "/")
		if substrIndex == -1 {
			break
		}
		url = url[0:substrIndex]
	}

	return url
}

func (c ConfidentialEKMClient) post(ctx context.Context, url string, protoReq, protoResp proto.Message) error {
	marshaled, err := protojson.Marshal(protoReq)
	if err != nil {
		return fmt.Errorf("error marshaling request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(marshaled))
	if err != nil {
		return fmt.Errorf("error creating HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	if c.AuthToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.AuthToken)
	}

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: c.CertPool,
			},
		},
	}

	httpResp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("HTTP call returned with error: %w", err)
	}

	defer httpResp.Body.Close()
	respBody, err := ioutil.ReadAll(httpResp.Body)
	if err != nil {
		return fmt.Errorf("error reading HTTP response body: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("non-OK status returned: %s - %s", httpResp.Status, string(respBody))
	}

	if err = protojson.Unmarshal(respBody, protoResp); err != nil {
		return fmt.Errorf("error unmarshaling response: %w", err)
	}

	return nil
}

func (c ConfidentialEKMClient) BeginSession(ctx context.Context, req *sspb.BeginSessionRequest) (*sspb.BeginSessionResponse, error) {
	resp := &sspb.BeginSessionResponse{}
	url := removeEndpointPathComponent(c.URI) + beginSessionEndpoint
	if err := c.post(ctx, url, req, resp); err != nil {
		return nil, err
	}

	if resp.GetTlsRecords()[0] == tlsAlertRecord {
		return resp, fmt.Errorf("TLS alert in response: %s", hex.EncodeToString(resp.GetTlsRecords()))
	}
	return resp, nil
}

func (c ConfidentialEKMClient) Handshake(ctx context.Context, req *sspb.HandshakeRequest) (*sspb.HandshakeResponse, error) {
	resp := &sspb.HandshakeResponse{}
	url := removeEndpointPathComponent(c.URI) + handshakeEndpoint
	if err := c.post(ctx, url, req, resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (c ConfidentialEKMClient) NegotiateAttestation(ctx context.Context, req *sspb.NegotiateAttestationRequest) (*sspb.NegotiateAttestationResponse, error) {
	resp := &sspb.NegotiateAttestationResponse{}
	url := removeEndpointPathComponent(c.URI) + negotiateAttestationEndpoint
	if err := c.post(ctx, url, req, resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (c ConfidentialEKMClient) Finalize(ctx context.Context, req *sspb.FinalizeRequest) (*sspb.FinalizeResponse, error) {
	resp := &sspb.FinalizeResponse{}
	url := removeEndpointPathComponent(c.URI) + finalizeEndpoint
	if err := c.post(ctx, url, req, resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (c ConfidentialEKMClient) EndSession(ctx context.Context, req *sspb.EndSessionRequest) (*sspb.EndSessionResponse, error) {
	resp := &sspb.EndSessionResponse{}
	url := removeEndpointPathComponent(c.URI) + endSessionEndpoint
	if err := c.post(ctx, url, req, resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (c ConfidentialEKMClient) ConfidentialWrap(ctx context.Context, req *cwpb.ConfidentialWrapRequest) (*cwpb.ConfidentialWrapResponse, error) {
	resp := &cwpb.ConfidentialWrapResponse{}
	url := c.URI + confidentialWrapEndpoint
	if err := c.post(ctx, url, req, resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (c ConfidentialEKMClient) ConfidentialUnwrap(ctx context.Context, req *cwpb.ConfidentialUnwrapRequest) (*cwpb.ConfidentialUnwrapResponse, error) {
	resp := &cwpb.ConfidentialUnwrapResponse{}
	url := c.URI + confidentialUnwrapEndpoint
	if err := c.post(ctx, url, req, resp); err != nil {
		return nil, err
	}

	return resp, nil
}
