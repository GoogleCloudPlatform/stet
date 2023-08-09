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
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"testing"

	"google.golang.org/api/idtoken"
	"google.golang.org/grpc/metadata"

	pb "github.com/GoogleCloudPlatform/stet/proto/secure_session_go_proto"
)

const testJWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qga2lkIiwidHlwIjoiSldUIn0.eyJhdWQiOiJ0ZXN0IGF1ZCIsImV4cCI6MzU4MzI2MTI3NH0.cpGYWeOX-3qXBdA7I9pVVHaJ_r8bPUQMLc9MTZiUR3IWLDdNXlLrPljfsHzpGyp6F7eP6IW9_B4Ie_EuI_3ZwbU9cmVSSloItlQ3qzJNyJ3lZ9PZSG6jMUeQyrYtfagvNApcaCIYiHUikaaW-GJ6ZkI5tJRCdS0Vt-xEdbLAd_um0oJG3m67zkOb3UhKGLIzPRbSlL8N7e5Y23z4zDezpb9_zvd1OaimN31DQXvYW-jMDuxBH887tRBRGU-23Hl_GH3ieXHgHdzfn5Ifcp9bGKAIa37Lbwt_gnurZzEPmtn-McTcamzvGpafj0-OII1zU8lO4FgSYFzoLZWDO5LVMg"

// Audience field in testJWT.
const testAudience = "test aud"

// JWK info corresponding to testJWT.
var testJWKInfo = map[string]any{
	"keys": []map[string]any{
		{
			"alg": "RS256",
			"kid": "test kid",
			"n":   "pR6gUn5QfE1yOX06786vx_Ppg7p5fJ45-rKCXBeZrmfITKqZ2Mr0QwchjFWuFMTI0nx-YBSWqQ2PSRRh7uKrzN3WH2VvYW4DwUzNomNvDWETwaB8DYgcnaO8blaFJDv15CViReJ0sVOtl3uUCm4EBz29g3xU44hYea97Mgyvt7BcYewcfqBegbMNgbxWZhsz7D9jAbUfYEMKIufOXHTncocxOxiy8Gq9zIf4zBKzYw7rdghjqWJcf2ZxvR7MhACb0P8qnS5taAIPYU0bxyUjWYml8RQPaDxWkdrXprhOrccHnpLTil3jC_dCIQAHIEKnJS_h3cV3wokh_HMfhES_ow",
			"e":   "AQAB",
		},
	},
}

func TestNewSecureSessionService(t *testing.T) {
	expectedTLSVersion := uint16(1)
	expectedAudience := testAudience

	service, err := NewSecureSessionService(expectedTLSVersion, expectedAudience)
	if err != nil {
		t.Fatalf("Failed to create SecureSessionService: %v", err)
	}

	if service.audience != expectedAudience {
		t.Errorf("Service does not have expected audience: got %v, want %v", service.audience, expectedAudience)
	}

	if service.tlsVersion != expectedTLSVersion {
		t.Errorf("Service does not have expected tlsVersion: got %v, want %v", service.tlsVersion, expectedTLSVersion)
	}
}

func TestBeginSessionFailsWithNoRecords(t *testing.T) {
	s := SecureSessionService{}

	ctx := context.Background()
	req := &pb.BeginSessionRequest{}
	if _, err := s.BeginSession(ctx, req); err == nil {
		t.Fatalf("Expected BeginSession to fail with no TLS records, but got no error")
	}
}

func TestHandshakeFailsWithNoRecords(t *testing.T) {
	s := SecureSessionService{}

	ctx := context.Background()
	req := &pb.HandshakeRequest{}
	if _, err := s.Handshake(ctx, req); err == nil {
		t.Fatalf("Expected Handshake to fail with no TLS records, but got no error")
	}
}

func TestNegotiateAttestationFailsWithNoRecords(t *testing.T) {
	s := SecureSessionService{}

	ctx := context.Background()
	req := &pb.NegotiateAttestationRequest{}
	if _, err := s.NegotiateAttestation(ctx, req); err == nil {
		t.Fatalf("Expected NegotiateAttestation to fail with no TLS records, but got no error")
	}
}

func TestFinalizeFailsWithNoRecords(t *testing.T) {
	s := SecureSessionService{}

	ctx := context.Background()
	req := &pb.FinalizeRequest{}
	if _, err := s.Finalize(ctx, req); err == nil {
		t.Fatalf("Expected Finalize to fail with no TLS records, but got no error")
	}
}

type testRoundTripper struct {
	roundTripFunc func(req *http.Request) *http.Response
}

func (t *testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return t.roundTripFunc(req), nil
}

func TestVerifyToken(t *testing.T) {
	ctx := context.Background()

	// Add fake Authtoken to context metadata.
	testMetadata := metadata.MD{
		TokenMetadataKey: {TokenPrefix + testJWT},
	}
	ctx = metadata.NewIncomingContext(ctx, testMetadata)

	// Create fake idtoken validator.
	validatorClient := &http.Client{
		Transport: &testRoundTripper{
			roundTripFunc: func(req *http.Request) *http.Response {
				respBytes, err := json.Marshal(testJWKInfo)
				if err != nil {
					t.Fatalf("Unable to marshal server response: %v", err)
				}

				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       ioutil.NopCloser(bytes.NewBuffer(respBytes)),
				}
			},
		},
	}

	validator, err := idtoken.NewValidator(ctx, idtoken.WithHTTPClient(validatorClient))
	if err != nil {
		t.Fatalf("Unable to create test validator: %v", err)
	}

	service := &SecureSessionService{
		audience:           testAudience,
		testTokenValidator: validator,
	}

	if err := service.verifyToken(ctx); err != nil {
		t.Errorf("Failed to verify token: %v", err)
	}
}

func TestVerifyTokenError(t *testing.T) {
	ctx := context.Background()

	testcases := []struct {
		name string
		ctx  context.Context
	}{
		{
			name: "No metadata in context",
			ctx:  ctx,
		},
		{
			name: "Multiple tokens",
			ctx: metadata.NewIncomingContext(ctx, metadata.MD{
				TokenMetadataKey: {TokenPrefix + testJWT, TokenPrefix + "another token"},
			}),
		},
		{
			name: "Validation error",
			ctx: metadata.NewIncomingContext(ctx, metadata.MD{
				TokenMetadataKey: {TokenPrefix + testJWT},
			}),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			// Create fake idtoken validator.
			validatorClient := &http.Client{
				Transport: &testRoundTripper{
					roundTripFunc: func(req *http.Request) *http.Response {
						// Only expect the last test case to reach the validator.
						if tc.name != "Validation error" {
							t.Fatalf("Unexpected call to Validate in \"%s\"testcase", tc.name)
						}

						return &http.Response{
							StatusCode: http.StatusInternalServerError,
							Header:     make(http.Header),
							Body:       ioutil.NopCloser(bytes.NewBuffer([]byte("panic!"))),
						}
					},
				},
			}

			validator, err := idtoken.NewValidator(ctx, idtoken.WithHTTPClient(validatorClient))
			if err != nil {
				t.Fatalf("Unable to create test validator: %v", err)
			}

			service := &SecureSessionService{
				audience:           testAudience,
				testTokenValidator: validator,
			}

			if err := service.verifyToken(ctx); err == nil {
				t.Errorf("VerifyToken returned success, expected error.")
			}
		})
	}

}
