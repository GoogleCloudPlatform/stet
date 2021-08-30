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

package client

import (
	"context"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"

	cwpb "github.com/GoogleCloudPlatform/stet/proto/confidential_wrap_go_proto"
	sspb "github.com/GoogleCloudPlatform/stet/proto/secure_session_go_proto"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"testing"
)

func TestPost(t *testing.T) {
	authToken := "I am a token."
	expectedReq := &sspb.BeginSessionRequest{TlsRecords: []byte("Hello, World!")}
	expectedResp := &sspb.BeginSessionResponse{SessionContext: []byte("Goodbye"), TlsRecords: []byte("World")}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify HTTP headers.
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("HTTP request does not have expected Content-Type header: got %s, want application/json", r.Header.Get("Content-Type"))
		}

		expectedAuthHeader := "Bearer " + authToken
		if r.Header.Get("Authorization") != expectedAuthHeader {
			t.Errorf("HTTP request does not have expected Authorization header: got %s, want %s", r.Header.Get("Authorization"), expectedAuthHeader)
		}

		// Verify HTTP Request body.
		defer r.Body.Close()
		reqBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Error reading HTTP request body: %s", err)
		}

		req := &sspb.BeginSessionRequest{}
		if err = protojson.Unmarshal(reqBody, req); err != nil {
			t.Fatalf("Error unmarshaling HTTP request body: %s", err)
		}

		if !proto.Equal(req, expectedReq) {
			t.Errorf("Incorrect BeginSessionRequest recieved by server: got %v, want %v", req, expectedReq)
		}

		// Send HTTP Response.
		marshaled, err := protojson.Marshal(expectedResp)
		if err != nil {
			t.Fatalf("Unable to marshal server response: %s", expectedResp)
		}

		w.Write(marshaled)
	}))

	certPool := x509.NewCertPool()
	certPool.AddCert(ts.Certificate())

	client := confidentialEkmClient{url: ts.URL, authToken: authToken, certPool: certPool}

	resp := &sspb.BeginSessionResponse{}
	if err := client.post(context.Background(), ts.URL, expectedReq, resp); err != nil {
		t.Fatalf("sendPostToEKM(ctx, url, expectedReq, resp) returned error: %s", err)
	}

	if !proto.Equal(resp, expectedResp) {
		t.Fatalf("sendPostToEKM(ctx, url, expectedReq, resp) = %v, want %v", resp, expectedResp)
	}
}

func TestPostErrors(t *testing.T) {
	testCases := []struct {
		name              string
		handlerFunc       func(http.ResponseWriter, *http.Request)
		errURL            string
		expectedErrSubstr string
	}{
		{
			name: "Server returns Non-OK Response",
			handlerFunc: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			expectedErrSubstr: "Non-OK HTTP Response",
		},
		{
			name: "HTTP Response Body unmarshaling fails",
			handlerFunc: func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte("This is nonsense."))
			},
			expectedErrSubstr: "unmarshalling HTTP Response Body",
		},
		{
			name: "Invalid URL provided for request",
			handlerFunc: func(w http.ResponseWriter, _ *http.Request) {
				t.Errorf("HTTP server successfully called when it should not be.")
			},
			errURL:            "https://this.is.nonsense",
			expectedErrSubstr: "invalid URL",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewTLSServer(http.HandlerFunc(tc.handlerFunc))
			defer ts.Close()

			url := ts.URL
			if tc.errURL != "" {
				url = tc.errURL
			}

			client := &confidentialEkmClient{}

			if err := client.post(context.Background(), url, &sspb.BeginSessionRequest{}, &sspb.BeginSessionResponse{}); err == nil {
				t.Errorf("sentPostToEKM(ctx, url, req, resp) returned with no error, expected error related to %s", tc.expectedErrSubstr)
			}
		})
	}
}

/*
 * Returns a simple TLS test server and a CertPool containing its certificate.
 *
 * The test server checks that the request contains the provided urlSuffix,
 * then marshals and sends the provided response.
 */
func getTestServerAndCertPool(t *testing.T, urlSuffix string, resp proto.Message) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify endpoint.
		if !strings.HasSuffix(r.URL.String(), urlSuffix) {
			t.Errorf("HTTP call made to %s, expected suffix %s", r.URL.String(), urlSuffix)
		}

		// Marshal and send response.
		marshaled, err := protojson.Marshal(resp)
		if err != nil {
			t.Fatalf("Unable to marshal server response: %s", err)
		}

		w.Write(marshaled)
	}))

	certPool := x509.NewCertPool()
	certPool.AddCert(ts.Certificate())

	return ts, certPool
}

func TestBeginSession(t *testing.T) {
	expectedResp := &sspb.BeginSessionResponse{
		SessionContext: []byte("Knock knock."),
		TlsRecords:     []byte("Who's there?"),
	}

	ts, certPool := getTestServerAndCertPool(t, "/v0/session/begin-session", expectedResp)
	defer ts.Close()

	client := &confidentialEkmClient{url: ts.URL, authToken: "", certPool: certPool}

	resp, err := client.BeginSession(context.Background(), &sspb.BeginSessionRequest{})
	if err != nil {
		t.Fatalf("BeginSession(ctx, req) Failed: %s", err)
	}

	if !proto.Equal(resp, expectedResp) {
		t.Errorf("BeginSession(ctx, req) = %v, want %v", resp, expectedResp)
	}
}

func TestHandshake(t *testing.T) {
	expectedResp := &sspb.HandshakeResponse{TlsRecords: []byte("Goodbye, Handshake!")}

	ts, certPool := getTestServerAndCertPool(t, "/v0/session/handshake", expectedResp)
	defer ts.Close()

	client := &confidentialEkmClient{url: ts.URL, authToken: "", certPool: certPool}

	resp, err := client.Handshake(context.Background(), &sspb.HandshakeRequest{})
	if err != nil {
		t.Fatalf("Handshake(ctx, req) Failed: %s", err)
	}

	if !proto.Equal(resp, expectedResp) {
		t.Errorf("Handshake(ctx, req) = %v, want %v", resp, expectedResp)
	}
}

func TestNegotiateAttestation(t *testing.T) {
	expectedResp := &sspb.NegotiateAttestationResponse{RequiredEvidenceTypesRecords: []byte("Goodbye, Handshake!")}

	ts, certPool := getTestServerAndCertPool(t, "/v0/session/negotiate-attestations", expectedResp)
	defer ts.Close()

	client := &confidentialEkmClient{url: ts.URL, authToken: "", certPool: certPool}

	resp, err := client.NegotiateAttestation(context.Background(), &sspb.NegotiateAttestationRequest{})
	if err != nil {
		t.Fatalf("NegotiateAttestation(ctx, req) Failed: %s", err)
	}

	if !proto.Equal(resp, expectedResp) {
		t.Errorf("NegotiateAttestation(ctx, req) = %v, want %v", resp, expectedResp)
	}
}

func TestFinalize(t *testing.T) {
	expectedResp := &sspb.FinalizeResponse{}

	ts, certPool := getTestServerAndCertPool(t, "/v0/session/finalize", expectedResp)
	defer ts.Close()

	client := &confidentialEkmClient{url: ts.URL, authToken: "", certPool: certPool}

	resp, err := client.Finalize(context.Background(), &sspb.FinalizeRequest{})
	if err != nil {
		t.Fatalf("Finalize(ctx, req) Failed: %s", err)
	}

	if !proto.Equal(resp, expectedResp) {
		t.Errorf("Finalize(ctx, req) = %v, want %v", resp, expectedResp)
	}
}

func TestEndSession(t *testing.T) {
	expectedResp := &sspb.EndSessionResponse{}

	ts, certPool := getTestServerAndCertPool(t, "/v0/session/end-session", expectedResp)
	defer ts.Close()

	client := &confidentialEkmClient{url: ts.URL, authToken: "", certPool: certPool}

	resp, err := client.EndSession(context.Background(), &sspb.EndSessionRequest{})
	if err != nil {
		t.Fatalf("EndSession(ctx, req) Failed: %s", err)
	}

	if !proto.Equal(resp, expectedResp) {
		t.Errorf("EndSession(ctx, req) = %v, want %v", resp, expectedResp)
	}
}

func TestConfidentialWrap(t *testing.T) {
	keyPath := "Hello"
	expectedResp := &cwpb.ConfidentialWrapResponse{
		TlsRecords: []byte("Goodbye, ConfidentialWrap."),
	}

	ts, certPool := getTestServerAndCertPool(t, fmt.Sprintf("/v0/%s:confidential-wrap", keyPath), expectedResp)
	defer ts.Close()

	client := &confidentialEkmClient{url: ts.URL, authToken: "", certPool: certPool}

	resp, err := client.ConfidentialWrap(context.Background(),
		&cwpb.ConfidentialWrapRequest{RequestMetadata: &cwpb.RequestMetadata{KeyPath: keyPath}})
	if err != nil {
		t.Fatalf("ConfidentialWrap(ctx, req) Failed: %s", err)
	}

	if !proto.Equal(resp, expectedResp) {
		t.Errorf("ConfidentialWrap(ctx, req) = %v, want %v", resp, expectedResp)
	}

}

func TestConfidentialUnwrap(t *testing.T) {
	keyPath := "Hello"
	expectedResp := &cwpb.ConfidentialUnwrapResponse{
		TlsRecords: []byte("Goodbye, ConfidentialUnwrap."),
	}

	ts, certPool := getTestServerAndCertPool(t, fmt.Sprintf("/v0/%s:confidential-unwrap", keyPath), expectedResp)
	defer ts.Close()

	client := &confidentialEkmClient{url: ts.URL, authToken: "", certPool: certPool}

	resp, err := client.ConfidentialUnwrap(context.Background(),
		&cwpb.ConfidentialUnwrapRequest{RequestMetadata: &cwpb.RequestMetadata{KeyPath: keyPath}})
	if err != nil {
		t.Fatalf("ConfidentialUnwrap(ctx, req) Failed: %s", err)
	}

	if !proto.Equal(resp, expectedResp) {
		t.Errorf("ConfidentialUnwrap(ctx, req) = %v, want %v", resp, expectedResp)
	}
}
