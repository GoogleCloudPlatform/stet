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

// This test file functions as a integration test between the secure
// session component of the client library and the reference server
// implementation, rather than unit testing `securesession.go`.

package securesession

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	aepb "github.com/GoogleCloudPlatform/stet/proto/attestation_evidence_go_proto"
	cwpb "github.com/GoogleCloudPlatform/stet/proto/confidential_wrap_go_proto"
	pb "github.com/GoogleCloudPlatform/stet/proto/secure_session_go_proto"
	"google.golang.org/protobuf/proto"
)

var testSendBuf = []byte("test sendbuf")
var testReceiveBuf = []byte("test receivebuf")

type fakeShim struct {
	net.Conn
	t *testing.T
}

func (f *fakeShim) DrainSendBuf() []byte {
	return testSendBuf
}

func (f *fakeShim) QueueReceiveBuf(b []byte) {
	if !bytes.Equal(b, testReceiveBuf) {
		f.t.Fatalf("QueueReceiveBuf() = %v, want %v", b, testReceiveBuf)
	}
}

type fakeEkmClient struct {
	beginSessionFunc         func(context.Context, *pb.BeginSessionRequest) (*pb.BeginSessionResponse, error)
	handshakeFunc            func(context.Context, *pb.HandshakeRequest) (*pb.HandshakeResponse, error)
	negotiateAttestationFunc func(context.Context, *pb.NegotiateAttestationRequest) (*pb.NegotiateAttestationResponse, error)
	finalizeFunc             func(context.Context, *pb.FinalizeRequest) (*pb.FinalizeResponse, error)
	endSessionFunc           func(context.Context, *pb.EndSessionRequest) (*pb.EndSessionResponse, error)
	confidentialWrapFunc     func(context.Context, *cwpb.ConfidentialWrapRequest) (*cwpb.ConfidentialWrapResponse, error)
	confidentialUnwrapFunc   func(context.Context, *cwpb.ConfidentialUnwrapRequest) (*cwpb.ConfidentialUnwrapResponse, error)
}

func (f *fakeEkmClient) BeginSession(ctx context.Context, req *pb.BeginSessionRequest) (*pb.BeginSessionResponse, error) {
	if f.beginSessionFunc == nil {
		return nil, errors.New("BeginSession not implemented")
	}

	return f.beginSessionFunc(ctx, req)
}

func (f *fakeEkmClient) Handshake(ctx context.Context, req *pb.HandshakeRequest) (*pb.HandshakeResponse, error) {
	if f.handshakeFunc == nil {
		return nil, errors.New("Handshake not implemented")
	}

	return f.handshakeFunc(ctx, req)
}

func (f *fakeEkmClient) NegotiateAttestation(ctx context.Context, req *pb.NegotiateAttestationRequest) (*pb.NegotiateAttestationResponse, error) {
	if f.negotiateAttestationFunc == nil {
		return nil, errors.New("NegotiateAttestation not implemented")
	}

	return f.negotiateAttestationFunc(ctx, req)
}

func (f *fakeEkmClient) Finalize(ctx context.Context, req *pb.FinalizeRequest) (*pb.FinalizeResponse, error) {
	if f.finalizeFunc == nil {
		return nil, errors.New("Finalize not implemented")
	}

	return f.finalizeFunc(ctx, req)
}

func (f *fakeEkmClient) EndSession(ctx context.Context, req *pb.EndSessionRequest) (*pb.EndSessionResponse, error) {
	if f.endSessionFunc == nil {
		return nil, errors.New("EndSession not implemented")
	}

	return f.endSessionFunc(ctx, req)
}

func (f *fakeEkmClient) ConfidentialWrap(ctx context.Context, req *cwpb.ConfidentialWrapRequest) (*cwpb.ConfidentialWrapResponse, error) {
	if f.confidentialWrapFunc == nil {
		return nil, errors.New("ConfidentialWrap not implemented")
	}

	return f.confidentialWrapFunc(ctx, req)
}

func (f *fakeEkmClient) ConfidentialUnwrap(ctx context.Context, req *cwpb.ConfidentialUnwrapRequest) (*cwpb.ConfidentialUnwrapResponse, error) {
	if f.confidentialUnwrapFunc == nil {
		return nil, errors.New("ConfidentialUnwrap not implemented")
	}

	return f.confidentialUnwrapFunc(ctx, req)
}

type fakeTLSConn struct {
	writeFunc           func([]byte) (int, error)
	readFunc            func([]byte) (int, error)
	connectionStateFunc func() tls.ConnectionState
	handshakeFunc       func() error
}

func (f *fakeTLSConn) Write(b []byte) (int, error) {
	if f.writeFunc == nil {
		return 0, errors.New("Write not implemented")
	}

	return f.writeFunc(b)
}

func (f *fakeTLSConn) Read(b []byte) (int, error) {
	if f.readFunc == nil {
		return 0, errors.New("Read not implemented")
	}

	return f.readFunc(b)
}

func (f *fakeTLSConn) ConnectionState() tls.ConnectionState {
	if f.connectionStateFunc == nil {
		return tls.ConnectionState{}
	}

	return f.connectionStateFunc()
}

func (f *fakeTLSConn) Handshake() error {
	if f.handshakeFunc == nil {
		return errors.New("Handshake not implemented")
	}

	return f.handshakeFunc()
}

func TestBeginSession(t *testing.T) {
	expectedContext := []byte("test session context")
	ekmClient := &fakeEkmClient{
		beginSessionFunc: func(ctx context.Context, req *pb.BeginSessionRequest) (*pb.BeginSessionResponse, error) {
			if !bytes.Equal(req.GetTlsRecords(), testSendBuf) {
				t.Fatalf("BeginSessionRequest.GetTlsRecords() = %v, want %v", req.GetTlsRecords(), testSendBuf)
			}
			return &pb.BeginSessionResponse{
				SessionContext: expectedContext,
				TlsRecords:     testReceiveBuf,
			}, nil
		},
	}

	ssClient := &SecureSessionClient{
		client: ekmClient,
		shim:   &fakeShim{t: t},
	}

	if err := ssClient.beginSession(context.Background()); err != nil {
		t.Fatalf("beginSession() returned unexpected error: %v", err)
	}

	if ssClient.state != clientStateInitiated {
		t.Errorf("Client state is %v, want %v", ssClient.state, clientStateInitiated)
	}

	if !bytes.Equal(ssClient.ctx, expectedContext) {
		t.Errorf("Client context is %v, want %v", ssClient.ctx, expectedContext)
	}
}

func TestBeginSessionErrors(t *testing.T) {
	testcases := []struct {
		name             string
		beginSessionFunc func(context.Context, *pb.BeginSessionRequest) (*pb.BeginSessionResponse, error)
		expectedSubstr   string
	}{
		{
			name: "client.BeginSession() returns error",
			beginSessionFunc: func(context.Context, *pb.BeginSessionRequest) (*pb.BeginSessionResponse, error) {
				return nil, errors.New("BeginSession error")
			},
			expectedSubstr: "initializing TLS",
		},
		{
			name: "Missing session context",
			beginSessionFunc: func(context.Context, *pb.BeginSessionRequest) (*pb.BeginSessionResponse, error) {
				return &pb.BeginSessionResponse{}, nil
			},
			expectedSubstr: "failed to initialize session",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ekmClient := &fakeEkmClient{
				beginSessionFunc: tc.beginSessionFunc,
			}

			ssClient := &SecureSessionClient{
				client: ekmClient,
				shim:   &fakeShim{t: t},
			}

			err := ssClient.beginSession(context.Background())

			if err == nil {
				t.Fatalf("beginSession() succeeded, want error")
			}

			if !strings.Contains(err.Error(), tc.expectedSubstr) {
				t.Errorf("beginSession() error = %v, want error containing %v", err, tc.expectedSubstr)
			}
		})
	}
}

func TestHandshake(t *testing.T) {
	expectedContext := []byte("test session context")

	testcases := []struct {
		name                   string
		handshakeFunc          func(context.Context, *pb.HandshakeRequest) (*pb.HandshakeResponse, error)
		tlsHandshakeComplete   bool
		expectedClientState    clientState
		expectedHandshakeState handshakeState
	}{
		{
			name: "Successful handshake",
			handshakeFunc: func(ctx context.Context, req *pb.HandshakeRequest) (*pb.HandshakeResponse, error) {
				if !bytes.Equal(req.GetSessionContext(), expectedContext) {
					t.Fatalf("HandshakeRequest.GetSessionContext() = %v, want %v", req.GetSessionContext(), expectedContext)
				}

				if !bytes.Equal(req.GetTlsRecords(), testSendBuf) {
					t.Fatalf("HandshakeRequest.GetTlsRecords() = %v, want %v", req.GetTlsRecords(), testSendBuf)
				}
				return &pb.HandshakeResponse{
					TlsRecords: testReceiveBuf,
				}, nil
			},
			tlsHandshakeComplete:   true,
			expectedClientState:    clientStateHandshakeCompleted,
			expectedHandshakeState: handshakeCompleted,
		},
		{
			name: "TLS not complete",
			handshakeFunc: func(context.Context, *pb.HandshakeRequest) (*pb.HandshakeResponse, error) {
				return &pb.HandshakeResponse{
					TlsRecords: testReceiveBuf,
				}, nil
			},
			tlsHandshakeComplete:   false,
			expectedClientState:    clientStateUnknown,
			expectedHandshakeState: handshakeInitiated,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ssClient := &SecureSessionClient{
				client: &fakeEkmClient{handshakeFunc: tc.handshakeFunc},
				shim:   &fakeShim{t: t},
				ctx:    expectedContext,
				tls: &fakeTLSConn{
					connectionStateFunc: func() tls.ConnectionState {
						return tls.ConnectionState{HandshakeComplete: tc.tlsHandshakeComplete}
					},
				},
				state:          clientStateUnknown,
				handshakeState: &atomic.Value{},
			}

			ssClient.handshakeState.Store(handshakeInitiated)

			if err := ssClient.handshake(context.Background()); err != nil {
				t.Fatalf("handshake() returned unexpected error: %v", err)
			}

			if ssClient.state != tc.expectedClientState {
				t.Errorf("Client state is %v, want %v", ssClient.state, tc.expectedClientState)
			}

			if ssClient.handshakeState.Load() != tc.expectedHandshakeState {
				t.Errorf("Client handshake state is %v, want %v", ssClient.handshakeState, tc.expectedHandshakeState)
			}
		})
	}
}

func TestHandshakeError(t *testing.T) {
	ekmClient := &fakeEkmClient{
		handshakeFunc: func(context.Context, *pb.HandshakeRequest) (*pb.HandshakeResponse, error) {
			return nil, errors.New("Handshake error")
		},
	}

	ssClient := &SecureSessionClient{
		client: ekmClient,
		shim:   &fakeShim{t: t},
		ctx:    []byte("test session context"),
		tls: &fakeTLSConn{
			connectionStateFunc: func() tls.ConnectionState {
				return tls.ConnectionState{HandshakeComplete: true}
			},
		},
	}

	if err := ssClient.handshake(context.Background()); err == nil {
		t.Errorf("handshake() succeeded, want error")
	}
}

func TestNegotiateAttestation(t *testing.T) {
	expectedContext := []byte("test session context")
	ekmClient := &fakeEkmClient{
		negotiateAttestationFunc: func(ctx context.Context, req *pb.NegotiateAttestationRequest) (*pb.NegotiateAttestationResponse, error) {
			if !bytes.Equal(req.GetSessionContext(), expectedContext) {
				t.Fatalf("NegotiateAttestationRequest.GetSessionContext() = %v, want %v", req.GetSessionContext(), expectedContext)
			}

			if !bytes.Equal(req.OfferedEvidenceTypesRecords, testSendBuf) {
				t.Fatalf("NegotiateAttestationRequest.GetOfferedEvidenceTypesRecords() = %v, want %v", req.GetOfferedEvidenceTypesRecords(), testSendBuf)
			}

			return &pb.NegotiateAttestationResponse{
				RequiredEvidenceTypesRecords: testReceiveBuf,
			}, nil
		},
	}

	fakeTLS := &fakeTLSConn{
		writeFunc: func(b []byte) (int, error) {
			return len(b), nil
		},
		readFunc: func(b []byte) (int, error) {
			marshaled, err := proto.Marshal(&aepb.AttestationEvidenceTypeList{
				Types: []aepb.AttestationEvidenceType{aepb.AttestationEvidenceType_NULL_ATTESTATION},
			})
			if err != nil {
				t.Fatalf("proto.Marshal() returned unexpected error: %v", err)
			}

			copy(b, marshaled)

			return len(marshaled), nil
		},
	}

	ssClient := &SecureSessionClient{
		client: ekmClient,
		shim:   &fakeShim{t: t},
		ctx:    expectedContext,
		tls:    fakeTLS,
	}

	if err := ssClient.negotiateAttestation(context.Background()); err != nil {
		t.Fatalf("negotiateAttestation() returned unexpected error: %v", err)
	}

	if ssClient.state != clientStateAttestationNegotiated {
		t.Errorf("Client state is %v, want %v", ssClient.state, clientStateAttestationNegotiated)
	}
}

func TestNegotiateAttestationError(t *testing.T) {
	marshaledEvidence, err := proto.Marshal(&aepb.AttestationEvidenceTypeList{
		Types: []aepb.AttestationEvidenceType{aepb.AttestationEvidenceType_NULL_ATTESTATION},
	})
	if err != nil {
		t.Fatalf("proto.Marshal() returned unexpected error: %v", err)
	}

	negotiateAttSuccessFunc := func(context.Context, *pb.NegotiateAttestationRequest) (*pb.NegotiateAttestationResponse, error) {
		return &pb.NegotiateAttestationResponse{
			RequiredEvidenceTypesRecords: testReceiveBuf,
		}, nil
	}

	testcases := []struct {
		name                     string
		negotiateAttestationFunc func(context.Context, *pb.NegotiateAttestationRequest) (*pb.NegotiateAttestationResponse, error)
		tlsConn                  *fakeTLSConn
		expectedSubstr           string
	}{
		{
			name: "client.NegotiateAttestation() returns error",
			negotiateAttestationFunc: func(context.Context, *pb.NegotiateAttestationRequest) (*pb.NegotiateAttestationResponse, error) {
				return nil, errors.New("NegotiateAttestation error")
			},
			tlsConn: &fakeTLSConn{
				writeFunc: func(b []byte) (int, error) { return len(b), nil },
				readFunc: func(b []byte) (int, error) {
					copy(b, marshaledEvidence)
					return len(marshaledEvidence), nil
				},
			},
			expectedSubstr: "negotiating attestation",
		},
		{
			name:                     "error writing evidence to TLS",
			negotiateAttestationFunc: negotiateAttSuccessFunc,
			tlsConn: &fakeTLSConn{
				writeFunc: func(b []byte) (int, error) { return 0, errors.New("Write error") },
				readFunc: func(b []byte) (int, error) {
					copy(b, marshaledEvidence)
					return len(marshaledEvidence), nil
				},
			},
			expectedSubstr: "writing evidence to TLS",
		},
		{
			name:                     "error reading from TLS",
			negotiateAttestationFunc: negotiateAttSuccessFunc,
			tlsConn: &fakeTLSConn{
				writeFunc: func(b []byte) (int, error) { return len(b), nil },
				readFunc: func(b []byte) (int, error) {
					return 0, errors.New("Read error")
				},
			},
			expectedSubstr: "reading data from TLS",
		},
		{
			name:                     "invalid proto read from TLS",
			negotiateAttestationFunc: negotiateAttSuccessFunc,
			tlsConn: &fakeTLSConn{
				writeFunc: func(b []byte) (int, error) { return len(b), nil },
				readFunc: func(b []byte) (int, error) {
					marshaled := []byte("invalid proto")
					copy(b, marshaled)
					return len(marshaled), nil
				},
			},
			expectedSubstr: "parsing attestation types",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ekmClient := &fakeEkmClient{
				negotiateAttestationFunc: tc.negotiateAttestationFunc,
			}

			ssClient := &SecureSessionClient{
				client: ekmClient,
				shim:   &fakeShim{t: t},
				ctx:    []byte("test session context"),
				tls:    tc.tlsConn,
			}
			err := ssClient.negotiateAttestation(context.Background())
			if err == nil {
				t.Fatalf("negotiateAttestation() succeeded, want error")
			}

			if !strings.Contains(err.Error(), tc.expectedSubstr) {
				t.Errorf("negotiateAttestation() error = %v, want error containing %q", err, tc.expectedSubstr)
			}
		})
	}
}

func TestFinalize(t *testing.T) {
	expectedContext := []byte("test session context")
	ekmClient := &fakeEkmClient{
		finalizeFunc: func(ctx context.Context, req *pb.FinalizeRequest) (*pb.FinalizeResponse, error) {
			if !bytes.Equal(req.GetSessionContext(), expectedContext) {
				t.Fatalf("FinalizeRequest.GetSessionContext() = %v, want %v", req.GetSessionContext(), expectedContext)
			}

			return &pb.FinalizeResponse{}, nil
		},
	}

	ssClient := &SecureSessionClient{
		client: ekmClient,
		ctx:    []byte("test session context"),
		tls: &fakeTLSConn{
			writeFunc: func(b []byte) (int, error) {
				return len(b), nil
			},
		},
		attestationTypes: &aepb.AttestationEvidenceTypeList{
			Types: []aepb.AttestationEvidenceType{aepb.AttestationEvidenceType_NULL_ATTESTATION},
		},
	}

	if err := ssClient.finalize(context.Background()); err != nil {
		t.Fatalf("finalize() returned unexpected error: %v", err)
	}

	if ssClient.state != clientStateAttestationAccepted {
		t.Errorf("Client state is %v, want %v", ssClient.state, clientStateAttestationAccepted)
	}
}

func TestFinalizeErrors(t *testing.T) {
	testcases := []struct {
		name             string
		finalizeFunc     func(context.Context, *pb.FinalizeRequest) (*pb.FinalizeResponse, error)
		attestationTypes *aepb.AttestationEvidenceTypeList
		expectedSubstr   string
	}{
		{
			name: "client.Finalize() returns error",
			finalizeFunc: func(context.Context, *pb.FinalizeRequest) (*pb.FinalizeResponse, error) {
				return nil, errors.New("Finalize error")
			},
			attestationTypes: &aepb.AttestationEvidenceTypeList{
				Types: []aepb.AttestationEvidenceType{aepb.AttestationEvidenceType_NULL_ATTESTATION},
			},
			expectedSubstr: "finalizing secure session",
		},
		{
			name:         "require Tpm2Quote without EventLog",
			finalizeFunc: nil,
			attestationTypes: &aepb.AttestationEvidenceTypeList{
				Types: []aepb.AttestationEvidenceType{
					aepb.AttestationEvidenceType_NULL_ATTESTATION,
					aepb.AttestationEvidenceType_TPM2_QUOTE,
				},
			},
			expectedSubstr: "should request both the Tpm2Quote and the EventLog",
		},
		{
			name:         "require EventLog without Tpm2Quote",
			finalizeFunc: nil,
			attestationTypes: &aepb.AttestationEvidenceTypeList{
				Types: []aepb.AttestationEvidenceType{
					aepb.AttestationEvidenceType_NULL_ATTESTATION,
					aepb.AttestationEvidenceType_TCG_EVENT_LOG,
				},
			},
			expectedSubstr: "should request both the Tpm2Quote and the EventLog",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ekmClient := &fakeEkmClient{
				finalizeFunc: tc.finalizeFunc,
			}

			ssClient := &SecureSessionClient{
				client: ekmClient,
				tls: &fakeTLSConn{
					writeFunc: func(b []byte) (int, error) {
						return len(b), nil
					},
				},
				ctx:              []byte("test session context"),
				attestationTypes: tc.attestationTypes,
			}

			err := ssClient.finalize(context.Background())

			if err == nil {
				t.Fatalf("finalize() succeeded, want error")
			}

			if !strings.Contains(err.Error(), tc.expectedSubstr) {
				t.Errorf("finalize() error = %v, want error containing %q", err, tc.expectedSubstr)
			}
		})
	}
}

func TestEndSession(t *testing.T) {
	expectedContext := []byte("test session context")
	ekmClient := &fakeEkmClient{
		endSessionFunc: func(ctx context.Context, req *pb.EndSessionRequest) (*pb.EndSessionResponse, error) {
			if !bytes.Equal(req.GetSessionContext(), expectedContext) {
				t.Fatalf("EndSessionRequest.GetSessionContext() = %v, want %v", req.GetSessionContext(), expectedContext)
			}

			if !bytes.Equal(req.GetTlsRecords(), testSendBuf) {
				t.Fatalf("EndSessionRequest.GetTlsRecords() = %v, want %v", req.GetTlsRecords(), testSendBuf)
			}
			return &pb.EndSessionResponse{}, nil
		},
	}

	ssClient := &SecureSessionClient{
		client: ekmClient,
		shim:   &fakeShim{t: t},
		ctx:    expectedContext,
		tls: &fakeTLSConn{
			writeFunc: func(b []byte) (int, error) {
				return len(b), nil
			},
		},
		state: clientStateAttestationAccepted,
	}

	if err := ssClient.EndSession(context.Background()); err != nil {
		t.Fatalf("EndSession() returned unexpected error: %v", err)
	}

	if ssClient.state != clientStateEnded {
		t.Errorf("Client state is %v, want %v", ssClient.state, clientStateEnded)
	}
}

func TestEndSessionErrors(t *testing.T) {
	testcases := []struct {
		name           string
		endSessionFunc func(context.Context, *pb.EndSessionRequest) (*pb.EndSessionResponse, error)
		tlsConn        *fakeTLSConn
		clientState    clientState
		expectedSubstr string
	}{
		{
			name:           "Secure session not established",
			endSessionFunc: nil,
			clientState:    clientStateUnknown,
			expectedSubstr: "unestablished secure session",
		},
		{
			name:           "Error writing EndSession constant",
			endSessionFunc: nil,
			tlsConn: &fakeTLSConn{
				writeFunc: func([]byte) (int, error) { return 0, errors.New("TLS error") },
			},
			clientState:    clientStateAttestationAccepted,
			expectedSubstr: "session-encrypting",
		},
		{
			name: "client.EndSession() returns error",
			endSessionFunc: func(context.Context, *pb.EndSessionRequest) (*pb.EndSessionResponse, error) {
				return nil, errors.New("EndSession error")
			},
			tlsConn: &fakeTLSConn{
				writeFunc: func(b []byte) (int, error) { return len(b), nil },
			},
			clientState:    clientStateAttestationAccepted,
			expectedSubstr: "ending session",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ekmClient := &fakeEkmClient{
				endSessionFunc: tc.endSessionFunc,
			}

			ssClient := &SecureSessionClient{
				client: ekmClient,
				shim:   &fakeShim{t: t},
				ctx:    []byte("test session context"),
				tls:    tc.tlsConn,
				state:  tc.clientState,
			}

			err := ssClient.EndSession(context.Background())
			if err == nil {
				t.Fatalf("EndSession() succeeded, want error")
			}

			if !strings.Contains(err.Error(), tc.expectedSubstr) {
				t.Errorf("EndSession() error = %v, want error containing %q", err, tc.expectedSubstr)
			}
		})
	}
}

func TestConfidentialWrap(t *testing.T) {
	expectedContext := []byte("test session context")
	cipherSuffix := []byte(" (encrypted)")

	expectedWrapReq := &cwpb.WrapRequest{
		KeyPath:   "test/key/path",
		Plaintext: []byte("test plaintext"),
		AdditionalContext: &cwpb.RequestContext{
			RelativeResourceName: "test-key-name",
			AccessReasonContext:  &cwpb.AccessReasonContext{Reason: cwpb.AccessReasonContext_CUSTOMER_INITIATED_ACCESS},
		},
		AdditionalAuthenticatedData: nil,
		KeyUriPrefix:                "",
	}

	ekmClient := &fakeEkmClient{
		confidentialWrapFunc: func(ctx context.Context, req *cwpb.ConfidentialWrapRequest) (*cwpb.ConfidentialWrapResponse, error) {
			expectedReq := &cwpb.ConfidentialWrapRequest{
				SessionContext: expectedContext,
				TlsRecords:     testSendBuf,
				RequestMetadata: &cwpb.RequestMetadata{
					KeyPath:           expectedWrapReq.GetKeyPath(),
					KeyUriPrefix:      expectedWrapReq.GetKeyUriPrefix(),
					AdditionalContext: expectedWrapReq.GetAdditionalContext(),
				},
			}

			if !proto.Equal(req, expectedReq) {
				t.Fatalf("ConfidentialWrapRequest = %v, want %v", req, expectedReq)
			}

			return &cwpb.ConfidentialWrapResponse{
				TlsRecords: testReceiveBuf,
			}, nil
		},
	}

	expectedWrapResp := &cwpb.WrapResponse{
		WrappedBlob: append(expectedWrapReq.GetPlaintext(), cipherSuffix...),
	}
	marshaled, err := proto.Marshal(expectedWrapResp)
	if err != nil {
		t.Fatalf("proto.Marshal() returned unexpected error: %v", err)
	}

	fakeTLS := &fakeTLSConn{
		writeFunc: func(b []byte) (int, error) {
			wrapReq := &cwpb.WrapRequest{}
			if err := proto.Unmarshal(b, wrapReq); err != nil {
				t.Fatalf("proto.Unmarshal() returned unexpected error: %v", err)
			}

			if !proto.Equal(wrapReq, expectedWrapReq) {
				t.Fatalf("WrapRequest = %v, want %v", wrapReq, expectedWrapReq)
			}

			return len(b), nil
		},
		readFunc: func(b []byte) (int, error) {
			copy(b, marshaled)
			return len(marshaled), nil
		},
	}

	ssClient := &SecureSessionClient{
		client: ekmClient,
		shim:   &fakeShim{t: t},
		ctx:    expectedContext,
		tls:    fakeTLS,
		state:  clientStateAttestationAccepted,
	}

	wrapped, err := ssClient.ConfidentialWrap(context.Background(), expectedWrapReq.KeyPath, expectedWrapReq.AdditionalContext.RelativeResourceName, expectedWrapReq.Plaintext)
	if err != nil {
		t.Fatalf("ConfidentialWrap() returned unexpected error: %v", err)
	}

	if !bytes.Equal(wrapped, expectedWrapResp.GetWrappedBlob()) {
		t.Errorf("ConfidentialWrap() = %v, want %v", wrapped, expectedWrapResp.GetWrappedBlob())
	}
}

func TestConfidentialWrapErrors(t *testing.T) {
	successWrapFunc := func(context.Context, *cwpb.ConfidentialWrapRequest) (*cwpb.ConfidentialWrapResponse, error) {
		return &cwpb.ConfidentialWrapResponse{
			TlsRecords: testReceiveBuf,
		}, nil
	}

	testcases := []struct {
		name                 string
		state                clientState
		tlsConn              *fakeTLSConn
		confidentialWrapFunc func(context.Context, *cwpb.ConfidentialWrapRequest) (*cwpb.ConfidentialWrapResponse, error)
		expectedSubstr       string
	}{
		{
			name:                 "client state not accepted",
			state:                clientStateUnknown,
			tlsConn:              &fakeTLSConn{},
			confidentialWrapFunc: nil,
			expectedSubstr:       "unestablished secure session",
		},
		{
			name:  "error writing WrapRequest",
			state: clientStateAttestationAccepted,
			tlsConn: &fakeTLSConn{
				writeFunc: func([]byte) (int, error) { return 0, errors.New("TLS error") },
			},
			confidentialWrapFunc: nil,
			expectedSubstr:       "writing the WrapRequest",
		},
		{
			name:  "client.ConfidentialWrap() returns error",
			state: clientStateAttestationAccepted,
			tlsConn: &fakeTLSConn{
				writeFunc: func([]byte) (int, error) { return 1, nil },
			},
			confidentialWrapFunc: func(context.Context, *cwpb.ConfidentialWrapRequest) (*cwpb.ConfidentialWrapResponse, error) {
				return nil, errors.New("ConfidentialWrap error")
			},
			expectedSubstr: "session-encrypting",
		},
		{
			name:  "error reading WrapResponse",
			state: clientStateAttestationAccepted,
			tlsConn: &fakeTLSConn{
				writeFunc: func([]byte) (int, error) { return 1, nil },
				readFunc:  func([]byte) (int, error) { return 0, errors.New("TLS error") },
			},
			confidentialWrapFunc: successWrapFunc,
			expectedSubstr:       "reading WrapResponse",
		},
		{
			name:  "invalid WrapResponse proto",
			state: clientStateAttestationAccepted,
			tlsConn: &fakeTLSConn{
				writeFunc: func([]byte) (int, error) { return 1, nil },
				readFunc: func(b []byte) (int, error) {
					resp := []byte("invalid proto")
					copy(b, resp)
					return len(resp), nil
				},
			},
			confidentialWrapFunc: successWrapFunc,
			expectedSubstr:       "parsing WrapResponse",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ekmClient := &fakeEkmClient{
				confidentialWrapFunc: tc.confidentialWrapFunc,
			}

			ssClient := &SecureSessionClient{
				client: ekmClient,
				shim:   &fakeShim{t: t},
				ctx:    []byte("test session context"),
				tls:    tc.tlsConn,
				state:  tc.state,
			}

			_, err := ssClient.ConfidentialWrap(context.Background(), "test/key/path", "test-key-name", []byte("test plaintext"))

			if err == nil {
				t.Fatalf("ConfidentialWrap() succeeded, want error")
			}

			if !strings.Contains(err.Error(), tc.expectedSubstr) {
				t.Errorf("ConfidentialWrap() error = %v, want error containing %q", err, tc.expectedSubstr)
			}
		})
	}
}

func TestConfidentialUnwrap(t *testing.T) {
	expectedContext := []byte("test session context")
	expectedPlaintext := []byte("test plaintext")
	cipherSuffix := []byte(" (encrypted)")

	expectedUnwrapReq := &cwpb.UnwrapRequest{
		KeyPath:     "test/key/path",
		WrappedBlob: append(expectedPlaintext, cipherSuffix...),
		AdditionalContext: &cwpb.RequestContext{
			RelativeResourceName: "test-key-name",
			AccessReasonContext:  &cwpb.AccessReasonContext{Reason: cwpb.AccessReasonContext_CUSTOMER_INITIATED_ACCESS},
		},
		AdditionalAuthenticatedData: nil,
		KeyUriPrefix:                "",
	}

	ekmClient := &fakeEkmClient{
		confidentialUnwrapFunc: func(ctx context.Context, req *cwpb.ConfidentialUnwrapRequest) (*cwpb.ConfidentialUnwrapResponse, error) {
			expectedReq := &cwpb.ConfidentialUnwrapRequest{
				SessionContext: expectedContext,
				TlsRecords:     testSendBuf,
				RequestMetadata: &cwpb.RequestMetadata{
					KeyPath:           expectedUnwrapReq.GetKeyPath(),
					KeyUriPrefix:      expectedUnwrapReq.GetKeyUriPrefix(),
					AdditionalContext: expectedUnwrapReq.GetAdditionalContext(),
				},
			}

			if !proto.Equal(req, expectedReq) {
				t.Fatalf("ConfidentialUnwrapRequest = %v, want %v", req, expectedReq)
			}

			return &cwpb.ConfidentialUnwrapResponse{
				TlsRecords: testReceiveBuf,
			}, nil
		},
	}

	expectedWrapResp := &cwpb.UnwrapResponse{Plaintext: expectedPlaintext}

	marshaled, err := proto.Marshal(expectedWrapResp)
	if err != nil {
		t.Fatalf("proto.Marshal() returned unexpected error: %v", err)
	}

	fakeTLS := &fakeTLSConn{
		writeFunc: func(b []byte) (int, error) {
			unwrapReq := &cwpb.UnwrapRequest{}
			if err := proto.Unmarshal(b, unwrapReq); err != nil {
				t.Fatalf("proto.Unmarshal() returned unexpected error: %v", err)
			}

			if !proto.Equal(unwrapReq, expectedUnwrapReq) {
				t.Fatalf("UnwrapRequest = %v, want %v", unwrapReq, expectedUnwrapReq)
			}

			return len(b), nil
		},
		readFunc: func(b []byte) (int, error) {
			copy(b, marshaled)
			return len(marshaled), nil
		},
	}

	ssClient := &SecureSessionClient{
		client: ekmClient,
		shim:   &fakeShim{t: t},
		ctx:    expectedContext,
		tls:    fakeTLS,
		state:  clientStateAttestationAccepted,
	}

	plaintext, err := ssClient.ConfidentialUnwrap(context.Background(), expectedUnwrapReq.KeyPath, expectedUnwrapReq.AdditionalContext.RelativeResourceName, expectedUnwrapReq.WrappedBlob)
	if err != nil {
		t.Fatalf("ConfidentialUnwrap() returned unexpected error: %v", err)
	}

	if !bytes.Equal(plaintext, expectedPlaintext) {
		t.Errorf("ConfidentialUnwrap() = %v, want %v", plaintext, expectedPlaintext)
	}
}

func TestConfidentialUnwrapErrors(t *testing.T) {
	successUnwrapFunc := func(context.Context, *cwpb.ConfidentialUnwrapRequest) (*cwpb.ConfidentialUnwrapResponse, error) {
		return &cwpb.ConfidentialUnwrapResponse{
			TlsRecords: testReceiveBuf,
		}, nil
	}

	testcases := []struct {
		name                   string
		state                  clientState
		tlsConn                *fakeTLSConn
		confidentialUnwrapFunc func(context.Context, *cwpb.ConfidentialUnwrapRequest) (*cwpb.ConfidentialUnwrapResponse, error)
		expectedSubstr         string
	}{
		{
			name:                   "client state not accepted",
			state:                  clientStateUnknown,
			tlsConn:                &fakeTLSConn{},
			confidentialUnwrapFunc: nil,
			expectedSubstr:         "unestablished secure session",
		},
		{
			name:  "error writing UnwrapRequest",
			state: clientStateAttestationAccepted,
			tlsConn: &fakeTLSConn{
				writeFunc: func([]byte) (int, error) { return 0, errors.New("TLS error") },
			},
			confidentialUnwrapFunc: nil,
			expectedSubstr:         "writing UnwrapRequest",
		},
		{
			name:  "client.ConfidentialUnwrap() returns error",
			state: clientStateAttestationAccepted,
			tlsConn: &fakeTLSConn{
				writeFunc: func([]byte) (int, error) { return 1, nil },
			},
			confidentialUnwrapFunc: func(context.Context, *cwpb.ConfidentialUnwrapRequest) (*cwpb.ConfidentialUnwrapResponse, error) {
				return nil, errors.New("ConfidentialUnwrap error")
			},
			expectedSubstr: "session-decrypting",
		},
		{
			name:  "error reading UnwrapResponse",
			state: clientStateAttestationAccepted,
			tlsConn: &fakeTLSConn{
				writeFunc: func([]byte) (int, error) { return 1, nil },
				readFunc:  func([]byte) (int, error) { return 0, errors.New("TLS error") },
			},
			confidentialUnwrapFunc: successUnwrapFunc,
			expectedSubstr:         "reading UnwrapResponse",
		},
		{
			name:  "invalid UnwrapResponse proto",
			state: clientStateAttestationAccepted,
			tlsConn: &fakeTLSConn{
				writeFunc: func([]byte) (int, error) { return 1, nil },
				readFunc: func(b []byte) (int, error) {
					resp := []byte("invalid proto")
					copy(b, resp)
					return len(resp), nil
				},
			},
			confidentialUnwrapFunc: successUnwrapFunc,
			expectedSubstr:         "parsing UnwrapResponse",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ekmClient := &fakeEkmClient{
				confidentialUnwrapFunc: tc.confidentialUnwrapFunc,
			}

			ssClient := &SecureSessionClient{
				client: ekmClient,
				shim:   &fakeShim{t: t},
				ctx:    []byte("test session context"),
				tls:    tc.tlsConn,
				state:  tc.state,
			}

			_, err := ssClient.ConfidentialUnwrap(context.Background(), "test/key/path", "test-key-name", []byte("test plaintext"))

			if err == nil {
				t.Fatalf("ConfidentialUnwrap() succeeded, want error")
			}

			if !strings.Contains(err.Error(), tc.expectedSubstr) {
				t.Errorf("ConfidentialUnwrap() error = %v, want error containing %q", err, tc.expectedSubstr)
			}
		})
	}
}
