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
	"testing"

	pb "github.com/GoogleCloudPlatform/stet/proto/secure_session_go_proto"
)

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
