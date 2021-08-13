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

// temporarily disabling these.
/*
func TestBeginSession(t *testing.T) {
	s := SecureSessionService{}

	ctx := context.Background()
	req := &pb.BeginSessionRequest{}
	_, err := s.BeginSession(ctx, req)
	if err != nil {
		t.Fatalf("BeginSession failed")
	}
}

func TestHandshake(t *testing.T) {
	s := SecureSessionService{}

	ctx := context.Background()
	req := &pb.HandshakeRequest{}
	_, err := s.Handshake(ctx, req)
	if err != nil {
		t.Fatalf("Handshake Failed")
	}
}
*/

func TestNegotiateAttestation(t *testing.T) {
	s := SecureSessionService{}

	ctx := context.Background()
	req := &pb.NegotiateAttestationRequest{}
	_, err := s.NegotiateAttestation(ctx, req)
	if err == nil {
		t.Fatalf("Expected NegotiateAttestation to be unimplemented")
	}
}

func TestFinalize(t *testing.T) {
	s := SecureSessionService{}

	ctx := context.Background()
	req := &pb.FinalizeRequest{}
	_, err := s.Finalize(ctx, req)
	if err == nil {
		t.Fatalf("Expected Finalize to be unimplemented")
	}
}
