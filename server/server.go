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

// Package server contains the reference server implementation for the CC + EKM integration.
package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/GoogleCloudPlatform/stet/constants"
	attpb "github.com/GoogleCloudPlatform/stet/proto/attestation_evidence_go_proto"
	pb "github.com/GoogleCloudPlatform/stet/proto/secure_session_go_proto"
	ts "github.com/GoogleCloudPlatform/stet/transportshim"
	glog "github.com/golang/glog"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

// SrvState is the state of the secure session establishment on the server side.
type SrvState int

// Constants representing different ClientStates.
const (
	ServerStateUninitialized = iota
	ServerStateInitiated
	ServerStateHandshakeCompleted
	ServerStateAttestationNegotiated
	ServerStateAttestationAccepted
	ServerStateEnded
	ServerStateFailed
	ServerStateUnknown
)

// Channel for connection internals
type Channel struct {
	conn   *tls.Conn
	shim   ts.ShimInterface
	connID []byte
	state  SrvState
}

// SecureSessionService implements the SecureSession interface.
type SecureSessionService struct {
	mu       sync.Mutex
	channels map[string]*Channel
}

// minUnchunkedAttestationSize used as hint to apply multiple
// read approach when receiving the attestation.
const minUnchunkedAttestationSize = 1024

// NewChannel sets up tls context and network shim
func NewChannel() (ch *Channel, err error) {

	ch = &Channel{}
	ch.state = ServerStateUninitialized
	ch.shim = ts.NewTransportShim()

	crt, err := tls.X509KeyPair([]byte(constants.SrvTestCrt), []byte(constants.SrvTestKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create server credentials: %v", err)
	}

	conf := &tls.Config{Certificates: []tls.Certificate{crt}, MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true, InsecureSkipVerify: true}
	ch.conn = tls.Server(ch.shim, conf)
	id, err := uuid.NewRandom()

	if err != nil {
		return nil, fmt.Errorf("failed to create UUID: %v", err)
	}

	ch.connID, err = id.MarshalBinary()

	if err != nil {
		return nil, fmt.Errorf("failed to create connection id: %v", err)
	}

	return ch, nil
}

// NewSecureSessionService creates instance of secure session service
func NewSecureSessionService() (srv *SecureSessionService, err error) {
	srv = &SecureSessionService{}
	srv.channels = make(map[string]*Channel)
	return srv, nil
}

func (s *SecureSessionService) BeginSession(ctx context.Context, req *pb.BeginSessionRequest) (*pb.BeginSessionResponse, error) {

	ch, err := NewChannel()

	if err != nil {
		return nil, fmt.Errorf("failed to create new channnel: %v", err)
	}

	go func() {
		err := ch.conn.Handshake()
		if err != nil {
			glog.Warningf("Handshake failed with: %v", err.Error())
		}
	}()

	ch.shim.QueueReceiveBuf(req.TlsRecords)

	rep := &pb.BeginSessionResponse{
		SessionContext: ch.connID,
		TlsRecords:     ch.shim.GetSendBuf(0),
	}

	ch.state = ServerStateInitiated
	s.channels[base64.StdEncoding.EncodeToString(ch.connID)] = ch

	return rep, nil
}

func (s *SecureSessionService) Handshake(ctx context.Context, req *pb.HandshakeRequest) (*pb.HandshakeResponse, error) {
	connID := base64.StdEncoding.EncodeToString(req.SessionContext)

	ch, found := s.channels[connID]

	if !found {
		return nil, fmt.Errorf("session with id: %v not found", connID)
	}

	if ch.state != ServerStateInitiated {
		return nil, fmt.Errorf("session with id: %v in unexpected state: %d. Expecting: %d", connID, ch.state, ServerStateInitiated)
	}

	ch.shim.QueueReceiveBuf(req.TlsRecords)

	rep := &pb.HandshakeResponse{
		TlsRecords: ch.shim.GetSendBufNonBlocking(),
	}

	ch.state = ServerStateHandshakeCompleted
	return rep, nil
}

func (s *SecureSessionService) NegotiateAttestation(ctx context.Context, req *pb.NegotiateAttestationRequest) (*pb.NegotiateAttestationResponse, error) {
	connID := base64.StdEncoding.EncodeToString(req.SessionContext)
	ch, found := s.channels[connID]

	if !found {
		return nil, fmt.Errorf("session with id: %v not found", connID)
	}

	if ch.state != ServerStateHandshakeCompleted {
		return nil, fmt.Errorf("session with id: %v in unexpected state: %d. Expecting: %d", connID, ch.state, ServerStateHandshakeCompleted)
	}

	ch.shim.QueueReceiveBuf(req.OfferedEvidenceTypesRecords)

	buf := make([]byte, len(req.OfferedEvidenceTypesRecords))
	bufLen, err := ch.conn.Read(buf)

	if err != nil {
		ch.state = ServerStateFailed
		return nil, fmt.Errorf("failed to read client's OfferedEvidenceTypeRecords message from tls connection : %v", err)
	}

	var clientAttList attpb.AttestationEvidenceTypeList

	err = proto.Unmarshal(buf[:bufLen], &clientAttList)
	if err != nil {
		ch.state = ServerStateFailed
		return nil, fmt.Errorf("failed to unmarshal AttestationEvidenceTypeList: %v", err)
	}

	serverSelection := attpb.AttestationEvidenceTypeList{}
	selectedEvidence := attpb.AttestationEvidenceType_UNKNOWN
	for _, tp := range clientAttList.Types {
		if tp == attpb.AttestationEvidenceType_TPM2_QUOTE || tp == attpb.AttestationEvidenceType_TCG_EVENT_LOG || tp == attpb.AttestationEvidenceType_NULL_ATTESTATION {
			selectedEvidence = tp
			break
		}
	}

	if selectedEvidence == attpb.AttestationEvidenceType_UNKNOWN {
		ch.state = ServerStateFailed
		return nil, fmt.Errorf("client's AttestationEvidenceTypeList not supported by the server")
	}
	serverSelection.Types = append(serverSelection.Types, selectedEvidence)

	buf, err = proto.Marshal(&serverSelection)
	if err != nil {
		ch.state = ServerStateFailed
		return nil, fmt.Errorf("failed to marshal server's AttestationEvidenceTypeList: %v", err)
	}

	go func() {
		_, err := ch.conn.Write(buf)
		if err != nil {
			ch.state = ServerStateFailed
			glog.Warningf("server failed to send selected evidence via TLS connection: %v", err.Error())
		}
	}()

	rep := &pb.NegotiateAttestationResponse{}
	rep.RequiredEvidenceTypesRecords = ch.shim.GetSendBuf(0)

	ch.state = ServerStateAttestationNegotiated
	return rep, nil
}

func (s *SecureSessionService) Finalize(ctx context.Context, req *pb.FinalizeRequest) (*pb.FinalizeResponse, error) {

	connID := base64.StdEncoding.EncodeToString(req.SessionContext)
	ch, found := s.channels[connID]

	if !found {
		return nil, fmt.Errorf("session with id: %v not found", connID)
	}

	if ch.state != ServerStateAttestationNegotiated {
		return nil, fmt.Errorf("session with id: %v in unexpected state: %d. Expecting: %d", connID, ch.state, ServerStateAttestationNegotiated)
	}

	ch.shim.QueueReceiveBuf(req.AttestationEvidenceRecords)
	buf := make([]byte, len(req.AttestationEvidenceRecords))

	offset := 0
	priorChunkLen := 0

	/*
	 * Approach: for a large attestation (e.g., 11K TLS read returns the attestation
	 * in chunks.  The attestation size in total is smaller than the length
	 * of the req.AttestationEvidenceRecords buffer after its decrypted via
	 * ch.conn.Read. If ch.conn.Read is called beyond the total size of the
	 * decrypted attestion it will block and hang the connection.  Given that we
	 * do not know the attestation's exact size, the current strategy is to keep
	 * reading while the decrypted chunks returned by the ch.conn.Read are getting
	 * larger.  Once a decrease in size is detected, it is treated as the last chunk.
	 */

	for {
		chunkLen, err := ch.conn.Read(buf[offset:])

		if err != nil {
			ch.state = ServerStateFailed
			return nil, fmt.Errorf("failed to read client's AttestationEvidenceRecords message from TLS connection : %v", err)
		}

		offset += chunkLen

		// The multi-chunk approach described above only applies to large attestations (e.g., 11K).
		if priorChunkLen == 0 && chunkLen <= minUnchunkedAttestationSize {
			break
		}

		if chunkLen <= priorChunkLen {
			break
		} else {
			priorChunkLen = chunkLen
		}
	}

	var clientAttEvidence attpb.AttestationEvidence

	// 16 bytes to account for session key that gets appended.
	AttestationPayloadOffset := len([]byte(constants.AttestationPrefix)) + 16

	err := proto.Unmarshal(buf[AttestationPayloadOffset:offset], &clientAttEvidence)
	if err != nil {
		ch.state = ServerStateFailed
		return nil, fmt.Errorf("failed to unmarshal AttestationEvidence: %v", err)
	}

	rep := &pb.FinalizeResponse{}

	ch.state = ServerStateAttestationAccepted
	return rep, nil
}

func (s *SecureSessionService) EndSession(ctx context.Context, req *pb.EndSessionRequest) (*pb.EndSessionResponse, error) {
	connID := base64.StdEncoding.EncodeToString(req.SessionContext)
	ch, found := s.channels[connID]

	if !found {
		return nil, fmt.Errorf("session with id: %v not found", connID)
	}

	if ch.state != ServerStateAttestationAccepted {
		return nil, fmt.Errorf("session with id: %v in unexpected state: %d. Expecting: %d", connID, ch.state, ServerStateAttestationAccepted)
	}

	ch.shim.QueueReceiveBuf(req.TlsRecords)

	buf := make([]byte, len(req.TlsRecords))
	bufLen, err := ch.conn.Read(buf)

	if err != nil {
		ch.state = ServerStateFailed
		return nil, fmt.Errorf("failed to read from tls connection : %v", err)
	}

	if !bytes.Equal(buf[:bufLen], []byte(constants.EndSessionString)) {
		ch.state = ServerStateFailed
		return nil, fmt.Errorf("End of session string mismatch")
	}

	rep := &pb.EndSessionResponse{}

	glog.Infof("EndSession: %v session ended.", connID)

	ch.state = ServerStateEnded
	return rep, nil
}
