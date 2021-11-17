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
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"sync"

	"github.com/GoogleCloudPlatform/stet/constants"
	attpb "github.com/GoogleCloudPlatform/stet/proto/attestation_evidence_go_proto"
	cwpb "github.com/GoogleCloudPlatform/stet/proto/confidential_wrap_go_proto"
	pb "github.com/GoogleCloudPlatform/stet/proto/secure_session_go_proto"
	sspb "github.com/GoogleCloudPlatform/stet/proto/secure_session_go_proto"
	ts "github.com/GoogleCloudPlatform/stet/transportshim"
	glog "github.com/golang/glog"
	tpmpb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/uuid"
	"google.golang.org/api/compute/v1"
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

const (
	// KeyPath1 is the key path for key1 in the reference server, which has
	// no policy requirements.
	KeyPath1 = "key1"
	key1     = "key1encrypted"

	// KeyPath2 is the key path for key2 in the reference server, which requires
	// a minimum technology of SEV to wrap or unwrap keys.
	KeyPath2 = "key2"
	key2     = "key2encrypted"
)

var requireSEV = &tpmpb.Policy{
	Platform: &tpmpb.PlatformPolicy{
		MinimumTechnology: tpmpb.GCEConfidentialTechnology_AMD_SEV,
	},
}

// Channel for connection internals
type Channel struct {
	conn   *tls.Conn
	shim   ts.ShimInterface
	connID []byte
	state  SrvState

	// The negotiated attestation types.
	attestationEvidenceTypes []attpb.AttestationEvidenceType

	// The MachineState corresponding to the attestation. This is nil if the
	// workload presented the null attestation.
	ms *tpmpb.MachineState
}

// SecureSessionService implements the SecureSession interface.
type SecureSessionService struct {
	tlsVersion uint16
	mu         sync.Mutex
	channels   map[string]*Channel
	keys       map[string]string

	// Necessary to embed these to maintain forward compatibility.
	pb.UnimplementedConfidentialEkmSessionEstablishmentServiceServer
	cwpb.UnimplementedConfidentialWrapUnwrapServiceServer
}

// minUnchunkedAttestationSize used as hint to apply multiple
// read approach when receiving the attestation.
const minUnchunkedAttestationSize = 1024

// Wrap takes in a keyPath, aad, and plaintext, and outputs the wrapped
// plaintext that the server returns. Invariant: object must have been
// created through NewSecureSessionService to set up keys. keyURI must be valid.
func (s *SecureSessionService) Wrap(keyURI string, aad, plaintext []byte) []byte {
	key := s.keys[keyURI]
	return append(append(aad, key...), plaintext...)
}

// NewChannel sets up tls context and network shim
func NewChannel(tlsVersion uint16) (ch *Channel, err error) {
	ch = &Channel{}
	ch.state = ServerStateUninitialized
	ch.shim = ts.NewTransportShim()

	crt, err := tls.X509KeyPair([]byte(constants.SrvTestCrt), []byte(constants.SrvTestKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create server credentials: %v", err)
	}

	conf := &tls.Config{
		Certificates:           []tls.Certificate{crt},
		MinVersion:             tlsVersion,
		MaxVersion:             tlsVersion,
		CipherSuites:           constants.AllowableCipherSuites,
		SessionTicketsDisabled: true,
		InsecureSkipVerify:     true,
	}
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
func NewSecureSessionService(tlsVersion uint16) (srv *SecureSessionService, err error) {
	srv = &SecureSessionService{tlsVersion: tlsVersion}
	srv.channels = make(map[string]*Channel)
	srv.keys = map[string]string{
		KeyPath1: key1,
		KeyPath2: key2,
	}
	return srv, nil
}

func (s *SecureSessionService) BeginSession(ctx context.Context, req *sspb.BeginSessionRequest) (*sspb.BeginSessionResponse, error) {
	ch, err := NewChannel(s.tlsVersion)

	if err != nil {
		return nil, fmt.Errorf("failed to create new channnel: %v", err)
	}

	go func() {
		if err := ch.conn.Handshake(); err != nil {
			glog.Warningf("Handshake failed with: %v", err.Error())
		}
	}()

	if len(req.TlsRecords) == 0 {
		return nil, fmt.Errorf("TLS records were empty")
	}

	ch.shim.QueueReceiveBuf(req.TlsRecords)

	rep := &sspb.BeginSessionResponse{
		SessionContext: ch.connID,
		TlsRecords:     ch.shim.DrainSendBuf(),
	}

	ch.state = ServerStateInitiated
	s.channels[base64.StdEncoding.EncodeToString(ch.connID)] = ch

	return rep, nil
}

func (s *SecureSessionService) Handshake(ctx context.Context, req *sspb.HandshakeRequest) (*sspb.HandshakeResponse, error) {
	connID := base64.StdEncoding.EncodeToString(req.SessionContext)
	ch, found := s.channels[connID]

	if !found {
		return nil, fmt.Errorf("session with id: %v not found", connID)
	}

	if ch.state != ServerStateInitiated {
		return nil, fmt.Errorf("session with id: %v in unexpected state: %d. Expecting: %d", connID, ch.state, ServerStateInitiated)
	}

	if len(req.TlsRecords) == 0 {
		return nil, fmt.Errorf("TLS records were empty")
	}

	ch.shim.QueueReceiveBuf(req.TlsRecords)

	// With the "Client Hello" and "Server Hello" records having already been
	// exchanged as part of the BeginSession request, the records exchanged
	// during this part of the handshake are "Client Change Cipher Spec" and
	// "Client Handshake Finished", both of which are sent simultaneously here.
	//
	// However, there is a divergence between the behaviour of TLS 1.2 and 1.3+
	// at this point: while in 1.2, the server must then respond with its
	// "Server Change Cipher Spec" and "Server Handshake Finished" records
	// before the client starts sending application data, in 1.3, the client
	// sends its application data directly following its "Client Handshake
	// Finished" (that is, there is no waiting on a "Server Handshake Finished"
	// from the server).
	//
	// Because of this, under TLS 1.2, the underlying TLS implementation has
	// records to drain here and send as part of the handshake response, whereas
	// with TLS 1.3, there are no bytes, and attempting a read from the TLS
	// implementation would result in 0 bytes. Therefore, we simply return an
	// empty byte slice as the records in the response.
	var records []byte
	if ch.conn.ConnectionState().Version == tls.VersionTLS12 {
		records = ch.shim.DrainSendBuf()
	}

	rep := &sspb.HandshakeResponse{
		TlsRecords: records,
	}

	// Update state if TLS indicates handshake is complete, otherwise
	// we expect to perform another Handshake call from the client.
	if ch.conn.ConnectionState().HandshakeComplete {
		ch.state = ServerStateHandshakeCompleted
	}
	return rep, nil
}

func (s *SecureSessionService) NegotiateAttestation(ctx context.Context, req *sspb.NegotiateAttestationRequest) (*sspb.NegotiateAttestationResponse, error) {
	connID := base64.StdEncoding.EncodeToString(req.SessionContext)
	ch, found := s.channels[connID]

	if !found {
		return nil, fmt.Errorf("session with id: %v not found", connID)
	}

	if ch.state != ServerStateHandshakeCompleted {
		return nil, fmt.Errorf("session with id: %v in unexpected state: %d. Expecting: %d", connID, ch.state, ServerStateHandshakeCompleted)
	}

	if len(req.OfferedEvidenceTypesRecords) == 0 {
		return nil, fmt.Errorf("TLS records were empty")
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
	for _, tp := range clientAttList.Types {
		switch tp {
		case attpb.AttestationEvidenceType_TPM2_QUOTE:
		case attpb.AttestationEvidenceType_TCG_EVENT_LOG:
			serverSelection.Types = append(serverSelection.Types, tp)
		}
	}

	if len(serverSelection.Types) == 0 {
		serverSelection.Types = append(serverSelection.Types, attpb.AttestationEvidenceType_NULL_ATTESTATION)
	}

	ch.attestationEvidenceTypes = serverSelection.Types

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

	rep := &sspb.NegotiateAttestationResponse{}
	rep.RequiredEvidenceTypesRecords = ch.shim.DrainSendBuf()

	ch.state = ServerStateAttestationNegotiated
	return rep, nil
}

func (s *SecureSessionService) Finalize(ctx context.Context, req *sspb.FinalizeRequest) (*sspb.FinalizeResponse, error) {
	connID := base64.StdEncoding.EncodeToString(req.SessionContext)
	ch, found := s.channels[connID]

	if !found {
		return nil, fmt.Errorf("session with id: %v not found", connID)
	}

	if ch.state != ServerStateAttestationNegotiated {
		return nil, fmt.Errorf("session with id: %v in unexpected state: %d. Expecting: %d", connID, ch.state, ServerStateAttestationNegotiated)
	}

	// Unmarshal attestation evidence if included in request.
	var clientAttEvidence attpb.AttestationEvidence

	if len(req.GetAttestationEvidenceRecords()) > 0 {
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

		if err := proto.Unmarshal(buf[:offset], &clientAttEvidence); err != nil {
			ch.state = ServerStateFailed
			return nil, fmt.Errorf("failed to unmarshal AttestationEvidence: %w", err)
		}
	}

	attestationExpected := false
	for _, tp := range ch.attestationEvidenceTypes {
		switch tp {
		case attpb.AttestationEvidenceType_TPM2_QUOTE:
		case attpb.AttestationEvidenceType_TCG_EVENT_LOG:
			attestationExpected = true
		}
	}

	if attestationExpected {
		att := clientAttEvidence.GetAttestation()

		if att == nil {
			return nil, fmt.Errorf("negotiated vTPM attestation but payload did not contain attestation")
		}

		instanceInfo := att.GetInstanceInfo()
		if instanceInfo == nil {
			return nil, fmt.Errorf("instanceInfo is empty; can't look up shielded instance identity")
		}

		client, err := compute.NewService(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to create GCE client: %w", err)
		}

		instance, err := client.Instances.GetShieldedInstanceIdentity(
			instanceInfo.GetProjectId(), instanceInfo.GetZone(), instanceInfo.GetInstanceName()).Do()
		if err != nil {
			return nil, fmt.Errorf("couldn't retrieve shielded instance identity: %w", err)
		}

		// Verify quote using the signing key returned by GetShieldedInstanceIdentity.
		block, _ := pem.Decode([]byte(instance.SigningKey.EkPub))
		if block == nil || block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("failed to decode PEM block containing public key")
		}

		pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unable to parse EK cert from GetShieldedInstanceIdentity: %w", err)
		}

		// Recreate the nonce generated on the client side to validate the attestation.
		tlsState := ch.conn.ConnectionState()
		material, err := tlsState.ExportKeyingMaterial(constants.ExportLabel, nil, 32)
		if err != nil {
			return nil, fmt.Errorf("error exporting key material: %w", err)
		}

		nonce := []byte(constants.AttestationPrefix)
		nonce = append(nonce, material...)

		ms, err := server.VerifyAttestation(att, server.VerifyOpts{Nonce: nonce, TrustedAKs: []crypto.PublicKey{pubKey}})
		if err != nil {
			return nil, fmt.Errorf("failed to verify quote: %w", err)
		}

		ch.ms = ms
		glog.Infof("Verified quote for instance: %v; machine state: %v", instanceInfo.String(), ms)
	} else {
		glog.Infof("Negotiated null attestation; skipping attestation verification")
	}

	rep := &sspb.FinalizeResponse{}

	ch.state = ServerStateAttestationAccepted
	return rep, nil
}

// ConfidentialWrap wraps the aad and plaintext in the request by concatenating
// them as (aad | key | plaintext).
func (s *SecureSessionService) ConfidentialWrap(ctx context.Context, req *cwpb.ConfidentialWrapRequest) (*cwpb.ConfidentialWrapResponse, error) {
	connID := base64.StdEncoding.EncodeToString(req.SessionContext)
	ch, found := s.channels[connID]

	if !found {
		return nil, fmt.Errorf("session with id: %v not found", connID)
	}

	if ch.state != ServerStateAttestationAccepted {
		return nil, fmt.Errorf("session with id: %v in unexpected state for ConfidentialWrap: %d. Expecting: %d", connID, ch.state, ServerStateAttestationAccepted)
	}

	ch.shim.QueueReceiveBuf(req.TlsRecords)
	buf := make([]byte, len(req.TlsRecords))

	bufLen, err := ch.conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("error reading WrapRequest from TLS records: %w", err)
	}

	wrapRequest := cwpb.WrapRequest{}
	if err := proto.Unmarshal(buf[:bufLen], &wrapRequest); err != nil {
		return nil, fmt.Errorf("failed to parse WrapRequest from TLS records: %w", err)
	}

	keyURI := fmt.Sprintf("%v%v", wrapRequest.GetKeyUriPrefix(), wrapRequest.GetKeyPath())
	if _, found = s.keys[keyURI]; !found {
		return nil, fmt.Errorf("key URI unknown by this server: %v", keyURI)
	}

	// Require SEV for `KeyPath2`.
	if keyURI == KeyPath2 {
		if err := server.EvaluatePolicy(ch.ms, requireSEV); err != nil {
			return nil, fmt.Errorf("attestation did not meet policy for key %v: %w", keyURI, err)
		}
	}

	wrapResponse := cwpb.WrapResponse{}
	wrapResponse.WrappedBlob = s.Wrap(keyURI, wrapRequest.GetAdditionalAuthenticatedData(), wrapRequest.GetPlaintext())

	buf, err = proto.Marshal(&wrapResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal server's WrapResponse: %w", err)
	}

	if _, err = ch.conn.Write(buf); err != nil {
		return nil, fmt.Errorf("server failed to send WrapResponse via TLS connection: %w", err)
	}

	rep := &cwpb.ConfidentialWrapResponse{}
	rep.TlsRecords = ch.shim.DrainSendBuf()

	return rep, nil
}

// ConfidentialUnwrap unwraps the given ciphertext with aad by splitting on the
// first instance of the requested key. The expected format of the wrapped text
// is (aad | key | plaintext). If the requested key is not present, or if the
// first part of the split does not match the aad, the unwrapping fails and
// returns an error. Otherwise, returns the determined plaintext.
func (s *SecureSessionService) ConfidentialUnwrap(ctx context.Context, req *cwpb.ConfidentialUnwrapRequest) (*cwpb.ConfidentialUnwrapResponse, error) {
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
		return nil, fmt.Errorf("error reading UnwrapRequest from TLS Records %w", err)
	}

	unwrapRequest := cwpb.UnwrapRequest{}
	if err := proto.Unmarshal(buf[:bufLen], &unwrapRequest); err != nil {
		return nil, fmt.Errorf("failed to parse UnwrapRequest from TLS records: %w", err)
	}

	keyURI := fmt.Sprintf("%v%v", unwrapRequest.GetKeyUriPrefix(), unwrapRequest.GetKeyPath())
	key, found := s.keys[keyURI]
	if !found {
		return nil, fmt.Errorf("key URI unknown by this server: %v", keyURI)
	}

	// Require SEV for `KeyPath2`.
	if keyURI == KeyPath2 {
		if err := server.EvaluatePolicy(ch.ms, requireSEV); err != nil {
			return nil, fmt.Errorf("attestation did not meet policy for key %v: %w", keyURI, err)
		}
	}

	unwrapResponse := cwpb.UnwrapResponse{}
	parts := bytes.SplitN(unwrapRequest.GetWrappedBlob(), []byte(key), 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("failed to decrypt wrapped blob")
	}
	if len(unwrapRequest.GetAdditionalAuthenticatedData()) != 0 && bytes.Compare(parts[0], unwrapRequest.GetAdditionalAuthenticatedData()) != 0 {
		return nil, fmt.Errorf("failed to match additional authenticated data")
	}
	unwrapResponse.Plaintext = parts[1]

	buf, err = proto.Marshal(&unwrapResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal server's UnwrapResponse: %w", err)
	}

	if _, err = ch.conn.Write(buf); err != nil {
		return nil, fmt.Errorf("server failed to send UnwrapResponse via TLS connection: %w", err)
	}

	rep := &cwpb.ConfidentialUnwrapResponse{}
	rep.TlsRecords = ch.shim.DrainSendBuf()

	return rep, nil
}

func (s *SecureSessionService) EndSession(ctx context.Context, req *sspb.EndSessionRequest) (*sspb.EndSessionResponse, error) {
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

	rep := &sspb.EndSessionResponse{}

	glog.Infof("EndSession: %v session ended.", connID)

	ch.state = ServerStateEnded
	return rep, nil
}
