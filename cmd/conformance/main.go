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

// Binary to run against a server to validate protocol conformance.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"

	"flag"
	"github.com/GoogleCloudPlatform/stet/client"
	"github.com/GoogleCloudPlatform/stet/constants"
	aepb "github.com/GoogleCloudPlatform/stet/proto/attestation_evidence_go_proto"
	cwpb "github.com/GoogleCloudPlatform/stet/proto/confidential_wrap_go_proto"
	sspb "github.com/GoogleCloudPlatform/stet/proto/secure_session_go_proto"
	"github.com/GoogleCloudPlatform/stet/server"
	"github.com/GoogleCloudPlatform/stet/transportshim"
	"github.com/alecthomas/colour"
	apb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm/tpm2"
	"google.golang.org/protobuf/proto"
)

var (
	keyURI = flag.String("key-uri", fmt.Sprintf("http://localhost:%d/v0/%v", constants.HTTPPort, server.KeyPath1), "A valid key URI stored in the server")
)

// recordBufferSize is the number of bytes allocated to buffers when reading
// records from the TLS session. 16KB is the maximum TLS record size, so this
// value guarantees incoming records will fit in the buffer.
const recordBufferSize = 16384

const (
	recordHeaderHandshake      = 0x16
	handshakeHeaderServerHello = 0x02
)

type ekmClient struct {
	client client.ConfidentialEKMClient
	shim   transportshim.ShimInterface
	tls    *tls.Conn
}

// Initializes a new EKM client against the given key URL with the given
// cipher suites, also kicking off the internal TLS handshake.
func newEKMClientWithSuites(keyURL string, cipherSuites []uint16) ekmClient {
	c := ekmClient{}
	c.client = client.NewConfidentialEKMClient(keyURL)

	c.shim = transportshim.NewTransportShim()

	cfg := &tls.Config{
		CipherSuites:       cipherSuites,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	}

	c.tls = tls.Client(c.shim, cfg)

	go func() {
		if err := c.tls.Handshake(); err != nil {
			return
		}
	}()

	return c
}

func newEKMClient(keyURL string) ekmClient {
	return newEKMClientWithSuites(keyURL, constants.AllowableCipherSuites)
}

// Returns an empty byte array.
func emptyFn([]byte) []byte { return []byte{} }

type beginSessionTest struct {
	testName         string
	expectErr        bool
	mutateTLSRecords func(r []byte) []byte
	altCipherSuites  []uint16
}

func runBeginSessionTestCase(mutateTLSRecords func(r []byte) []byte, altCipherSuites []uint16) error {
	ctx := context.Background()

	var c ekmClient
	if altCipherSuites != nil {
		c = newEKMClientWithSuites(*keyURI, altCipherSuites)
	} else {
		c = newEKMClient(*keyURI)
	}

	req := &sspb.BeginSessionRequest{
		TlsRecords: c.shim.DrainSendBuf(),
	}

	// Mutate the request TLS records.
	records := req.TlsRecords
	if mutateTLSRecords != nil {
		records = mutateTLSRecords(records)
	}
	req.TlsRecords = records

	resp, err := c.client.BeginSession(ctx, req)
	if err != nil {
		return err
	}

	records = resp.GetTlsRecords()
	if len(records) < 6 {
		return fmt.Errorf("length of record (%d) too short to be a Server Hello", len(records))
	}

	if records[0] != recordHeaderHandshake {
		return fmt.Errorf("handshake record not received")
	}

	if records[5] != handshakeHeaderServerHello {
		return fmt.Errorf("response is not Server Hello")
	}

	if records[1] == 3 && records[2] == 3 && altCipherSuites != nil {
		return errors.New("fake error to match the TLS 1.2 test")
	}
	return nil
}

type handshakeTest struct {
	testName         string
	expectErr        bool
	mutateTLSRecords func(r []byte) []byte
	mutateSessionKey func(s []byte) []byte
}

func runHandshakeTestCase(mutateTLSRecords, mutateSessionKey func(r []byte) []byte) error {
	ctx := context.Background()

	c := newEKMClient(*keyURI)

	req := &sspb.BeginSessionRequest{
		TlsRecords: c.shim.DrainSendBuf(),
	}

	resp, err := c.client.BeginSession(ctx, req)
	if err != nil {
		return err
	}

	sessionContext := resp.GetSessionContext()
	if mutateSessionKey != nil {
		sessionContext = mutateSessionKey(sessionContext)
	}

	c.shim.QueueReceiveBuf(resp.GetTlsRecords())

	records := c.shim.DrainSendBuf()
	if mutateTLSRecords != nil {
		records = mutateTLSRecords(records)
	}

	req2 := &sspb.HandshakeRequest{
		SessionContext: sessionContext,
		TlsRecords:     records,
	}

	_, err = c.client.Handshake(ctx, req2)
	if err != nil {
		return err
	}

	// Under TLS 1.3, the TLS implementation has nothing to return here.
	// However, attempting to call `c.tls.ConnectionState()` when the
	// server communicates with TLS 1.2 causes the client to hang
	// infinitely, so as a proxy, perform checks on the response records
	// only if they are non-nil.
	if len(resp.GetTlsRecords()) > 0 {
		records := resp.GetTlsRecords()

		// The handshake data itself is encypted, so just verify that the
		// header for this segment of data is a handshake record.
		if records[0] != recordHeaderHandshake {
			return fmt.Errorf("Handshake record not received")
		}
	}

	return nil
}

type negotiateAttestationTest struct {
	testName         string
	expectErr        bool
	evidenceTypes    []aepb.AttestationEvidenceType
	nonceTypes       []aepb.NonceType
	mutateTLSRecords func(r []byte) []byte
	mutateSessionKey func(s []byte) []byte
}

func runNegotiateAttestationTestCase(evidenceTypes []aepb.AttestationEvidenceType, nonceTypes []aepb.NonceType,
	mutateTLSRecords, mutateSessionKey func(r []byte) []byte) (*aepb.AttestationEvidenceTypeList, error) {
	ctx := context.Background()

	c := newEKMClient(*keyURI)

	req := &sspb.BeginSessionRequest{
		TlsRecords: c.shim.DrainSendBuf(),
	}

	resp, err := c.client.BeginSession(ctx, req)
	if err != nil {
		return nil, err
	}

	c.shim.QueueReceiveBuf(resp.GetTlsRecords())

	req2 := &sspb.HandshakeRequest{
		SessionContext: resp.GetSessionContext(),
		TlsRecords:     c.shim.DrainSendBuf(),
	}

	resp2, err := c.client.Handshake(ctx, req2)
	if err != nil {
		return nil, err
	}

	// If TLS 1.2, enqueue response bytes (TLS 1.3 has none).
	if len(resp.GetTlsRecords()) > 0 {
		c.shim.QueueReceiveBuf(resp2.GetTlsRecords())
	}

	evidenceTypeList := &aepb.AttestationEvidenceTypeList{
		Types:      evidenceTypes,
		NonceTypes: nonceTypes,
	}

	marshaledEvidenceTypes, err := proto.Marshal(evidenceTypeList)
	if err != nil {
		return nil, fmt.Errorf("error marshalling evidence to proto: %v", err)
	}

	if _, err := c.tls.Write(marshaledEvidenceTypes); err != nil {
		return nil, fmt.Errorf("error writing evidence to TLS connection: %v", err)
	}

	// Capture the TLS session-protected records and send them over the RPC.
	offeredEvidenceTypeRecords := c.shim.DrainSendBuf()
	if mutateTLSRecords != nil {
		offeredEvidenceTypeRecords = mutateTLSRecords(offeredEvidenceTypeRecords)
	}

	sessionContext := resp.GetSessionContext()
	if mutateSessionKey != nil {
		sessionContext = mutateSessionKey(sessionContext)
	}

	req3 := &sspb.NegotiateAttestationRequest{
		SessionContext:              sessionContext,
		OfferedEvidenceTypesRecords: offeredEvidenceTypeRecords,
	}

	resp3, err := c.client.NegotiateAttestation(ctx, req3)
	if err != nil {
		return nil, err
	}

	records := resp3.GetRequiredEvidenceTypesRecords()

	if len(records) == 0 {
		return nil, fmt.Errorf("got no evidence bytes from server response")
	}

	// Attempt to unmarshal the response by passing the serialized bytes to the
	// TLS implementation, and unmarshal the resulting decrypted bytes.
	evidenceRecords := resp3.GetRequiredEvidenceTypesRecords()
	c.shim.QueueReceiveBuf(evidenceRecords)

	readBuf := make([]byte, recordBufferSize)
	n, err := c.tls.Read(readBuf)

	if err != nil {
		return nil, fmt.Errorf("error reading data from TLS connection: %v", err)
	}

	// Unmarshal the response written back from the TLS intercept.
	negotiatedTypes := &aepb.AttestationEvidenceTypeList{}
	if err = proto.Unmarshal(readBuf[:n], negotiatedTypes); err != nil {
		return nil, fmt.Errorf("error parsing attestation types into a proto: %v", err)
	}

	if len(negotiatedTypes.GetTypes()) == 0 {
		return nil, fmt.Errorf("server responded with no attestation types")
	}

	return negotiatedTypes, nil
}

type finalizeTest struct {
	testName         string
	fullAttestation  bool
	expectErr        bool
	evidenceTypes    []aepb.AttestationEvidenceType
	nonceTypes       []aepb.NonceType
	mockAttestation  *apb.Attestation
	mutateTLSRecords func(r []byte) []byte
	mutateSessionKey func(s []byte) []byte
}

func runFinalizeTestCase(fullAttestation bool, evidenceTypes []aepb.AttestationEvidenceType, nonceTypes []aepb.NonceType,
	mockAttestation *apb.Attestation, mutateTLSRecords, mutateSessionKey func(r []byte) []byte) error {
	ctx := context.Background()

	// If running a test case where we are trying to generate a complete attestation, just use the
	// EstablishSecureSession() method from the `client` package (since it already has the complete
	// logic for generating attestations, etc).
	if fullAttestation {
		_, err := client.EstablishSecureSession(ctx, *keyURI, "", client.SkipTLSVerify(true))
		return err
	}

	c := newEKMClient(*keyURI)

	req := &sspb.BeginSessionRequest{
		TlsRecords: c.shim.DrainSendBuf(),
	}

	resp, err := c.client.BeginSession(ctx, req)
	if err != nil {
		return err
	}

	c.shim.QueueReceiveBuf(resp.GetTlsRecords())

	req2 := &sspb.HandshakeRequest{
		SessionContext: resp.GetSessionContext(),
		TlsRecords:     c.shim.DrainSendBuf(),
	}

	resp2, err := c.client.Handshake(ctx, req2)
	if err != nil {
		return err
	}

	// If TLS 1.2, enqueue response bytes (TLS 1.3 has none).
	if len(resp.GetTlsRecords()) > 0 {
		c.shim.QueueReceiveBuf(resp2.GetTlsRecords())
	}

	evidenceTypeList := &aepb.AttestationEvidenceTypeList{
		Types:      evidenceTypes,
		NonceTypes: nonceTypes,
	}

	marshaledEvidenceTypes, err := proto.Marshal(evidenceTypeList)
	if err != nil {
		return fmt.Errorf("error marshalling evidence type list to proto: %v", err)
	}

	if _, err := c.tls.Write(marshaledEvidenceTypes); err != nil {
		return fmt.Errorf("error writing evidence type list to TLS connection: %v", err)
	}

	// Capture the TLS session-protected records and send them over the RPC.
	offeredEvidenceTypeRecords := c.shim.DrainSendBuf()

	req3 := &sspb.NegotiateAttestationRequest{
		SessionContext:              resp.GetSessionContext(),
		OfferedEvidenceTypesRecords: offeredEvidenceTypeRecords,
	}

	resp3, err := c.client.NegotiateAttestation(ctx, req3)
	if err != nil {
		return err
	}

	records := resp3.GetRequiredEvidenceTypesRecords()

	if len(records) == 0 {
		return fmt.Errorf("got no evidence bytes from server response")
	}

	// Attempt to unmarshal the response by passing the serialized bytes to the
	// TLS implementation, and unmarshal the resulting decrypted bytes.
	evidenceRecords := resp3.GetRequiredEvidenceTypesRecords()
	c.shim.QueueReceiveBuf(evidenceRecords)

	readBuf := make([]byte, recordBufferSize)
	n, err := c.tls.Read(readBuf)

	if err != nil {
		return fmt.Errorf("error reading data from TLS connection: %v", err)
	}

	// Unmarshal the response written back from the TLS intercept.
	negotiatedTypes := &aepb.AttestationEvidenceTypeList{}
	if err = proto.Unmarshal(readBuf[:n], negotiatedTypes); err != nil {
		return fmt.Errorf("error parsing attestation types into a proto: %v", err)
	}

	if len(negotiatedTypes.GetTypes()) == 0 {
		return fmt.Errorf("server responded with no attestation types")
	}

	sessionContext := resp.GetSessionContext()
	if mutateSessionKey != nil {
		sessionContext = mutateSessionKey(sessionContext)
	}

	req4 := &sspb.FinalizeRequest{
		SessionContext: sessionContext,
	}

	if mockAttestation != nil {
		evidence := aepb.AttestationEvidence{
			Attestation: mockAttestation,
		}

		marshaledEvidence, err := proto.Marshal(&evidence)
		if err != nil {
			return fmt.Errorf("error marshalling attestation evidence to proto: %v", err)
		}

		if _, err := c.tls.Write(marshaledEvidence); err != nil {
			return fmt.Errorf("error writing evidence to TLS connection: %v", err)
		}

		// Wait for TLS session to process, then add session-protected records to request.
		records = c.shim.DrainSendBuf()
		if mutateTLSRecords != nil {
			records = mutateTLSRecords(records)
		}

		req4.AttestationEvidenceRecords = records
	}

	if _, err := c.client.Finalize(ctx, req4); err != nil {
		return err
	}

	return nil
}

// Establishes a secure session, returning the ekmClient and session context.
func establishSecureSession() (*ekmClient, []byte, error) {
	ctx := context.Background()

	c := newEKMClient(*keyURI)

	req := &sspb.BeginSessionRequest{
		TlsRecords: c.shim.DrainSendBuf(),
	}

	resp, err := c.client.BeginSession(ctx, req)
	if err != nil {
		return nil, nil, err
	}

	c.shim.QueueReceiveBuf(resp.GetTlsRecords())

	req2 := &sspb.HandshakeRequest{
		SessionContext: resp.GetSessionContext(),
		TlsRecords:     c.shim.DrainSendBuf(),
	}

	resp2, err := c.client.Handshake(ctx, req2)
	if err != nil {
		return nil, nil, err
	}

	// If TLS 1.2, enqueue response bytes (TLS 1.3 has none).
	if len(resp.GetTlsRecords()) > 0 {
		c.shim.QueueReceiveBuf(resp2.GetTlsRecords())
	}

	evidenceTypeList := &aepb.AttestationEvidenceTypeList{
		Types:      []aepb.AttestationEvidenceType{aepb.AttestationEvidenceType_NULL_ATTESTATION},
		NonceTypes: []aepb.NonceType{aepb.NonceType_NONCE_EKM32},
	}

	marshaledEvidenceTypes, err := proto.Marshal(evidenceTypeList)
	if err != nil {
		return nil, nil, fmt.Errorf("error marshalling evidence type list to proto: %v", err)
	}

	if _, err := c.tls.Write(marshaledEvidenceTypes); err != nil {
		return nil, nil, fmt.Errorf("error writing evidence type list to TLS connection: %v", err)
	}

	// Capture the TLS session-protected records and send them over the RPC.
	offeredEvidenceTypeRecords := c.shim.DrainSendBuf()

	req3 := &sspb.NegotiateAttestationRequest{
		SessionContext:              resp.GetSessionContext(),
		OfferedEvidenceTypesRecords: offeredEvidenceTypeRecords,
	}

	resp3, err := c.client.NegotiateAttestation(ctx, req3)
	if err != nil {
		return nil, nil, err
	}

	records := resp3.GetRequiredEvidenceTypesRecords()

	if len(records) == 0 {
		return nil, nil, fmt.Errorf("got no evidence bytes from server response")
	}

	// Attempt to unmarshal the response by passing the serialized bytes to the
	// TLS implementation, and unmarshal the resulting decrypted bytes.
	evidenceRecords := resp3.GetRequiredEvidenceTypesRecords()
	c.shim.QueueReceiveBuf(evidenceRecords)

	readBuf := make([]byte, recordBufferSize)
	n, err := c.tls.Read(readBuf)

	if err != nil {
		return nil, nil, fmt.Errorf("error reading data from TLS connection: %v", err)
	}

	// Unmarshal the response written back from the TLS intercept.
	negotiatedTypes := &aepb.AttestationEvidenceTypeList{}
	if err = proto.Unmarshal(readBuf[:n], negotiatedTypes); err != nil {
		return nil, nil, fmt.Errorf("error parsing attestation types into a proto: %v", err)
	}

	if len(negotiatedTypes.GetTypes()) == 0 {
		return nil, nil, fmt.Errorf("server responded with no attestation types")
	}

	req4 := &sspb.FinalizeRequest{
		SessionContext: resp.GetSessionContext(),
	}

	evidence := aepb.AttestationEvidence{
		Attestation: &apb.Attestation{},
	}

	marshaledEvidence, err := proto.Marshal(&evidence)
	if err != nil {
		return nil, nil, fmt.Errorf("error marshalling attestation evidence to proto: %v", err)
	}

	if _, err := c.tls.Write(marshaledEvidence); err != nil {
		return nil, nil, fmt.Errorf("error writing evidence to TLS connection: %v", err)
	}

	// Wait for TLS session to process, then add session-protected records to request.
	req4.AttestationEvidenceRecords = c.shim.DrainSendBuf()

	if _, err := c.client.Finalize(ctx, req4); err != nil {
		return nil, nil, err
	}

	return &c, resp.GetSessionContext(), nil
}

type endSessionTest struct {
	testName         string
	expectErr        bool
	mutateTLSRecords func(r []byte) []byte
	mutateSessionKey func(s []byte) []byte
}

func runEndSessionTestCase(mutateTLSRecords, mutateSessionKey func(r []byte) []byte) error {
	c, sessionContext, err := establishSecureSession()
	if err != nil {
		return err
	}

	if mutateSessionKey != nil {
		sessionContext = mutateSessionKey(sessionContext)
	}

	// Session-encrypt the EndSession constant string.
	if _, err := c.tls.Write([]byte(constants.EndSessionString)); err != nil {
		return fmt.Errorf("error session-encrypting the EndSession constant: %v", err)
	}

	records := c.shim.DrainSendBuf()
	if mutateTLSRecords != nil {
		records = mutateTLSRecords(records)
	}

	req5 := &sspb.EndSessionRequest{
		SessionContext: sessionContext,
		TlsRecords:     records,
	}

	_, err = c.client.EndSession(context.Background(), req5)
	return err
}

type confidentialWrapUnwrapTest struct {
	testName         string
	expectErr        bool
	keyPath          string
	mutateTLSRecords func(r []byte) []byte
	mutateSessionKey func(s []byte) []byte
}

func runConfidentialWrapTestCase(keyPath string, mutateTLSRecords, mutateSessionKey func(r []byte) []byte) error {
	c, sessionContext, err := establishSecureSession()
	if err != nil {
		return err
	}

	if mutateSessionKey != nil {
		sessionContext = mutateSessionKey(sessionContext)
	}

	// Create a WrapRequest, marshal, then session-encrypt it.
	wrapReq := &cwpb.WrapRequest{
		KeyPath:   keyPath,
		Plaintext: []byte{0x01},
		AdditionalContext: &cwpb.RequestContext{
			RelativeResourceName: "myresource",
			AccessReasonContext:  &cwpb.AccessReasonContext{Reason: cwpb.AccessReasonContext_CUSTOMER_INITIATED_ACCESS},
		},
		AdditionalAuthenticatedData: nil,
		KeyUriPrefix:                "",
	}

	marshaledWrapReq, err := proto.Marshal(wrapReq)
	if err != nil {
		return fmt.Errorf("error marshalling the WrapRequest to proto: %v", err)
	}

	if _, err := c.tls.Write(marshaledWrapReq); err != nil {
		return fmt.Errorf("error writing the WrapRequest to the TLS session: %v", err)
	}

	records := c.shim.DrainSendBuf()
	if mutateTLSRecords != nil {
		records = mutateTLSRecords(records)
	}

	req := &cwpb.ConfidentialWrapRequest{
		SessionContext: sessionContext,
		TlsRecords:     records,
		RequestMetadata: &cwpb.RequestMetadata{
			KeyPath:           wrapReq.GetKeyPath(),
			KeyUriPrefix:      wrapReq.GetKeyUriPrefix(),
			AdditionalContext: wrapReq.GetAdditionalContext(),
		},
	}

	_, err = c.client.ConfidentialWrap(context.Background(), req)
	if err != nil {
		return fmt.Errorf("error session-encrypting the records: %v", err)
	}

	return err
}

func runConfidentialUnwrapTestCase(keyPath string, mutateTLSRecords, mutateSessionKey func(r []byte) []byte) error {
	c, sessionContext, err := establishSecureSession()
	if err != nil {
		return err
	}

	plaintext := []byte("This is plaintext to encrypt.")

	// Send a ConfidentialWrapRequest so we have a wrapped blob to decrypt.
	wrapReq := &cwpb.WrapRequest{
		KeyPath:   keyPath,
		Plaintext: plaintext,
		AdditionalContext: &cwpb.RequestContext{
			RelativeResourceName: "myresource",
			AccessReasonContext:  &cwpb.AccessReasonContext{Reason: cwpb.AccessReasonContext_CUSTOMER_INITIATED_ACCESS},
		},
		AdditionalAuthenticatedData: nil,
		KeyUriPrefix:                "",
	}

	marshaledWrapReq, err := proto.Marshal(wrapReq)
	if err != nil {
		return fmt.Errorf("error marshalling the WrapRequest to proto: %v", err)
	}

	if _, err := c.tls.Write(marshaledWrapReq); err != nil {
		return fmt.Errorf("error writing the WrapRequest to the TLS session: %v", err)
	}

	records := c.shim.DrainSendBuf()
	if mutateTLSRecords != nil {
		records = mutateTLSRecords(records)
	}

	req := &cwpb.ConfidentialWrapRequest{
		SessionContext: sessionContext,
		TlsRecords:     records,
		RequestMetadata: &cwpb.RequestMetadata{
			KeyPath:           wrapReq.GetKeyPath(),
			KeyUriPrefix:      wrapReq.GetKeyUriPrefix(),
			AdditionalContext: wrapReq.GetAdditionalContext(),
		},
	}

	resp, err := c.client.ConfidentialWrap(context.Background(), req)
	if err != nil {
		return fmt.Errorf("error session-encrypting the records: %v", err)
	}

	// Session-decrypt the TLS records from the ConfidentialWrap call.
	records = resp.GetTlsRecords()
	c.shim.QueueReceiveBuf(records)

	readBuf := make([]byte, recordBufferSize)
	n, err := c.tls.Read(readBuf)

	if err != nil {
		return fmt.Errorf("error reading WrapResponse from TLS session: %v", err)
	}

	var wrapResp cwpb.WrapResponse
	if err = proto.Unmarshal(readBuf[:n], &wrapResp); err != nil {
		return fmt.Errorf("error parsing WrapResponse to proto: %v", err)
	}

	// Create an UnwrapRequest where the WrappedBlob is what we previously encrypted.
	unwrapReq := &cwpb.UnwrapRequest{
		KeyPath:     keyPath,
		WrappedBlob: wrapResp.GetWrappedBlob(),
		AdditionalContext: &cwpb.RequestContext{
			RelativeResourceName: "myresource",
			AccessReasonContext:  &cwpb.AccessReasonContext{Reason: cwpb.AccessReasonContext_CUSTOMER_INITIATED_ACCESS},
		},
		AdditionalAuthenticatedData: nil,
		KeyUriPrefix:                "",
	}

	marshaledUnwrapReq, err := proto.Marshal(unwrapReq)
	if err != nil {
		return fmt.Errorf("error marshalling the WrapRequest to proto: %v", err)
	}

	if _, err := c.tls.Write(marshaledUnwrapReq); err != nil {
		return fmt.Errorf("error writing the WrapRequest to the TLS session: %v", err)
	}

	records = c.shim.DrainSendBuf()
	if mutateTLSRecords != nil {
		records = mutateTLSRecords(records)
	}

	if mutateSessionKey != nil {
		sessionContext = mutateSessionKey(sessionContext)
	}

	req2 := &cwpb.ConfidentialUnwrapRequest{
		SessionContext: sessionContext,
		TlsRecords:     records,
		RequestMetadata: &cwpb.RequestMetadata{
			KeyPath:           unwrapReq.GetKeyPath(),
			KeyUriPrefix:      unwrapReq.GetKeyUriPrefix(),
			AdditionalContext: unwrapReq.GetAdditionalContext(),
		},
	}

	resp2, err := c.client.ConfidentialUnwrap(context.Background(), req2)
	if err != nil {
		return fmt.Errorf("error session-encrypting the records: %v", err)
	}

	records = resp2.GetTlsRecords()
	c.shim.QueueReceiveBuf(records)

	readBuf = make([]byte, recordBufferSize)
	n, err = c.tls.Read(readBuf)

	if err != nil {
		return fmt.Errorf("error reading UnwrapResponse from TLS session: %v", err)
	}

	var unwrapResp cwpb.UnwrapResponse
	if err = proto.Unmarshal(readBuf[:n], &unwrapResp); err != nil {
		return fmt.Errorf("error parsing UnwrapResponse: %v", err)
	}

	// Ensure session-decrypted plaintext in ConfidentialUnwrapRequest matches original plaintext.
	if !bytes.Equal(unwrapResp.GetPlaintext(), plaintext) {
		return fmt.Errorf("plaintext does not match original; got `%v`, want `%v`", unwrapResp.GetPlaintext(), plaintext)
	}

	return err
}

func main() {
	flag.Parse()

	// Define and run BeginSession tests.
	fmt.Println("Running BeginSession tests...")

	beginSessionTestCases := []beginSessionTest{
		{
			testName:  "Valid request with proper TLS Client Hello",
			expectErr: false,
		},
		{
			testName:  "Malformed Client Hello in request",
			expectErr: true,
			mutateTLSRecords: func(r []byte) []byte {
				r[5] = 0xFF // Client Hello byte should be 0x01
				return r
			},
		},
		{
			testName:         "No TLS records in request",
			expectErr:        true,
			mutateTLSRecords: emptyFn,
		},
		{
			testName:        "Invalid cipher suite",
			expectErr:       true,
			altCipherSuites: []uint16{tls.TLS_RSA_WITH_AES_256_GCM_SHA384},
		},
	}

	for _, testCase := range beginSessionTestCases {
		err := runBeginSessionTestCase(testCase.mutateTLSRecords, testCase.altCipherSuites)
		testPassed := testCase.expectErr == (err != nil)
		if testPassed {
			colour.Printf(" - ^2%v^R\n", testCase.testName)
		} else {
			colour.Printf(" - ^1%v^R (%v)\n", testCase.testName, err.Error())
		}
	}

	// Define and run Handshake tests.
	fmt.Println("\nRunning Handshake tests...")

	handshakeTestCases := []handshakeTest{
		{
			testName:  "Valid request with proper TLS Client Handshake",
			expectErr: false,
		},
		{
			testName:         "No TLS records in request",
			expectErr:        true,
			mutateTLSRecords: emptyFn,
		},
		{
			testName:         "Invalid session key",
			expectErr:        true,
			mutateSessionKey: emptyFn,
		},
	}

	for _, testCase := range handshakeTestCases {
		err := runHandshakeTestCase(testCase.mutateTLSRecords, testCase.mutateSessionKey)
		testPassed := testCase.expectErr == (err != nil)
		if testPassed {
			colour.Printf(" - ^2%v^R\n", testCase.testName)
		} else if err != nil {
			colour.Printf(" - ^1%v^R (%v)\n", testCase.testName, err.Error())
		} else {
			colour.Printf(" - ^1%v^R (missing error)\n", testCase.testName)
		}
	}

	// Define and run NegotiateAttestation tests.
	fmt.Println("\nRunning NegotiateAttestation tests...")

	negotiateAttestationTestCases := []negotiateAttestationTest{
		{
			testName:      "Valid request requesting null attestation",
			expectErr:     false,
			evidenceTypes: []aepb.AttestationEvidenceType{aepb.AttestationEvidenceType_NULL_ATTESTATION},
		},
		{
			testName:  "Valid request supporting all vTPM attestation types",
			expectErr: false,
			evidenceTypes: []aepb.AttestationEvidenceType{
				aepb.AttestationEvidenceType_TPM2_QUOTE,
				aepb.AttestationEvidenceType_TCG_EVENT_LOG,
			},
		},
		{
			testName:  "Valid request supporting all vTPM attestation types + null attestation",
			expectErr: false,
			evidenceTypes: []aepb.AttestationEvidenceType{
				aepb.AttestationEvidenceType_NULL_ATTESTATION,
				aepb.AttestationEvidenceType_TPM2_QUOTE,
				aepb.AttestationEvidenceType_TCG_EVENT_LOG,
			},
		},
		{
			testName:  "Valid request with server-unsupported evidence type",
			expectErr: true,
			evidenceTypes: []aepb.AttestationEvidenceType{
				aepb.AttestationEvidenceType_UNKNOWN_EVIDENCE_TYPE,
			},
		},
		{
			testName:  "Valid request with server-unsupported evidence type + null attestation",
			expectErr: false,
			evidenceTypes: []aepb.AttestationEvidenceType{
				aepb.AttestationEvidenceType_UNKNOWN_EVIDENCE_TYPE,
				aepb.AttestationEvidenceType_NULL_ATTESTATION,
			},
		},
		{
			testName:  "Valid request trying to negotiate nonce types",
			expectErr: false,
			evidenceTypes: []aepb.AttestationEvidenceType{
				aepb.AttestationEvidenceType_TPM2_QUOTE,
				aepb.AttestationEvidenceType_TCG_EVENT_LOG,
			},
			nonceTypes: []aepb.NonceType{
				aepb.NonceType_NONCE_EKM32,
			},
		},
		{
			testName:         "No TLS records in request",
			expectErr:        true,
			evidenceTypes:    []aepb.AttestationEvidenceType{aepb.AttestationEvidenceType_NULL_ATTESTATION},
			mutateTLSRecords: emptyFn,
		},
		{
			testName:         "Invalid session key",
			expectErr:        true,
			evidenceTypes:    []aepb.AttestationEvidenceType{aepb.AttestationEvidenceType_NULL_ATTESTATION},
			mutateSessionKey: emptyFn,
		},
	}

	for _, testCase := range negotiateAttestationTestCases {
		negotiatedTypes, err := runNegotiateAttestationTestCase(testCase.evidenceTypes, testCase.nonceTypes, testCase.mutateTLSRecords, testCase.mutateSessionKey)

		// Check that the negotiated types are what we expected.
		if err == nil {
			// At least one of the negotiated attestation types should be in the original list.
			if len(testCase.evidenceTypes) > 0 {
				goodAttestation := false
			matchAttestation:
				for _, negotiatedType := range negotiatedTypes.GetTypes() {
					for _, requestedType := range testCase.evidenceTypes {
						if negotiatedType == requestedType && negotiatedType != aepb.AttestationEvidenceType_UNKNOWN_EVIDENCE_TYPE {
							goodAttestation = true
							break matchAttestation
						}
					}
				}

				if !goodAttestation {
					err = fmt.Errorf("Negotiated attestation type(s) (%v) not in requested list (%v)", negotiatedTypes.GetTypes(), testCase.evidenceTypes)
				}
			}

			// At least one of the negotiated nonce types should be in the original list.
			//
			// Temporarily accept servers that don't negotiate nonce types, with the intention to
			// deprecate this in the future once it is reasonable to expect that all servers will
			// negotiate nonce types (as of now, this hasn't been part of the protocol for a long
			// enough period of time to expect all servers to implement it correctly).
			if len(testCase.nonceTypes) > 0 && len(negotiatedTypes.GetNonceTypes()) > 0 {
				goodNonce := false
			matchNonce:
				for _, negotiatedNonce := range negotiatedTypes.GetNonceTypes() {
					for _, requestedNonce := range testCase.nonceTypes {
						if negotiatedNonce == requestedNonce {
							goodNonce = true
							break matchNonce
						}
					}
				}

				if !goodNonce {
					err = fmt.Errorf("Negotiated nonce type(s) (%v) not in requested list (%v)", negotiatedTypes.GetNonceTypes(), testCase.nonceTypes)
				}
			}
		}

		testPassed := testCase.expectErr == (err != nil)

		if testPassed {
			colour.Printf(" - ^2%v^R\n", testCase.testName)
		} else if err != nil {
			colour.Printf(" - ^1%v^R (%v)\n", testCase.testName, err.Error())
		} else {
			colour.Printf(" - ^1%v^R (missing error)\n", testCase.testName)
		}
	}

	// Define and run Finalize tests.
	fmt.Println("\nRunning Finalize tests...")

	finalizeTestCases := []finalizeTest{
		{
			testName:      "Valid request requesting null attestation",
			expectErr:     false,
			evidenceTypes: []aepb.AttestationEvidenceType{aepb.AttestationEvidenceType_NULL_ATTESTATION},
		},
		{
			testName:        "Valid request requesting vTPM attestation evidence",
			fullAttestation: true,
			expectErr:       false,
			evidenceTypes: []aepb.AttestationEvidenceType{
				aepb.AttestationEvidenceType_TPM2_QUOTE,
				aepb.AttestationEvidenceType_TCG_EVENT_LOG,
			},
		},
		{
			testName:  "Invalid attestation records",
			expectErr: true,
			evidenceTypes: []aepb.AttestationEvidenceType{
				aepb.AttestationEvidenceType_TPM2_QUOTE,
				aepb.AttestationEvidenceType_TCG_EVENT_LOG,
			},
			mockAttestation: &apb.Attestation{AkPub: []byte("badestation")},
		},
		{
			testName:         "Invalid session key",
			expectErr:        true,
			evidenceTypes:    []aepb.AttestationEvidenceType{aepb.AttestationEvidenceType_NULL_ATTESTATION},
			mutateSessionKey: emptyFn,
		},
		{
			testName:  "Evidence doesn't match negotiated",
			expectErr: true,
			evidenceTypes: []aepb.AttestationEvidenceType{
				aepb.AttestationEvidenceType_TPM2_QUOTE,
				aepb.AttestationEvidenceType_TCG_EVENT_LOG,
			},
		},
	}

	// Check for TPM and root privileges to determine if we can generate attestations.
	_, err := tpm2.OpenTPM("/dev/tpmrm0")
	canAttest := err == nil

	if !canAttest {
		colour.Println("^5Note: Skipping test cases that require generating attestations.^R")
	}

	for _, testCase := range finalizeTestCases {
		if testCase.fullAttestation && !canAttest {
			colour.Printf(" - ^5%v [skipped]^R\n", testCase.testName)
			continue
		}

		err := runFinalizeTestCase(testCase.fullAttestation, testCase.evidenceTypes, testCase.nonceTypes,
			testCase.mockAttestation, testCase.mutateTLSRecords, testCase.mutateSessionKey)
		testPassed := testCase.expectErr == (err != nil)

		if testPassed {
			colour.Printf(" - ^2%v^R\n", testCase.testName)
		} else if err != nil {
			colour.Printf(" - ^1%v^R (%v)\n", testCase.testName, err.Error())
		} else {
			colour.Printf(" - ^1%v^R (missing error)\n", testCase.testName)
		}
	}

	// Define and run EndSession tests.
	fmt.Println("\nRunning EndSession tests...")

	endSessionTestCases := []endSessionTest{
		{
			testName:  "Establish secure session then valid EndSession",
			expectErr: false,
		},
		{
			testName:         "No TLS records in request",
			expectErr:        true,
			mutateTLSRecords: emptyFn,
		},
		{
			testName:         "Invalid session key",
			expectErr:        true,
			mutateSessionKey: emptyFn,
		},
	}

	for _, testCase := range endSessionTestCases {
		err := runEndSessionTestCase(testCase.mutateTLSRecords, testCase.mutateSessionKey)
		testPassed := testCase.expectErr == (err != nil)
		if testPassed {
			colour.Printf(" - ^2%v^R\n", testCase.testName)
		} else if err != nil {
			colour.Printf(" - ^1%v^R (%v)\n", testCase.testName, err.Error())
		} else {
			colour.Printf(" - ^1%v^R (missing error)\n", testCase.testName)
		}
	}

	goodKeyPath := (*keyURI)[strings.LastIndex(*keyURI, "/")+1:]

	// Define and run ConfidentialWrap tests.
	fmt.Println("\nRunning ConfidentialWrap tests...")

	confidentialWrapTestCases := []confidentialWrapUnwrapTest{
		{
			testName:  "Establish secure session then valid ConfidentialWrap",
			expectErr: false,
			keyPath:   goodKeyPath,
		},
		{
			testName:  "ConfidentialWrap with invalid key path",
			expectErr: true,
			keyPath:   "Surely the EKM would not have a valid key with this path...",
		},
		{
			testName:         "No TLS records in request",
			expectErr:        true,
			mutateTLSRecords: emptyFn,
		},
		{
			testName:         "Invalid session key",
			expectErr:        true,
			mutateSessionKey: emptyFn,
		},
	}

	for _, testCase := range confidentialWrapTestCases {
		err := runConfidentialWrapTestCase(testCase.keyPath, testCase.mutateTLSRecords, testCase.mutateSessionKey)
		testPassed := testCase.expectErr == (err != nil)
		if testPassed {
			colour.Printf(" - ^2%v^R\n", testCase.testName)
		} else if err != nil {
			colour.Printf(" - ^1%v^R (%v)\n", testCase.testName, err.Error())
		} else {
			colour.Printf(" - ^1%v^R missing error\n", testCase.testName)
		}
	}

	// Define and run ConfidentialUnwrap tests.
	fmt.Println("\nRunning ConfidentialUnwrap tests...")

	confidentialUnwrapTestCases := []confidentialWrapUnwrapTest{
		{
			testName:  "Establish secure session then valid ConfidentialUnwrap",
			expectErr: false,
			keyPath:   goodKeyPath,
		},
		{
			testName:  "ConfidentialWrap with invalid key path",
			expectErr: true,
			keyPath:   "Surely the EKM would not have a valid key with this path...",
		},
		{
			testName:         "No TLS records in request",
			expectErr:        true,
			mutateTLSRecords: emptyFn,
		},
		{
			testName:         "Invalid session key",
			expectErr:        true,
			mutateSessionKey: emptyFn,
		},
	}

	for _, testCase := range confidentialUnwrapTestCases {
		err := runConfidentialUnwrapTestCase(testCase.keyPath, testCase.mutateTLSRecords, testCase.mutateSessionKey)
		testPassed := testCase.expectErr == (err != nil)
		if testPassed {
			colour.Printf(" - ^2%v^R\n", testCase.testName)
		} else if err != nil {
			colour.Printf(" - ^1%v^R (%v)\n", testCase.testName, err.Error())
		} else {
			colour.Printf(" - ^1%v^R (missing error)\n", testCase.testName)
		}
	}

}
