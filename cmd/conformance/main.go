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
	"context"
	"crypto/tls"
	"fmt"

	"flag"
	"github.com/GoogleCloudPlatform/stet/client"
	"github.com/GoogleCloudPlatform/stet/constants"
	aepb "github.com/GoogleCloudPlatform/stet/proto/attestation_evidence_go_proto"
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

// Initializes a new EKM client for the given version of TLS against the
// given key URL, also kicking off the internal TLS handshake.
func newEKMClient(keyURL string, tlsVersion int) ekmClient {
	c := ekmClient{}
	c.client = client.NewConfidentialEKMClient(keyURL)

	c.shim = transportshim.NewTransportShim()

	cfg := &tls.Config{
		CipherSuites:       constants.AllowableCipherSuites,
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

// Returns an empty byte array.
func emptyFn([]byte) []byte { return []byte{} }

type beginSessionTest struct {
	testName         string
	expectErr        bool
	mutateTLSRecords func(r []byte) []byte
}

func runBeginSessionTestCase(mutateTLSRecords func(r []byte) []byte) error {
	ctx := context.Background()

	c := newEKMClient(*keyURI, tls.VersionTLS13)

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

	if records[0] != recordHeaderHandshake {
		return fmt.Errorf("Handshake record not received")
	}

	if records[5] != handshakeHeaderServerHello {
		return fmt.Errorf("Response is not Server Hello")
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

	c := newEKMClient(*keyURI, tls.VersionTLS13)

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

	c := newEKMClient(*keyURI, tls.VersionTLS13)

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

	c := newEKMClient(*keyURI, tls.VersionTLS13)

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

	att := &apb.Attestation{}
	if mockAttestation != nil {
		att = mockAttestation
	}

	evidence := aepb.AttestationEvidence{
		Attestation: att,
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

	if _, err := c.client.Finalize(ctx, req4); err != nil {
		return err
	}

	return nil
}

type endSessionTest struct {
	testName         string
	expectErr        bool
	mutateTLSRecords func(r []byte) []byte
	mutateSessionKey func(s []byte) []byte
}

func runEndSessionTestCase(mutateTLSRecords, mutateSessionKey func(r []byte) []byte) error {
	ctx := context.Background()

	c := newEKMClient(*keyURI, tls.VersionTLS13)

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
		Types:      []aepb.AttestationEvidenceType{aepb.AttestationEvidenceType_NULL_ATTESTATION},
		NonceTypes: []aepb.NonceType{aepb.NonceType_NONCE_EKM32},
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

	req4 := &sspb.FinalizeRequest{
		SessionContext: resp.GetSessionContext(),
	}

	evidence := aepb.AttestationEvidence{
		Attestation: &apb.Attestation{},
	}

	marshaledEvidence, err := proto.Marshal(&evidence)
	if err != nil {
		return fmt.Errorf("error marshalling attestation evidence to proto: %v", err)
	}

	if _, err := c.tls.Write(marshaledEvidence); err != nil {
		return fmt.Errorf("error writing evidence to TLS connection: %v", err)
	}

	// Wait for TLS session to process, then add session-protected records to request.
	req4.AttestationEvidenceRecords = c.shim.DrainSendBuf()

	if _, err := c.client.Finalize(ctx, req4); err != nil {
		return err
	}

	sessionContext := resp.GetSessionContext()
	if mutateSessionKey != nil {
		sessionContext = mutateSessionKey(sessionContext)
	}

	// Session-encrypt the EndSession constant string.
	if _, err := c.tls.Write([]byte(constants.EndSessionString)); err != nil {
		return fmt.Errorf("error session-encrypting the EndSession constant: %v", err)
	}

	records = c.shim.DrainSendBuf()
	if mutateTLSRecords != nil {
		records = mutateTLSRecords(records)
	}

	req5 := &sspb.EndSessionRequest{
		SessionContext: sessionContext,
		TlsRecords:     records,
	}

	_, err = c.client.EndSession(ctx, req5)
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
	}

	for _, testCase := range beginSessionTestCases {
		err := runBeginSessionTestCase(testCase.mutateTLSRecords)
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
		} else {
			colour.Printf(" - ^1%v^R (%v)\n", testCase.testName, err.Error())
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
		} else {
			colour.Printf(" - ^1%v^R (%v)\n", testCase.testName, err.Error())
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
		} else {
			colour.Printf(" - ^1%v^R (%v)\n", testCase.testName, err.Error())
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
		} else {
			colour.Printf(" - ^1%v^R (%v)\n", testCase.testName, err.Error())
		}
	}
}
