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
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"cloud.google.com/go/kms/apiv1"
	"flag"
	"github.com/GoogleCloudPlatform/stet/client/ekmclient"
	"github.com/GoogleCloudPlatform/stet/client/jwt"
	"github.com/GoogleCloudPlatform/stet/client/securesession"
	"github.com/GoogleCloudPlatform/stet/constants"
	aepb "github.com/GoogleCloudPlatform/stet/proto/attestation_evidence_go_proto"
	cwpb "github.com/GoogleCloudPlatform/stet/proto/confidential_wrap_go_proto"
	sspb "github.com/GoogleCloudPlatform/stet/proto/secure_session_go_proto"
	"github.com/GoogleCloudPlatform/stet/server"
	"github.com/GoogleCloudPlatform/stet/transportshim"
	"github.com/alecthomas/colour"
	glog "github.com/golang/glog"
	apb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm/tpm2"
	rpb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	spb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/protobuf/proto"
)

const (
	defaultKeyResourceName          = "myresource"
	defaultProtectedKeyResourceName = "myprotectedresource"
)

var (
	unprotectedKeyResourceName = flag.String("unprotected-resource-name", defaultKeyResourceName, "CloudKMS resource name of an external key not protected by CC attestation")
	protectedKeyResourceName   = flag.String("protected-resource-name", defaultProtectedKeyResourceName, "CloudKMS resource name of an external key protected by CC attestation")
	unprotectedKeyURI          string
	protectedKeyURI            string
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
	client ekmclient.ConfidentialEKMClient
	shim   transportshim.ShimInterface
	tls    *tls.Conn
}

// Encode JWT specific base64url encoding with padding stripped
func encodeSegment(seg []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")
}

// Decode JWT specific base64url encoding with padding stripped
func decodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}

func createAuthToken(ctx context.Context, keyURL string) (string, error) {
	u, err := url.Parse(keyURL)
	if err != nil {
		glog.Fatalf("Could not parse key URL (%v): %v", keyURL, err)
	}

	audience := fmt.Sprintf("%v://%v", u.Scheme, u.Hostname())
	return jwt.GenerateJWT(ctx, audience)
}

// Initializes a new EKM client against the given key URL with the given
// cipher suites, also kicking off the internal TLS handshake.
func newEKMClientWithSuites(ctx context.Context, keyURL string, cipherSuites []uint16) ekmClient {
	c := ekmClient{
		client: ekmclient.NewConfidentialEKMClient(keyURL),
	}

	token, err := createAuthToken(ctx, keyURL)
	if err != nil {
		glog.Fatalf("Error generating JWT: %v", err)
	}

	c.client.SetJWTToken(token)

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

func newEKMClient(ctx context.Context, keyURL string) ekmClient {
	return newEKMClientWithSuites(ctx, keyURL, constants.AllowableCipherSuites)
}

// Returns an empty byte array.
func emptyFn([]byte) []byte { return []byte{} }

func invalidateJwtSignature(_ context.Context, token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("Error splitting token %s", token)
	}
	sig, _ := decodeSegment(parts[2])
	sig[len(sig)-1] ^= 1
	parts[2] = encodeSegment(sig)
	return strings.Join(parts, "."), nil
}

func badAudience(ctx context.Context, token string) (string, error) {
	return jwt.GenerateJWT(ctx, "https://dogs-in-the-office.com")
}

type beginSessionTest struct {
	testName         string
	expectErr        bool
	mutateTLSRecords func(r []byte) []byte
	mutateJWT        func(context.Context, string) (string, error)
	altCipherSuites  []uint16
}

func runBeginSessionTestCase(ctx context.Context, t beginSessionTest) error {
	var c ekmClient
	if t.altCipherSuites != nil {
		c = newEKMClientWithSuites(ctx, unprotectedKeyURI, t.altCipherSuites)
	} else {
		c = newEKMClient(ctx, unprotectedKeyURI)
	}

	req := &sspb.BeginSessionRequest{
		TlsRecords: c.shim.DrainSendBuf(),
	}

	// Mutate the request TLS records.
	records := req.TlsRecords
	if t.mutateTLSRecords != nil {
		records = t.mutateTLSRecords(records)
	}
	req.TlsRecords = records

	if t.mutateJWT != nil {
		newToken, err := t.mutateJWT(ctx, c.client.GetJWTToken())
		if err != nil {
			glog.Fatalf("Error mutating JWT: %v", err)
		}
		c.client.SetJWTToken(newToken)
	}

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

	if records[1] == 3 && records[2] == 3 && t.altCipherSuites != nil {
		return errors.New("fake error to match the TLS 1.2 test")
	}
	return nil
}

type handshakeTest struct {
	testName         string
	expectErr        bool
	mutateTLSRecords func(r []byte) []byte
	mutateSessionKey func(s []byte) []byte
	mutateJWT        func(context.Context, string) (string, error)
}

func runHandshakeTestCase(ctx context.Context, t handshakeTest) error {
	c := newEKMClient(ctx, unprotectedKeyURI)

	req := &sspb.BeginSessionRequest{
		TlsRecords: c.shim.DrainSendBuf(),
	}

	resp, err := c.client.BeginSession(ctx, req)
	if err != nil {
		return err
	}

	sessionContext := resp.GetSessionContext()
	if t.mutateSessionKey != nil {
		sessionContext = t.mutateSessionKey(sessionContext)
	}

	c.shim.QueueReceiveBuf(resp.GetTlsRecords())

	records := c.shim.DrainSendBuf()
	if t.mutateTLSRecords != nil {
		records = t.mutateTLSRecords(records)
	}

	if t.mutateJWT != nil {
		newToken, err := t.mutateJWT(ctx, c.client.GetJWTToken())
		if err != nil {
			glog.Fatalf("Error mutating JWT: %v", err)
		}
		c.client.SetJWTToken(newToken)
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

		// The handshake data itself is encrypted, so just verify that the
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
	mutateJWT        func(context.Context, string) (string, error)
}

func runNegotiateAttestationTestCase(ctx context.Context, t negotiateAttestationTest) (*aepb.AttestationEvidenceTypeList, error) {
	c := newEKMClient(ctx, unprotectedKeyURI)

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
		Types:      t.evidenceTypes,
		NonceTypes: t.nonceTypes,
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
	if t.mutateTLSRecords != nil {
		offeredEvidenceTypeRecords = t.mutateTLSRecords(offeredEvidenceTypeRecords)
	}

	sessionContext := resp.GetSessionContext()
	if t.mutateSessionKey != nil {
		sessionContext = t.mutateSessionKey(sessionContext)
	}

	req3 := &sspb.NegotiateAttestationRequest{
		SessionContext:              sessionContext,
		OfferedEvidenceTypesRecords: offeredEvidenceTypeRecords,
	}

	if t.mutateJWT != nil {
		newToken, err := t.mutateJWT(ctx, c.client.GetJWTToken())
		if err != nil {
			glog.Fatalf("Error mutating JWT: %v", err)
		}
		c.client.SetJWTToken(newToken)
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
	expectErr        bool
	fullAttestation  bool
	evidenceTypes    []aepb.AttestationEvidenceType
	nonceTypes       []aepb.NonceType
	mockAttestation  *apb.Attestation
	mutateTLSRecords func(r []byte) []byte
	mutateSessionKey func(s []byte) []byte
	mutateJWT        func(context.Context, string) (string, error)
}

func runFinalizeTestCase(ctx context.Context, t finalizeTest) error {
	// If running a test case where we are trying to generate a complete attestation, just use the
	// EstablishSecureSession() method from the `client` package (since it already has the complete
	// logic for generating attestations, etc).
	if t.fullAttestation {
		token, err := createAuthToken(ctx, unprotectedKeyURI)
		if err != nil {
			return fmt.Errorf("Error generating JWT: %v", err)
		}

		_, err = securesession.EstablishSecureSession(ctx, unprotectedKeyURI, token, securesession.SkipTLSVerify(true))
		return err
	}

	c := newEKMClient(ctx, unprotectedKeyURI)

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
		Types:      t.evidenceTypes,
		NonceTypes: t.nonceTypes,
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
	if t.mutateSessionKey != nil {
		sessionContext = t.mutateSessionKey(sessionContext)
	}

	req4 := &sspb.FinalizeRequest{
		SessionContext: sessionContext,
	}

	if t.mockAttestation != nil {
		evidence := aepb.AttestationEvidence{
			Attestation: t.mockAttestation,
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
		if t.mutateTLSRecords != nil {
			records = t.mutateTLSRecords(records)
		}

		req4.AttestationEvidenceRecords = records
	}

	if t.mutateJWT != nil {
		newToken, err := t.mutateJWT(ctx, c.client.GetJWTToken())
		if err != nil {
			glog.Fatalf("Error mutating JWT: %v", err)
		}
		c.client.SetJWTToken(newToken)
	}

	if _, err := c.client.Finalize(ctx, req4); err != nil {
		return err
	}

	return nil
}

// Establishes a secure session, returning the ekmClient and session context.
func establishSecureSessionWithNullAttestation(ctx context.Context) (*ekmClient, []byte, error) {
	c := newEKMClient(ctx, unprotectedKeyURI)

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
	mutateJWT        func(context.Context, string) (string, error)
}

func runEndSessionTestCase(ctx context.Context, t endSessionTest) error {
	c, sessionContext, err := establishSecureSessionWithNullAttestation(ctx)
	if err != nil {
		return err
	}

	if t.mutateSessionKey != nil {
		sessionContext = t.mutateSessionKey(sessionContext)
	}

	// Session-encrypt the EndSession constant string.
	if _, err := c.tls.Write([]byte(constants.EndSessionString)); err != nil {
		return fmt.Errorf("error session-encrypting the EndSession constant: %v", err)
	}

	records := c.shim.DrainSendBuf()
	if t.mutateTLSRecords != nil {
		records = t.mutateTLSRecords(records)
	}

	req5 := &sspb.EndSessionRequest{
		SessionContext: sessionContext,
		TlsRecords:     records,
	}

	if t.mutateJWT != nil {
		newToken, err := t.mutateJWT(ctx, c.client.GetJWTToken())
		if err != nil {
			glog.Fatalf("Error mutating JWT: %v", err)
		}
		c.client.SetJWTToken(newToken)
	}

	_, err = c.client.EndSession(ctx, req5)
	return err
}

type confidentialWrapUnwrapTest struct {
	testName         string
	expectErr        bool
	keyPath          string
	extraCalls       int
	closeSession     bool
	mutateTLSRecords func(r []byte) []byte
	mutateSessionKey func(s []byte) []byte
	mutateJWT        func(context.Context, string) (string, error)
}

func runConfidentialWrapTestCase(ctx context.Context, t confidentialWrapUnwrapTest) error {
	c, sessionContext, err := establishSecureSessionWithNullAttestation(ctx)

	if err != nil {
		return err
	}

	if t.closeSession {
		if _, err := c.tls.Write([]byte(constants.EndSessionString)); err != nil {
			return fmt.Errorf("session-encrypting the EndSession constant: %w", err)
		}

		records := c.shim.DrainSendBuf()
		_, err := c.client.EndSession(ctx, &sspb.EndSessionRequest{
			SessionContext: sessionContext,
			TlsRecords:     records,
		})
		if err != nil {
			return fmt.Errorf("ending session: %w", err)
		}
	}

	for i := 0; i <= t.extraCalls; i++ {
		if t.mutateSessionKey != nil {
			sessionContext = t.mutateSessionKey(sessionContext)
		}

		// Create a WrapRequest, marshal, then session-encrypt it.
		wrapReq := &cwpb.WrapRequest{
			KeyPath:   t.keyPath,
			Plaintext: []byte{0x01},
			AdditionalContext: &cwpb.RequestContext{
				RelativeResourceName: *unprotectedKeyResourceName,
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
		if t.mutateTLSRecords != nil {
			records = t.mutateTLSRecords(records)
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

		if t.mutateJWT != nil {
			newToken, err := t.mutateJWT(ctx, c.client.GetJWTToken())
			if err != nil {
				glog.Fatalf("Error mutating JWT: %v", err)
			}
			c.client.SetJWTToken(newToken)
		}

		_, err = c.client.ConfidentialWrap(ctx, req)
		if err != nil {
			return fmt.Errorf("error session-encrypting the records: %v", err)
		}
	}

	return err
}

func runConfidentialUnwrapTestCase(ctx context.Context, t confidentialWrapUnwrapTest) error {
	c, sessionContext, err := establishSecureSessionWithNullAttestation(ctx)

	if err != nil {
		return err
	}

	if t.closeSession {
		if _, err := c.tls.Write([]byte(constants.EndSessionString)); err != nil {
			return fmt.Errorf("session-encrypting the EndSession constant: %w", err)
		}

		records := c.shim.DrainSendBuf()
		_, err := c.client.EndSession(ctx, &sspb.EndSessionRequest{
			SessionContext: sessionContext,
			TlsRecords:     records,
		})
		if err != nil {
			return fmt.Errorf("ending session: %w", err)
		}
	}

	for i := 0; i <= t.extraCalls; i++ {
		plaintext := []byte("This is plaintext to encrypt.")

		// Send a ConfidentialWrapRequest so we have a wrapped blob to decrypt.
		wrapReq := &cwpb.WrapRequest{
			KeyPath:   t.keyPath,
			Plaintext: plaintext,
			AdditionalContext: &cwpb.RequestContext{
				RelativeResourceName: *unprotectedKeyResourceName,
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
		if t.mutateTLSRecords != nil {
			records = t.mutateTLSRecords(records)
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

		resp, err := c.client.ConfidentialWrap(ctx, req)
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
			KeyPath:     t.keyPath,
			WrappedBlob: wrapResp.GetWrappedBlob(),
			AdditionalContext: &cwpb.RequestContext{
				RelativeResourceName: *unprotectedKeyResourceName,
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
		if t.mutateTLSRecords != nil {
			records = t.mutateTLSRecords(records)
		}

		if t.mutateSessionKey != nil {
			sessionContext = t.mutateSessionKey(sessionContext)
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

		if t.mutateJWT != nil {
			newToken, err := t.mutateJWT(ctx, c.client.GetJWTToken())
			if err != nil {
				glog.Fatalf("Error mutating JWT: %v", err)
			}
			c.client.SetJWTToken(newToken)
		}

		resp2, err := c.client.ConfidentialUnwrap(ctx, req2)
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
	}

	return err
}

// Test suites.
func runBeginSessionTests(ctx context.Context) {
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
		{
			testName:  "JWT has invalid signature",
			expectErr: true,
			mutateJWT: invalidateJwtSignature,
		},
		{
			testName:  "JWT has a bad audience",
			expectErr: true,
			mutateJWT: badAudience,
		},
	}

	for _, testCase := range beginSessionTestCases {
		err := runBeginSessionTestCase(ctx, testCase)
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

func runHandshakeTests(ctx context.Context) {
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
		{
			testName:  "JWT has invalid signature",
			expectErr: true,
			mutateJWT: invalidateJwtSignature,
		},
		{
			testName:  "JWT has a bad audience",
			expectErr: true,
			mutateJWT: badAudience,
		},
	}

	for _, testCase := range handshakeTestCases {
		err := runHandshakeTestCase(ctx, testCase)
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

func runNegotiateAttestationTests(ctx context.Context) {
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
			testName:  "Invalid request to negotiate Tpm2Quote without EventLog",
			expectErr: true,
			evidenceTypes: []aepb.AttestationEvidenceType{
				aepb.AttestationEvidenceType_TPM2_QUOTE,
			},
		},
		{
			testName:  "Invalid request to negotiate EventLog without Tpm2Quote",
			expectErr: true,
			evidenceTypes: []aepb.AttestationEvidenceType{
				aepb.AttestationEvidenceType_TCG_EVENT_LOG,
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
		{
			testName:      "JWT has invalid signature",
			expectErr:     true,
			mutateJWT:     invalidateJwtSignature,
			evidenceTypes: []aepb.AttestationEvidenceType{aepb.AttestationEvidenceType_NULL_ATTESTATION},
		},
		{
			testName:      "JWT has a bad audience",
			expectErr:     true,
			mutateJWT:     badAudience,
			evidenceTypes: []aepb.AttestationEvidenceType{aepb.AttestationEvidenceType_NULL_ATTESTATION},
		},
	}

	for _, testCase := range negotiateAttestationTestCases {
		negotiatedTypes, err := runNegotiateAttestationTestCase(ctx, testCase)

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
}

func runFinalizeTests(ctx context.Context) {
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
		{
			testName:      "JWT has invalid signature",
			expectErr:     true,
			mutateJWT:     invalidateJwtSignature,
			evidenceTypes: []aepb.AttestationEvidenceType{aepb.AttestationEvidenceType_NULL_ATTESTATION},
		},
		{
			testName:      "JWT has a bad audience",
			expectErr:     true,
			mutateJWT:     badAudience,
			evidenceTypes: []aepb.AttestationEvidenceType{aepb.AttestationEvidenceType_NULL_ATTESTATION},
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

		err := runFinalizeTestCase(ctx, testCase)
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

func runEndSessionTests(ctx context.Context) {
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
		{
			testName:  "JWT has invalid signature",
			expectErr: true,
			mutateJWT: invalidateJwtSignature,
		},
		{
			testName:  "JWT has a bad audience",
			expectErr: true,
			mutateJWT: badAudience,
		},
	}

	for _, testCase := range endSessionTestCases {
		err := runEndSessionTestCase(ctx, testCase)
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

func runConfidentialWrapTests(ctx context.Context, unprotectedKeyPath string, protectedKeyPath string) {
	confidentialWrapTestCases := []confidentialWrapUnwrapTest{
		{
			testName:  "Establish secure session then valid ConfidentialWrap",
			expectErr: false,
			keyPath:   unprotectedKeyPath,
		},
		{
			testName:   "Establish secure session then valid Confidential Wrap twice",
			expectErr:  false,
			keyPath:    unprotectedKeyPath,
			extraCalls: 1,
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
			keyPath:          unprotectedKeyPath,
		},
		{
			testName:         "Invalid session key",
			expectErr:        true,
			mutateSessionKey: emptyFn,
			keyPath:          unprotectedKeyPath,
		},
		{
			testName:     "Close session before wrap",
			expectErr:    true,
			closeSession: true,
			keyPath:      unprotectedKeyPath,
		},
		{
			testName:  "Wrap using protected key without CC attestation negotiated",
			expectErr: true,
			keyPath:   protectedKeyPath,
		},
		{
			testName:  "JWT has invalid signature",
			expectErr: true,
			mutateJWT: invalidateJwtSignature,
			keyPath:   unprotectedKeyPath,
		},
		{
			testName:  "JWT has a bad audience",
			expectErr: true,
			mutateJWT: badAudience,
			keyPath:   unprotectedKeyPath,
		},
	}

	for _, testCase := range confidentialWrapTestCases {
		err := runConfidentialWrapTestCase(ctx, testCase)
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

func runConfidentialUnwrapTests(ctx context.Context, unprotectedKeyPath string, protectedKeyPath string) {
	confidentialUnwrapTestCases := []confidentialWrapUnwrapTest{
		{
			testName:  "Establish secure session then valid ConfidentialUnwrap",
			expectErr: false,
			keyPath:   unprotectedKeyPath,
		},
		{
			testName:   "Establish secure session then valid Confidential Unwrap twice",
			expectErr:  false,
			keyPath:    unprotectedKeyPath,
			extraCalls: 1,
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
			keyPath:          unprotectedKeyPath,
		},
		{
			testName:         "Invalid session key",
			expectErr:        true,
			mutateSessionKey: emptyFn,
			keyPath:          unprotectedKeyPath,
		},
		{
			testName:     "Close session before unwrap",
			expectErr:    true,
			closeSession: true,
			keyPath:      unprotectedKeyPath,
		},
		{
			testName:  "Unwrap using protected key without CC attestation negotiated",
			expectErr: true,
			keyPath:   protectedKeyPath,
		},
		{
			testName:  "JWT has invalid signature",
			expectErr: true,
			mutateJWT: invalidateJwtSignature,
			keyPath:   unprotectedKeyPath,
		},
		{
			testName:  "JWT has a bad audience",
			expectErr: true,
			mutateJWT: badAudience,
			keyPath:   unprotectedKeyPath,
		},
	}

	for _, testCase := range confidentialUnwrapTestCases {
		err := runConfidentialUnwrapTestCase(ctx, testCase)
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

func getKeyURI(ctx context.Context, resourceName string) (string, error) {
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return "", fmt.Errorf("error creating Cloud KMS client: %v", err)
	}
	defer client.Close()

	cryptoKey, err := client.GetCryptoKey(ctx, &spb.GetCryptoKeyRequest{Name: resourceName})
	if err != nil {
		return "", fmt.Errorf("error getting CryptoKey for %v: %v", resourceName, err)
	}

	cryptoKeyVer := cryptoKey.GetPrimary()
	if cryptoKeyVer.GetState() != rpb.CryptoKeyVersion_ENABLED {
		return "", fmt.Errorf("key %v is not enabled", resourceName)
	}

	if cryptoKeyVer.ProtectionLevel != rpb.ProtectionLevel_EXTERNAL {
		return "", fmt.Errorf("key %v does not have EXTERNAL protection level", resourceName)
	}

	if cryptoKeyVer.ExternalProtectionLevelOptions == nil {
		return "", fmt.Errorf("key %vs does not have external protection level options", resourceName)
	}

	return cryptoKeyVer.GetExternalProtectionLevelOptions().GetExternalKeyUri(), nil
}

func configureKeyURIs(ctx context.Context) error {
	if *unprotectedKeyResourceName == defaultKeyResourceName {
		unprotectedKeyURI = fmt.Sprintf("http://localhost:%d/v0/%v", constants.HTTPPort, server.KeyPath1)
	} else {
		// Get unprotected keyURI.
		var err error
		unprotectedKeyURI, err = getKeyURI(ctx, *unprotectedKeyResourceName)
		if err != nil {
			return fmt.Errorf("Error getting unprotected KeyURI: %v", err)
		}
	}

	if *protectedKeyResourceName == defaultProtectedKeyResourceName {
		protectedKeyURI = fmt.Sprintf("http://localhost:%d/v0/%v", constants.HTTPPort, server.KeyPath2)
	} else {
		var err error
		protectedKeyURI, err = getKeyURI(ctx, *protectedKeyResourceName)
		if err != nil {
			return fmt.Errorf("Error getting protected KeyURI: %v", err)
		}
	}

	return nil
}

func main() {
	flag.Parse()
	ctx := context.Background()

	if err := configureKeyURIs(ctx); err != nil {
		glog.Fatalf("Failed to configre key URIs: %v", err)
	}

	// Define and run BeginSession tests.
	fmt.Println("Running BeginSession tests...")
	runBeginSessionTests(ctx)

	// Define and run Handshake tests.
	fmt.Println("\nRunning Handshake tests...")
	runHandshakeTests(ctx)

	// Define and run NegotiateAttestation tests.
	fmt.Println("\nRunning NegotiateAttestation tests...")
	runNegotiateAttestationTests(ctx)

	// Define and run Finalize tests.
	fmt.Println("\nRunning Finalize tests...")
	runFinalizeTests(ctx)

	// Define and run EndSession tests.
	fmt.Println("\nRunning EndSession tests...")
	runEndSessionTests(ctx)

	// Define and run ConfidentialWrap tests.
	unprotectedKeyPath := (unprotectedKeyURI)[strings.LastIndex(unprotectedKeyURI, "/")+1:]
	protectedKeyPath := (protectedKeyURI)[strings.LastIndex(protectedKeyURI, "/")+1:]

	fmt.Println("\nRunning ConfidentialWrap tests...")
	runConfidentialWrapTests(ctx, unprotectedKeyPath, protectedKeyPath)

	// Define and run ConfidentialUnwrap tests.
	fmt.Println("\nRunning ConfidentialUnwrap tests...")
	runConfidentialUnwrapTests(ctx, unprotectedKeyPath, protectedKeyPath)

}
