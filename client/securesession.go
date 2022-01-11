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

// Defines a client for making RPC calls to the SecureSession service.

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"syscall"

	"cloud.google.com/go/compute/metadata"
	tpmclient "github.com/google/go-tpm-tools/client"
	atpb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm/tpm2"

	"github.com/GoogleCloudPlatform/stet/constants"
	aepb "github.com/GoogleCloudPlatform/stet/proto/attestation_evidence_go_proto"
	cwpb "github.com/GoogleCloudPlatform/stet/proto/confidential_wrap_go_proto"
	pb "github.com/GoogleCloudPlatform/stet/proto/secure_session_go_proto"
	"github.com/GoogleCloudPlatform/stet/transportshim"
	glog "github.com/golang/glog"
	"google.golang.org/protobuf/proto"
)

// clientState is the state of the secure session establishment of the client.
type clientState int

// Constants representing different clientStates.
const (
	clientStateUninitialized clientState = iota
	clientStateInitiated
	clientStateHandshakeCompleted
	clientStateAttestationNegotiated
	clientStateAttestationAccepted
	clientStateEnded
	clientStateFailed
	clientStateUnknown
)

// recordBufferSize is the number of bytes allocated to buffers when reading
// records from the TLS session. 16KB is the maximum TLS record size, so this
// value guarantees incoming records will fit in the buffer.
const recordBufferSize = 16384

// ekmToken is a struct that implements credentials.PerRPCCredentials to
// store a bearer token for authenticating requests to the EKM.
type ekmToken struct {
	token string
}

func (t ekmToken) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{
		"Authorization": fmt.Sprintf("Bearer %s", t.token),
	}, nil
}

func (ekmToken) RequireTransportSecurity() bool {
	return false
}

// SecureSessionClient is a SecureSession service client.
type SecureSessionClient struct {
	client           ConfidentialEKMClient
	shim             transportshim.ShimInterface
	tls              *tls.Conn
	state            clientState
	ctx              []byte // the opaque session context
	attestationTypes *aepb.AttestationEvidenceTypeList
}

// tryReescalatePrivileges checks if the process is owned by root but
// invoked as user, and the real UID is currently 0 (with non-zero
// effective UID). If so, it attempts to swap the two, thus escalating
// back to root privileges, returning an error if any syscalls fail.
func tryReescalatePrivileges() error {
	ruid := syscall.Getuid()
	euid := syscall.Geteuid()
	if ruid == 0 && euid != 0 {
		return syscall.Setreuid(euid, ruid)
	}
	return nil
}

// tryDescalatePrivileges checks if the process is owned by root but
// invoked as user, and the effective UID is 0 (with non-zero real UID).
// If so, it attempts to swap the two, thus de-escalating down to user
// privileges, returning an error if any syscalls fail.
func tryDeescalatePrivileges() error {
	ruid := syscall.Getuid()
	euid := syscall.Geteuid()
	if ruid != 0 && euid == 0 {
		return syscall.Setreuid(euid, ruid)
	}
	return nil
}

type secureSessionOptions struct {
	httpCertPool  *x509.CertPool
	skipTLSVerify bool
}

// SecureSessionOption configures EstablishSecureSession.
type SecureSessionOption func(*secureSessionOptions)

// HTTPCertPool sets an explicitly-configured x509.CertPool for the HTTPS
// connection. Passing this option again will overwrite earlier values.
func HTTPCertPool(pool *x509.CertPool) SecureSessionOption {
	return func(opts *secureSessionOptions) {
		opts.httpCertPool = pool
	}
}

// SkipTLSVerify specifies whether the inner TLS session's certificate should
// be validated. Passing this option again will overwrite earlier values.
func SkipTLSVerify(skipTLSVerify bool) SecureSessionOption {
	return func(opts *secureSessionOptions) {
		opts.skipTLSVerify = skipTLSVerify
	}
}

// DefaultSecureSessionOptions control the default values before
// applying options passed to EstablishSecureSession.
var DefaultSecureSessionOptions = []SecureSessionOption{
	HTTPCertPool(nil),
	SkipTLSVerify(false),
}

// EstablishSecureSession takes in a service address and performs the
// handshaking flow, returning a Client object with the fully-established
// secure session, or an error if one of the steps in the handshake failed.
func EstablishSecureSession(ctx context.Context, addr, authToken string, opts ...SecureSessionOption) (*SecureSessionClient, error) {
	// Process variadic options.
	var options secureSessionOptions
	for _, opt := range DefaultSecureSessionOptions {
		opt(&options)
	}

	for _, opt := range opts {
		opt(&options)
	}

	client, err := newSecureSessionClient(addr, authToken, options.httpCertPool, options.skipTLSVerify)

	if err != nil {
		return nil, fmt.Errorf("error creating a secure session client: %v", err)
	}

	// Begin secure session establishment with a BeginSession call.
	if err := client.beginSession(ctx); err != nil {
		return nil, fmt.Errorf("error beginning session establishment: %v", err)
	}

	// Continue making Handshake requests until the TLS handshake is complete.
	for client.state != clientStateHandshakeCompleted {
		if err := client.handshake(ctx); err != nil {
			return nil, fmt.Errorf("error on handshake: %v", err)
		}
	}

	// Ask server for what attestation evidence is acceptable.
	if err := client.negotiateAttestation(ctx); err != nil {
		return nil, fmt.Errorf("error negotiating attestation: %v", err)
	}

	// Present negotiated attestation evidence to finalize the secure session.
	if err := client.finalize(ctx); err != nil {
		return nil, fmt.Errorf("error finalizing attestation: %v", err)
	}

	return client, nil
}

// newClient returns a new SecureSessionClient object that connects to a
// secure session service at the given address.
func newSecureSessionClient(addr, authToken string, httpCertPool *x509.CertPool, skipTLSVerify bool) (*SecureSessionClient, error) {
	c := &SecureSessionClient{}

	c.client = ConfidentialEKMClient{uri: addr, authToken: authToken, certPool: httpCertPool}
	c.shim = transportshim.NewTransportShim()

	cfg := &tls.Config{
		CipherSuites: constants.AllowableCipherSuites,
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}

	// If in testing mode, skip verification. Otherwise, set ServerName based on key URI.
	if skipTLSVerify {
		cfg.InsecureSkipVerify = true
		glog.Warningln("Skipping inner TLS verification.")
	} else {
		u, err := url.Parse(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse address for secure session client: %v", err)
		}
		cfg.ServerName = u.Hostname()
	}

	c.tls = tls.Client(c.shim, cfg)

	// Kick off inner TLS session handshake and wait for a write.
	go func() {
		if err := c.tls.Handshake(); err != nil {
			glog.Errorf("Inner TLS handshake failed: %v", err.Error())
			return
		}
		glog.Infof("Inner TLS handshake succeeded")
	}()

	// Set state.
	c.state = clientStateUninitialized

	return c, nil
}

// beginSession starts the secure session establishment with the server.
func (c *SecureSessionClient) beginSession(ctx context.Context) error {
	req := &pb.BeginSessionRequest{
		// The buffer here is populated by the handshake in the newSecureSessionClient goroutine.
		TlsRecords: c.shim.DrainSendBuf(),
	}

	resp, err := c.client.BeginSession(ctx, req)
	if err != nil {
		return fmt.Errorf("error initializing TLS secure session: %v", err)
	}

	if resp.GetSessionContext() == nil {
		return errors.New("Failed to initialize session; likely authentication error")
	}

	// Update the state of the session.
	c.state = clientStateInitiated
	c.ctx = resp.GetSessionContext()

	// Write received TLS records back to the transport shim.
	c.shim.QueueReceiveBuf(resp.GetTlsRecords())

	return nil
}

// handshake continues the secure session establishment with the server.
func (c *SecureSessionClient) handshake(ctx context.Context) error {
	req := &pb.HandshakeRequest{
		SessionContext: c.ctx,
		// The buffer here is populated by the handshake in the newSecureSessionClient goroutine.
		TlsRecords: c.shim.DrainSendBuf(),
	}

	resp, err := c.client.Handshake(ctx, req)
	if err != nil {
		return fmt.Errorf("error continuing session establishment: %v", err)
	}

	// Write received TLS records back to the transport shim.
	c.shim.QueueReceiveBuf(resp.GetTlsRecords())

	// Update state of client if TLS indicates handshake is complete.
	if c.tls.ConnectionState().HandshakeComplete {
		c.state = clientStateHandshakeCompleted
	}

	return nil
}

// negotiateAttestation confirms attestation evidence options with the server.
func (c *SecureSessionClient) negotiateAttestation(ctx context.Context) error {
	req := &pb.NegotiateAttestationRequest{
		SessionContext: c.ctx,
	}

	// The client should always support null attestations.
	evidenceTypes := &aepb.AttestationEvidenceTypeList{
		Types: []aepb.AttestationEvidenceType{aepb.AttestationEvidenceType_NULL_ATTESTATION},
	}

	// Attempt to re-escalate execution privileges.
	if err := tryReescalatePrivileges(); err != nil {
		return fmt.Errorf("failed to re-escalate to root privileges to open TPM device: %w", err)
	}

	if _, err := tpm2.OpenTPM("/dev/tpmrm0"); err != nil {
		glog.Infof("TPM not available. Using null attestation")
	} else {
		evidenceTypes.Types = append(evidenceTypes.Types, aepb.AttestationEvidenceType_TPM2_QUOTE)
		evidenceTypes.Types = append(evidenceTypes.Types, aepb.AttestationEvidenceType_TCG_EVENT_LOG)

		// Communicate to the server the nonce types that we support.
		evidenceTypes.NonceTypes = append(evidenceTypes.NonceTypes, aepb.NonceType_NONCE_EKM32)
	}

	if err := tryDeescalatePrivileges(); err != nil {
		return fmt.Errorf("failed to de-escalate to user privileges: %w", err)
	}

	// Write marshalled attestation evidence to TLS channel.
	marshaledEvidenceTypes, err := proto.Marshal(evidenceTypes)
	if err != nil {
		return fmt.Errorf("error marshalling evidence to proto: %v", err)
	}

	if _, err := c.tls.Write(marshaledEvidenceTypes); err != nil {
		return fmt.Errorf("error writing evidence to TLS connection: %v", err)
	}

	// Capture the TLS session-protected records and send them over the RPC.
	req.OfferedEvidenceTypesRecords = c.shim.DrainSendBuf()

	resp, err := c.client.NegotiateAttestation(ctx, req)
	if err != nil {
		return fmt.Errorf("error negotiating attestation with client: %v", err)
	}

	// Decode the records that the server responded with to figure out what
	// attestation evidence is appropriate for the finalize step. This involves
	// writing the session-encrypted records back to the TLS client.
	evidenceRecords := resp.GetRequiredEvidenceTypesRecords()
	c.shim.QueueReceiveBuf(evidenceRecords)

	readBuf := make([]byte, recordBufferSize)
	n, err := c.tls.Read(readBuf)

	if err != nil {
		return fmt.Errorf("error reading data from TLS connection: %v", err)
	}

	// Unmarshal the response written back from the TLS intercept.
	c.attestationTypes = &aepb.AttestationEvidenceTypeList{}
	if err = proto.Unmarshal(readBuf[:n], c.attestationTypes); err != nil {
		return fmt.Errorf("error parsing attestation types into a proto: %v", err)
	}

	c.state = clientStateAttestationNegotiated
	return nil
}

// finalize ends the secure session establishment with the server.
func (c *SecureSessionClient) finalize(ctx context.Context) error {
	req := &pb.FinalizeRequest{
		SessionContext: c.ctx,
	}

	evidence := aepb.AttestationEvidence{
		Attestation: &atpb.Attestation{},
	}

	// Attempt to re-escalate execution privileges.
	if err := tryReescalatePrivileges(); err != nil {
		return fmt.Errorf("failed to re-escalate to root privileges to generate attestation: %w", err)
	}

	// If the TPM device is present, generate an attestation.
	if rwc, err := tpm2.OpenTPM("/dev/tpmrm0"); err == nil {
		if ek, err := tpmclient.GceAttestationKeyRSA(rwc); err != nil {
			glog.Errorf("Error generating and loading the GCE RSA AK: %v", err)
			glog.Infof("Skipping attestation generation")
		} else {
			defer ek.Close()

			// Resolve the most recent supported nonce type from the server's repsonse.
			preferredNonceTypes := []aepb.NonceType{
				aepb.NonceType_NONCE_EKM32,
			}

			// Fallback to NONCE_EKM32 if the server responds with a 0-length list of
			// nonce types (this implies server has not implemented negotiation).
			negotiatedNonceType := aepb.NonceType_NONCE_EKM32

		nonceLoop:
			for _, nonceType := range preferredNonceTypes {
				for _, serverNonceType := range c.attestationTypes.GetNonceTypes() {
					if nonceType == serverNonceType {
						negotiatedNonceType = nonceType
						break nonceLoop
					}
				}
			}

			var nonce []byte

			switch negotiatedNonceType {
			case aepb.NonceType_NONCE_EKM32:
				// Generate exported keying material and attestation.
				tlsState := c.tls.ConnectionState()
				material, err := tlsState.ExportKeyingMaterial(constants.ExportLabel, nil, 32)
				if err != nil {
					return fmt.Errorf("error exporting key material: %v", err)
				}

				nonce = append(nonce, []byte(constants.AttestationPrefix)...)
				nonce = append(nonce, material...)
			default:
				return fmt.Errorf("negotiated unknown nonce type: %v", negotiatedNonceType)
			}

			att, err := ek.Attest(tpmclient.AttestOpts{Nonce: nonce})

			if err != nil {
				return fmt.Errorf("error generating attestation: %v", err)
			}

			glog.Infof("Obtained attestation from the vTPM")

			if err := tryDeescalatePrivileges(); err != nil {
				return fmt.Errorf("failed to de-escalate to user privileges: %w", err)
			}

			// Add GCE instance info to the attestation proto.
			projectID, err := metadata.ProjectID()
			// If unable to retrieve the Project ID, set to empty string.
			if err != nil {
				projectID = ""
			}

			zone, err := metadata.Zone()
			// If unable to retrieve the Zone, set to empty string.
			if err != nil {
				zone = ""
			}

			instanceName, err := metadata.InstanceName()
			// If unable to retrieve the Instance Name, set to empty string.
			if err != nil {
				instanceName = ""
			}

			att.InstanceInfo = &atpb.GCEInstanceInfo{
				Zone:         zone,
				ProjectId:    projectID,
				InstanceName: instanceName,
			}

			evidence = aepb.AttestationEvidence{
				Attestation: att,
			}

			// Session-encrypt the attestation evidence proto.
			marshaledEvidence, err := proto.Marshal(&evidence)
			if err != nil {
				return fmt.Errorf("error marshalling evidence to a proto: %v", err)
			}

			// Pass the buffer through TLS.
			if _, err := c.tls.Write(marshaledEvidence); err != nil {
				return fmt.Errorf("error writing records to TLS: %v", err)
			}

			// Wait for TLS session to process, then add session-protected records to request.
			req.AttestationEvidenceRecords = c.shim.DrainSendBuf()
		}
	} else {
		glog.Errorf("Error opening TPM device: %v", err)
		glog.Infof("Skipping attestation generation")
	}

	if _, err := c.client.Finalize(ctx, req); err != nil {
		return fmt.Errorf("error finalizing secure session with client: %v", err)
	}

	c.state = clientStateAttestationAccepted
	return nil
}

// EndSession explicitly closes the previous established secure session.
func (c *SecureSessionClient) EndSession(ctx context.Context) error {
	if c.state != clientStateAttestationAccepted {
		return errors.New("Called EndSession with unestablished secure session")
	}

	// Session-encrypt the EndSession constant string.
	if _, err := c.tls.Write([]byte(constants.EndSessionString)); err != nil {
		return fmt.Errorf("error session-encrypting the EndSession constant: %v", err)
	}

	// Send the session-encrypted string over the network to end the session.
	req := &pb.EndSessionRequest{
		SessionContext: c.ctx,
		TlsRecords:     c.shim.DrainSendBuf(),
	}

	if _, err := c.client.EndSession(ctx, req); err != nil {
		return fmt.Errorf("error ending session: %v", err)
	}

	c.state = clientStateEnded
	return nil
}

// ConfidentialWrap uses the established secure session to wrap the given plaintext
// using the specified key path and resource name, returning the wrapped blob.
func (c *SecureSessionClient) ConfidentialWrap(ctx context.Context, keyPath, resourceName string, plaintext []byte) ([]byte, error) {
	if c.state != clientStateAttestationAccepted {
		return nil, errors.New("Called ConfidentialWrap with unestablished secure sesssion")
	}

	// Create a WrapRequest, marshal, then session-encrypt it.
	wrapReq := &cwpb.WrapRequest{
		KeyPath:   keyPath,
		Plaintext: plaintext,
		AdditionalContext: &cwpb.RequestContext{
			RelativeResourceName: resourceName,
			AccessReasonContext:  &cwpb.AccessReasonContext{Reason: cwpb.AccessReasonContext_CUSTOMER_INITIATED_ACCESS},
		},
		AdditionalAuthenticatedData: nil,
		KeyUriPrefix:                "",
	}

	marshaledWrapReq, err := proto.Marshal(wrapReq)
	if err != nil {
		return nil, fmt.Errorf("error marshalling the WrapRequest to proto: %v", err)
	}

	if _, err := c.tls.Write(marshaledWrapReq); err != nil {
		return nil, fmt.Errorf("error writing the WrapRequest to the TLS session: %v", err)
	}

	req := &cwpb.ConfidentialWrapRequest{
		SessionContext: c.ctx,
		TlsRecords:     c.shim.DrainSendBuf(),
		RequestMetadata: &cwpb.RequestMetadata{
			KeyPath:           wrapReq.GetKeyPath(),
			KeyUriPrefix:      wrapReq.GetKeyUriPrefix(),
			AdditionalContext: wrapReq.GetAdditionalContext(),
		},
	}

	// Make RPC, session-encrypt the records, and unmarshal the inner WrapResponse.
	resp, err := c.client.ConfidentialWrap(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("error session-encrypting the records: %v", err)
	}

	records := resp.GetTlsRecords()
	c.shim.QueueReceiveBuf(records)

	readBuf := make([]byte, recordBufferSize)
	n, err := c.tls.Read(readBuf)

	if err != nil {
		return nil, fmt.Errorf("error reading WrapResponse from TLS session: %v", err)
	}

	var wrapResp cwpb.WrapResponse
	if err = proto.Unmarshal(readBuf[:n], &wrapResp); err != nil {
		return nil, fmt.Errorf("error parsing WrapResponse to proto: %v", err)
	}

	return wrapResp.GetWrappedBlob(), nil
}

// ConfidentialUnwrap uses the established secure session to unwrap the given
// blob via the given key path and resource name, returning the plaintext.
func (c *SecureSessionClient) ConfidentialUnwrap(ctx context.Context, keyPath, resourceName string, wrappedBlob []byte) ([]byte, error) {
	if c.state != clientStateAttestationAccepted {
		return nil, errors.New("Called ConfidentialUnwrap with unestablished secure sesssion")
	}

	// Create an UnwrapRequest, marshal, then session-encrypt it.
	unwrapReq := &cwpb.UnwrapRequest{
		KeyPath:     keyPath,
		WrappedBlob: wrappedBlob,
		AdditionalContext: &cwpb.RequestContext{
			RelativeResourceName: resourceName,
			AccessReasonContext:  &cwpb.AccessReasonContext{Reason: cwpb.AccessReasonContext_CUSTOMER_INITIATED_ACCESS},
		},
		AdditionalAuthenticatedData: nil,
		KeyUriPrefix:                "",
	}

	marshaledUnwrapReq, err := proto.Marshal(unwrapReq)
	if err != nil {
		return nil, fmt.Errorf("error marshalling UnwrapRequest: %v", err)
	}

	if _, err := c.tls.Write(marshaledUnwrapReq); err != nil {
		return nil, fmt.Errorf("error writing UnwrapRequest to TLS session: %v", err)
	}

	req := &cwpb.ConfidentialUnwrapRequest{
		SessionContext: c.ctx,
		TlsRecords:     c.shim.DrainSendBuf(),
		RequestMetadata: &cwpb.RequestMetadata{
			KeyPath:           unwrapReq.GetKeyPath(),
			KeyUriPrefix:      unwrapReq.GetKeyUriPrefix(),
			AdditionalContext: unwrapReq.GetAdditionalContext(),
		},
	}

	// Make RPC, session-decrypt the records, and unmarshal the inner WrapResponse.
	resp, err := c.client.ConfidentialUnwrap(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("error session-decrypting the records: %v", err)
	}

	records := resp.GetTlsRecords()
	c.shim.QueueReceiveBuf(records)

	readBuf := make([]byte, recordBufferSize)
	n, err := c.tls.Read(readBuf)

	if err != nil {
		return nil, fmt.Errorf("error reading UnwrapResponse from TLS session: %v", err)
	}

	var unwrapResp cwpb.UnwrapResponse
	if err = proto.Unmarshal(readBuf[:n], &unwrapResp); err != nil {
		return nil, fmt.Errorf("error parsing UnwrapResponse: %v", err)
	}

	return unwrapResp.GetPlaintext(), nil
}
