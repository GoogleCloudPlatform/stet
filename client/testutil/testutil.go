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

// Package testutil contains utilities for unit tests.
package testutil

import (
	"context"
	"errors"
	"hash/crc32"
	"os"
	"testing"

	"cloud.google.com/go/kms/apiv1"
	ekmpb "cloud.google.com/go/kms/apiv1/kmspb"
	kmsrpb "cloud.google.com/go/kms/apiv1/kmspb"
	kmsspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/GoogleCloudPlatform/stet/client/securesession"
	"github.com/googleapis/gax-go/v2"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	gcpKMSPrefix       = "gcp-kms://"
	cryptoKeyVerSuffix = "/cryptoKeyVersions/test"

	// ExternalEKMURI is the external URI corresponding to ExternalKEK.
	ExternalEKMURI = "https://my-kms.io/external-key"

	// ExternalVPCBackend represents the ekmConnection for an External_VPC KEK.
	ExternalVPCBackend = "projects/test/locations/test/ekmConnection/testConn"
	// ExternalVPCHostname represents the external URI hostname for an External_VPC KEK.
	ExternalVPCHostname = "testvpchost"
	// ExternalVPCKeyPath represents the keyPath for an External_VPC KEK.
	ExternalVPCKeyPath = "api/v1/cckm/ekm/endpoints/testpath"
)

func newKEK(nameSuffix string, protectionLevel kmsrpb.ProtectionLevel) *KEK {
	return &KEK{
		Name:            "projects/test/locations/test/keyRings/test/cryptoKeys" + nameSuffix,
		ProtectionLevel: protectionLevel,
	}
}

// KEK contains basic information about test KEKs.
type KEK struct {
	Name            string
	ProtectionLevel kmsrpb.ProtectionLevel
}

// URI returns the KEK's CloudKMS URI by appending the GCP KMS prefix to the key name.
func (k *KEK) URI() string {
	return gcpKMSPrefix + k.Name
}

var (
	// SoftwareKEK represents a test KEK with the Software protection level.
	SoftwareKEK = newKEK("testSoftware", kmsrpb.ProtectionLevel_SOFTWARE)
	// HSMKEK represents a test KEK with the HSM protection level.
	HSMKEK = newKEK("testHsm", kmsrpb.ProtectionLevel_HSM)
	// ExternalKEK represents a test KEK with the External protection level.
	ExternalKEK = newKEK("testExternal", kmsrpb.ProtectionLevel_EXTERNAL)
	// VPCKEK represents a test KEK with the External_VPC protection level.
	VPCKEK = newKEK("testExternalVPC", kmsrpb.ProtectionLevel_EXTERNAL_VPC)
)

var defaultKEKs map[kmsrpb.ProtectionLevel]*KEK = map[kmsrpb.ProtectionLevel]*KEK{
	kmsrpb.ProtectionLevel_HSM:          SoftwareKEK,
	kmsrpb.ProtectionLevel_SOFTWARE:     HSMKEK,
	kmsrpb.ProtectionLevel_EXTERNAL:     ExternalKEK,
	kmsrpb.ProtectionLevel_EXTERNAL_VPC: VPCKEK,
}

// CreateTempTokenFile creates a temp directory/file as a stand-in for the attestation token.
func CreateTempTokenFile(t *testing.T) string {
	// Create token file.
	tempDir := t.TempDir()
	tokenFile := tempDir + "/test_token"
	if err := os.WriteFile(tokenFile, []byte("test token"), 0755); err != nil {
		t.Fatalf("Error creating token file at %v: %v", tokenFile, err)
	}

	return tokenFile
}

// CRC32C returns the Castagnoli CRC32 checksum of the given data.
func CRC32C(data []byte) uint32 {
	t := crc32.MakeTable(crc32.Castagnoli)
	return crc32.Checksum(data, t)
}

// CreateEnabledCryptoKey creates a fake CryptoKey with the given protection level and name of the
// format "projects/*/locations/*/keyRings/*/cryptoKeys/*".
func CreateEnabledCryptoKey(protectionLevel kmsrpb.ProtectionLevel, name string) *kmsrpb.CryptoKey {
	// If a custom name was specified, use it. Otherwise, use the default test URI for that protection level.
	if len(name) == 0 {
		name = defaultKEKs[protectionLevel].Name
	}

	ck := &kmsrpb.CryptoKey{
		Name: name,
		Primary: &kmsrpb.CryptoKeyVersion{
			Name:            name + cryptoKeyVerSuffix,
			State:           kmsrpb.CryptoKeyVersion_ENABLED,
			ProtectionLevel: protectionLevel,
		},
	}

	// For external protection level, add ExternalProtectionLevelOptions and external URI.
	if protectionLevel == kmsrpb.ProtectionLevel_EXTERNAL {
		ck.Primary.ExternalProtectionLevelOptions = &kmsrpb.ExternalProtectionLevelOptions{
			ExternalKeyUri: ExternalEKMURI,
		}
	} else if protectionLevel == kmsrpb.ProtectionLevel_EXTERNAL_VPC {
		ck.CryptoKeyBackend = ExternalVPCBackend
		ck.Primary.ExternalProtectionLevelOptions = &kmsrpb.ExternalProtectionLevelOptions{
			EkmConnectionKeyPath: ExternalVPCKeyPath,
		}
	}

	return ck
}

// FakeKeyManagementClient is a fake version of Cloud KMS Key Management client.
type FakeKeyManagementClient struct {
	kms.KeyManagementClient

	GetCryptoKeyFunc func(context.Context, *kmsspb.GetCryptoKeyRequest, ...gax.CallOption) (*kmsrpb.CryptoKey, error)
	EncryptFunc      func(context.Context, *kmsspb.EncryptRequest, ...gax.CallOption) (*kmsspb.EncryptResponse, error)
	DecryptFunc      func(context.Context, *kmsspb.DecryptRequest, ...gax.CallOption) (*kmsspb.DecryptResponse, error)
}

func protectionLevelFromName(name string) kmsrpb.ProtectionLevel {
	for k, v := range defaultKEKs {
		if v.Name == name {
			return k
		}
	}
	return kmsrpb.ProtectionLevel_PROTECTION_LEVEL_UNSPECIFIED
}

func (f *FakeKeyManagementClient) GetCryptoKey(ctx context.Context, req *kmsspb.GetCryptoKeyRequest, opts ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
	if f.GetCryptoKeyFunc != nil {
		return f.GetCryptoKeyFunc(ctx, req, opts...)
	}

	return CreateEnabledCryptoKey(protectionLevelFromName(req.GetName()), req.GetName()), nil
}

// FakeKMSWrap returns a fake wrapped share.
func FakeKMSWrap(unwrapped []byte, name string) []byte {
	switch name {
	case HSMKEK.Name:
		return append(unwrapped, byte('H'))
	case SoftwareKEK.Name:
		return append(unwrapped, byte('S'))
	default:
		return append(unwrapped, byte('U'))
	}
}

// ValidEncryptResponse returns a fake successful response for CloudKMS Encrypt.
func ValidEncryptResponse(req *kmsspb.EncryptRequest) *kmsspb.EncryptResponse {
	wrappedShare := FakeKMSWrap(req.GetPlaintext(), req.GetName())

	return &kmsspb.EncryptResponse{
		Name:                    req.GetName(),
		Ciphertext:              wrappedShare,
		CiphertextCrc32C:        wrapperspb.Int64(int64(CRC32C(wrappedShare))),
		VerifiedPlaintextCrc32C: true,
	}
}

// Encrypt calls EncryptFunc if applicable. Otherwise returns a fake Encrypt response.
func (f *FakeKeyManagementClient) Encrypt(ctx context.Context, req *kmsspb.EncryptRequest, opts ...gax.CallOption) (*kmsspb.EncryptResponse, error) {
	if f.EncryptFunc != nil {
		return f.EncryptFunc(ctx, req, opts...)
	}

	return ValidEncryptResponse(req), nil
}

// FakeKMSUnwrap returns a fake unwrapped share.
func FakeKMSUnwrap(wrapped []byte, name string) []byte {
	var final byte
	switch name {
	case HSMKEK.Name:
		final = 'H'
	case SoftwareKEK.Name:
		final = 'S'
	default:
		final = 'U'
	}

	if wrapped[len(wrapped)-1] != final {
		return []byte("nonsenseee")
	}
	return wrapped[:len(wrapped)-1]
}

// ValidDecryptResponse returns a fake successful response for CloudKMS Decrypt.
func ValidDecryptResponse(req *kmsspb.DecryptRequest) *kmsspb.DecryptResponse {
	unwrappedShare := FakeKMSUnwrap(req.GetCiphertext(), req.GetName())

	return &kmsspb.DecryptResponse{
		Plaintext:       unwrappedShare,
		PlaintextCrc32C: wrapperspb.Int64(int64(CRC32C(unwrappedShare))),
	}
}

// Decrypt calls DecryptFunc if applicable. Otherwise returns a fake Decrypt response.
func (f *FakeKeyManagementClient) Decrypt(ctx context.Context, req *kmsspb.DecryptRequest, opts ...gax.CallOption) (*kmsspb.DecryptResponse, error) {
	if f.DecryptFunc != nil {
		return f.DecryptFunc(ctx, req, opts...)
	}

	return ValidDecryptResponse(req), nil
}

// Close is a no-op. Needed to implement the KMS Client interface.
func (f *FakeKeyManagementClient) Close() error {
	return nil
}

// FakeSecureSessionClient is a test version of a secure session client, used to communicate with
// external EKM.
type FakeSecureSessionClient struct {
	securesession.SecureSessionClient

	WrapErr       error
	UnwrapErr     error
	EndSessionErr error
}

// ConfidentialWrap simulates wrapping a share by appending a single byte ('E') to the end of the
// plaintext to indicate external protection level.
func (f *FakeSecureSessionClient) ConfidentialWrap(_ context.Context, _, _ string, plaintext []byte) ([]byte, error) {
	// Return configured error if one was set
	if f.WrapErr != nil {
		return nil, f.WrapErr
	}

	return append(plaintext, byte('E')), nil
}

// ConfidentialUnwrap removes the last byte of the wrapped share (mirroring ConfidentalWrap above).
func (f *FakeSecureSessionClient) ConfidentialUnwrap(_ context.Context, _, _ string, wrappedBlob []byte) ([]byte, error) {
	// Return configured error if one was set
	if f.UnwrapErr != nil {
		return nil, f.UnwrapErr
	}

	return wrappedBlob[:len(wrappedBlob)-1], nil
}

// EndSession is necessary to implement the SecureSessionClient interface.
func (f *FakeSecureSessionClient) EndSession(ctx context.Context) error {
	// Return configured error if one was set
	if f.EndSessionErr != nil {
		return f.EndSessionErr
	}

	return nil
}

// FakeCloudEKMClient is a fake implementation of the GCP EKM client.
type FakeCloudEKMClient struct {
	kms.EkmClient

	GetEkmConnectionFunc func(context.Context, *ekmpb.GetEkmConnectionRequest, ...gax.CallOption) (*ekmpb.EkmConnection, error)
}

// GetEkmConnection calls GetEkmConnectionFunc if applicable. Otherwise returns error.
func (f *FakeCloudEKMClient) GetEkmConnection(ctx context.Context, req *ekmpb.GetEkmConnectionRequest, opts ...gax.CallOption) (*ekmpb.EkmConnection, error) {
	if f.GetEkmConnectionFunc != nil {
		return f.GetEkmConnectionFunc(ctx, req, opts...)
	}

	return nil, errors.New("unimplemented fake")
}

// Close is a no-op. Needed to implement the EKM Client interface.
func (f *FakeCloudEKMClient) Close() error { return nil }
