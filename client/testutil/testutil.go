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
	"hash/crc32"

	"cloud.google.com/go/kms/apiv1"
	"github.com/googleapis/gax-go/v2"
	kmsrpb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	kmsspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	gcpKMSPrefix = "gcp-kms://"

	// TestKEKName is a test key name for a KEK.
	TestKEKName = "projects/test/locations/test/keyRings/test/cryptoKeys/test"
	// TestKEKURI is a test KEK URI corresponding to TestKEKName.
	TestKEKURI = gcpKMSPrefix + TestKEKName

	// TestExternalCloudKEKName is a test Cloud KMS key name for an external KEK.
	TestExternalCloudKEKName = "projects/test/locations/test/keyRings/test/cryptoKeys/testExternal"
	// TestExternalCloudKEKURI is a test KEK URI corresponding to TestExternalCloudKEKName.
	TestExternalCloudKEKURI = gcpKMSPrefix + TestExternalCloudKEKName
	// TestExternalKEKURI is the external URI for an EKM-managed KEK.
	TestExternalKEKURI = "https://my-kms.io/external-key"

	// TestHSMKEKName is a test key name for an HSM-protected KEK.
	TestHSMKEKName = "projects/test/locations/test/keyRings/test/cryptoKeys/testHsm"
	// TestHSMKEKURI is a test KEK URI corresponding to TestHSMKEKName.
	TestHSMKEKURI = gcpKMSPrefix + TestHSMKEKName

	// TestSoftwareKEKName is a test key name for a software-protected KEK.
	TestSoftwareKEKName = "projects/test/locations/test/keyRings/test/cryptoKeys/testSoftware"
	// TestSoftwareKEKURI is a test KEK URI corresponding to TestSoftwareKEKName.
	TestSoftwareKEKURI = gcpKMSPrefix + TestSoftwareKEKName
)

func crc32c(data []byte) uint32 {
	t := crc32.MakeTable(crc32.Castagnoli)
	return crc32.Checksum(data, t)
}

// CreateEnabledCryptoKey creates a fake CryptoKey with the given protection level.
func CreateEnabledCryptoKey(protectionLevel kmsrpb.ProtectionLevel) *kmsrpb.CryptoKey {
	ck := &kmsrpb.CryptoKey{
		Primary: &kmsrpb.CryptoKeyVersion{
			Name:            TestKEKName,
			State:           kmsrpb.CryptoKeyVersion_ENABLED,
			ProtectionLevel: protectionLevel,
		},
	}

	if protectionLevel == kmsrpb.ProtectionLevel_EXTERNAL {
		ck.Primary.ExternalProtectionLevelOptions = &kmsrpb.ExternalProtectionLevelOptions{
			ExternalKeyUri: TestExternalKEKURI,
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

func fakeKMSProtectionLevel(name string) kmsrpb.ProtectionLevel {
	switch name {
	case TestHSMKEKName:
		return kmsrpb.ProtectionLevel_HSM
	case TestSoftwareKEKName:
		return kmsrpb.ProtectionLevel_SOFTWARE
	case TestExternalCloudKEKName:
		return kmsrpb.ProtectionLevel_EXTERNAL
	default:
		return kmsrpb.ProtectionLevel_PROTECTION_LEVEL_UNSPECIFIED
	}
}

func (f *FakeKeyManagementClient) GetCryptoKey(ctx context.Context, req *kmsspb.GetCryptoKeyRequest, opts ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
	if f.GetCryptoKeyFunc != nil {
		return f.GetCryptoKeyFunc(ctx, req, opts...)
	}

	return CreateEnabledCryptoKey(fakeKMSProtectionLevel(req.GetName())), nil
}

// FakeKMSWrap returns a fake wrapped share.
func FakeKMSWrap(unwrapped []byte, name string) []byte {
	switch name {
	case TestHSMKEKName:
		return append(unwrapped, byte('H'))
	case TestSoftwareKEKName:
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
		CiphertextCrc32C:        wrapperspb.Int64(int64(crc32c(wrappedShare))),
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
	case TestHSMKEKName:
		final = 'H'
	case TestSoftwareKEKName:
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
		PlaintextCrc32C: wrapperspb.Int64(int64(crc32c(unwrappedShare))),
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
