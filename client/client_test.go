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

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"cloud.google.com/go/kms/apiv1"
	"github.com/google/tink/go/subtle/random"
	"github.com/googleapis/gax-go"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"

	configpb "github.com/GoogleCloudPlatform/stet/proto/config_go_proto"
	kmsrpb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	kmsspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
)

const (
	testKEKURI          = "gcp-kms://projects/test/locations/test/keyRings/test/cryptoKeys/test"
	testKEKName         = "projects/test/locations/test/keyRings/test/cryptoKeys/test"
	testKEKURIExternal  = "gcp-kms://projects/test/locations/test/keyRings/test/cryptoKeys/testExternal"
	testExternalKEKName = "projects/test/locations/test/keyRings/test/cryptoKeys/testExternal"
	testKEKURIHSM       = "gcp-kms://projects/test/locations/test/keyRings/test/cryptoKeys/testHsm"
	testHSMKEKName      = "projects/test/locations/test/keyRings/test/cryptoKeys/testHsm"
	testKEKURISoftware  = "gcp-kms://projects/test/locations/test/keyRings/test/cryptoKeys/testSoftware"
	testSoftwareKEKName = "projects/test/locations/test/keyRings/test/cryptoKeys/testSoftware"
)

func createEnabledCryptoKey(protectionLevel kmsrpb.ProtectionLevel) *kmsrpb.CryptoKey {
	ck := &kmsrpb.CryptoKey{
		Primary: &kmsrpb.CryptoKeyVersion{
			Name:            testKEKName,
			State:           kmsrpb.CryptoKeyVersion_ENABLED,
			ProtectionLevel: protectionLevel,
		},
	}

	if protectionLevel == kmsrpb.ProtectionLevel_EXTERNAL {
		ck.Primary.ExternalProtectionLevelOptions = &kmsrpb.ExternalProtectionLevelOptions{
			ExternalKeyUri: testKEKURIExternal,
		}
	}

	return ck
}

// Fake version of secure session client, used to communicate with external EKM.
type fakeSecureSessionClient struct {
	SecureSessionClient

	wrapErr       error
	unwrapErr     error
	endSessionErr error
}

// Appends a single byte ('E') to the end of the plaintext to indicate the external protection level.
func (f *fakeSecureSessionClient) ConfidentialWrap(_ context.Context, _, _ string, plaintext []byte) ([]byte, error) {
	// Return configured error if one was set
	if f.wrapErr != nil {
		return nil, f.wrapErr
	}

	return append(plaintext, byte('E')), nil
}

// Removes the last byte of the wrapped share (mirroring the fake ConfidentalWrap above).
func (f *fakeSecureSessionClient) ConfidentialUnwrap(_ context.Context, _, _ string, wrappedBlob []byte) ([]byte, error) {
	// Return configured error if one was set
	if f.unwrapErr != nil {
		return nil, f.unwrapErr
	}

	return wrappedBlob[:len(wrappedBlob)-1], nil
}

func (f *fakeSecureSessionClient) EndSession(ctx context.Context) error {
	// Return configured error if one was set
	if f.endSessionErr != nil {
		return f.endSessionErr
	}

	return nil
}

// Fake version of Cloud KMS Key Management client.
type fakeKeyManagementClient struct {
	kms.KeyManagementClient

	getCryptoKeyFunc func(context.Context, *kmsspb.GetCryptoKeyRequest, ...gax.CallOption) (*kmsrpb.CryptoKey, error)
	encryptFunc      func(context.Context, *kmsspb.EncryptRequest, ...gax.CallOption) (*kmsspb.EncryptResponse, error)
	decryptFunc      func(context.Context, *kmsspb.DecryptRequest, ...gax.CallOption) (*kmsspb.DecryptResponse, error)
}

func fakeKMSProtectionLevel(name string) kmsrpb.ProtectionLevel {
	switch name {
	case testHSMKEKName:
		return kmsrpb.ProtectionLevel_HSM
	case testSoftwareKEKName:
		return kmsrpb.ProtectionLevel_SOFTWARE
	case testExternalKEKName:
		return kmsrpb.ProtectionLevel_EXTERNAL
	default:
		return kmsrpb.ProtectionLevel_PROTECTION_LEVEL_UNSPECIFIED
	}
}

func (f *fakeKeyManagementClient) GetCryptoKey(ctx context.Context, req *kmsspb.GetCryptoKeyRequest, opts ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
	if f.getCryptoKeyFunc != nil {
		return f.getCryptoKeyFunc(ctx, req, opts...)
	}

	return createEnabledCryptoKey(fakeKMSProtectionLevel(req.GetName())), nil
}

func fakeKMSWrap(unwrapped []byte, name string) []byte {
	switch name {
	case testHSMKEKName:
		return append(unwrapped, byte('H'))
	case testSoftwareKEKName:
		return append(unwrapped, byte('S'))
	default:
		return append(unwrapped, byte('U'))
	}
}

func ValidEncryptResponse(req *kmsspb.EncryptRequest) *kmsspb.EncryptResponse {
	wrappedShare := fakeKMSWrap(req.GetPlaintext(), req.GetName())

	return &kmsspb.EncryptResponse{
		Name:                    req.GetName(),
		Ciphertext:              wrappedShare,
		CiphertextCrc32C:        wrapperspb.Int64(int64(crc32c(wrappedShare))),
		VerifiedPlaintextCrc32C: true,
	}
}

func (f *fakeKeyManagementClient) Encrypt(ctx context.Context, req *kmsspb.EncryptRequest, opts ...gax.CallOption) (*kmsspb.EncryptResponse, error) {
	if f.encryptFunc != nil {
		return f.encryptFunc(ctx, req, opts...)
	}

	return ValidEncryptResponse(req), nil
}

func fakeKMSUnwrap(wrapped []byte, name string) []byte {
	var final byte
	switch name {
	case testHSMKEKName:
		final = 'H'
	case testSoftwareKEKName:
		final = 'S'
	default:
		final = 'U'
	}

	if wrapped[len(wrapped)-1] != final {
		return []byte("nonsenseee")
	}
	return wrapped[:len(wrapped)-1]
}

func ValidDecryptResponse(req *kmsspb.DecryptRequest) *kmsspb.DecryptResponse {
	unwrappedShare := fakeKMSUnwrap(req.GetCiphertext(), req.GetName())

	return &kmsspb.DecryptResponse{
		Plaintext:       unwrappedShare,
		PlaintextCrc32C: wrapperspb.Int64(int64(crc32c(unwrappedShare))),
	}
}

func (f *fakeKeyManagementClient) Decrypt(ctx context.Context, req *kmsspb.DecryptRequest, opts ...gax.CallOption) (*kmsspb.DecryptResponse, error) {
	if f.decryptFunc != nil {
		return f.decryptFunc(ctx, req, opts...)
	}

	return ValidDecryptResponse(req), nil
}

func (f *fakeKeyManagementClient) Close() error {
	return nil
}

func TestParseEKMKeyURI(t *testing.T) {
	keyURI := "https://test.ekm.io/endpoints/123456"
	expectedAddr := fmt.Sprintf("https://test.ekm.io:%v", proxyPort)
	expectedKeyPath := "123456"

	addr, keyPath, err := parseEKMKeyURI(keyURI)
	if err != nil {
		t.Errorf("parseEKMKeyURI(%v) returned unexpected error: %v", keyURI, err)
	}

	if addr != expectedAddr {
		t.Errorf("parseEKMKeyURI(%v) returned unexpected address. Got %v, want %v", keyURI, addr, expectedAddr)
	}

	if keyPath != expectedKeyPath {
		t.Errorf("parseEKMKeyURI(%v) returned unexpected keyPath. Got %v, want %v", keyURI, keyPath, expectedKeyPath)
	}
}

func TestProtectionLevelsAndUris(t *testing.T) {
	ctx := context.Background()

	kekInfos := []*configpb.KekInfo{
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{
				KekUri: testKEKURI + "1",
			},
		},
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{
				KekUri: testKEKURI + "2",
			},
		},
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{
				KekUri: testKEKURI + "3",
			},
		},
	}

	expectedURIs := []string{testKEKURI + "1", testKEKURI + "2", testKEKURIExternal}

	protectionLevels := []kmsrpb.ProtectionLevel{kmsrpb.ProtectionLevel_HSM, kmsrpb.ProtectionLevel_SOFTWARE, kmsrpb.ProtectionLevel_EXTERNAL}
	plIndex := 0
	fakeKmsClient := &fakeKeyManagementClient{
		getCryptoKeyFunc: func(_ context.Context, req *kmsspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
			ck := createEnabledCryptoKey(protectionLevels[plIndex])
			plIndex++
			return ck, nil
		},
	}

	kekMetadatas, err := protectionLevelsAndUris(ctx, fakeKmsClient, kekInfos)
	if err != nil {
		t.Fatalf("protectionLevelsAndUris(ctx, %v, %v) returned with error %v", fakeKmsClient, kekInfos, err)
	}

	for i, kmd := range kekMetadatas {
		if kmd.uri != expectedURIs[i] {
			t.Errorf("protectionLevelsAndUris(ctx, %v, %v) did not return the expected URI. Got %v, want %v", fakeKmsClient, kekInfos, kmd.uri, expectedURIs[i])
		}
	}
}

func TestProtectionLevelsAndUrisErrors(t *testing.T) {
	ctx := context.Background()
	validKekInfos := []*configpb.KekInfo{
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{
				KekUri: testKEKURI,
			},
		},
	}

	testCases := []struct {
		name              string
		fakeKmsClient     *fakeKeyManagementClient
		kekInfos          []*configpb.KekInfo
		expectedErrSubstr string
	}{
		{
			name: "GetCryptoKey returns error",
			fakeKmsClient: &fakeKeyManagementClient{
				getCryptoKeyFunc: func(_ context.Context, req *kmsspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
					return nil, errors.New("this is an error from GetCryptoKey")
				},
			},
			kekInfos:          validKekInfos,
			expectedErrSubstr: "retrieving key metadata",
		},
		{
			name: "Primary GetCryptoKeyVersion is not enabled",
			fakeKmsClient: &fakeKeyManagementClient{
				getCryptoKeyFunc: func(_ context.Context, req *kmsspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
					return &kmsrpb.CryptoKey{
						Primary: &kmsrpb.CryptoKeyVersion{
							Name:            "projects/test/locations/test/keyRings/test/cryptoKeys/test/cryptoKeyVersions/test",
							State:           kmsrpb.CryptoKeyVersion_DISABLED,
							ProtectionLevel: kmsrpb.ProtectionLevel_SOFTWARE,
						},
					}, nil
				},
			},
			kekInfos:          validKekInfos,
			expectedErrSubstr: "not enabled",
		},
		{
			name: "Unspecified protection level",
			fakeKmsClient: &fakeKeyManagementClient{
				getCryptoKeyFunc: func(_ context.Context, req *kmsspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
					return createEnabledCryptoKey(kmsrpb.ProtectionLevel_PROTECTION_LEVEL_UNSPECIFIED), nil
				},
			},
			kekInfos:          validKekInfos,
			expectedErrSubstr: "unspecified protection level",
		},
		{
			name: "External protection level without ExternalProtectionLevelOptions",
			fakeKmsClient: &fakeKeyManagementClient{
				getCryptoKeyFunc: func(_ context.Context, req *kmsspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
					return &kmsrpb.CryptoKey{
						Primary: &kmsrpb.CryptoKeyVersion{
							Name:            "projects/test/locations/test/keyRings/test/cryptoKeys/test/cryptoKeyVersions/test",
							State:           kmsrpb.CryptoKeyVersion_ENABLED,
							ProtectionLevel: kmsrpb.ProtectionLevel_EXTERNAL,
						},
					}, nil
				},
			},
			kekInfos:          validKekInfos,
			expectedErrSubstr: "external protection level options",
		},
		{
			name:          "KEK URI lacks GCP KMS identifying prefix",
			fakeKmsClient: &fakeKeyManagementClient{},
			kekInfos: []*configpb.KekInfo{
				&configpb.KekInfo{
					KekType: &configpb.KekInfo_KekUri{
						KekUri: "invalid uri",
					},
				},
			},
			expectedErrSubstr: "expected URI prefix",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := protectionLevelsAndUris(ctx, testCase.fakeKmsClient, testCase.kekInfos)

			if err == nil {
				t.Errorf("protectionLevelsAndUris(ctx, %v, %v) returned no error, expected error related to \"%s\"", testCase.fakeKmsClient, testCase.kekInfos, testCase.expectedErrSubstr)
			}
		})
	}
}

func TestWrapKMSShareSucceeds(t *testing.T) {
	testShare := []byte("Food share")
	testCases := []struct {
		name         string
		kekName      string
		expectedWrap []byte
	}{
		{
			name:         "HSM",
			kekName:      testHSMKEKName,
			expectedWrap: fakeKMSWrap(testShare, testHSMKEKName),
		},
		{
			name:         "Software",
			kekName:      testSoftwareKEKName,
			expectedWrap: fakeKMSWrap(testShare, testSoftwareKEKName),
		},
	}

	ctx := context.Background()
	kmsClient := &fakeKeyManagementClient{}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			wrappedShare, err := wrapKMSShare(ctx, kmsClient, testShare, testCase.kekName)
			if err != nil {
				t.Fatalf("wrapKMSShare(%v, %v) = %v error, want nil error", testShare, testCase.kekName, err)
			}
			if !bytes.Equal(wrappedShare, testCase.expectedWrap) {
				t.Errorf("wrapKMSShare(%v, %v) = %v, want %v", testShare, testCase.kekName, wrappedShare, testCase.expectedWrap)
			}
		})
	}
}

func TestWrapKMSShareFails(t *testing.T) {
	plaintext := []byte("Plaintext")
	testCases := []struct {
		name            string
		encryptResponse *kmsspb.EncryptResponse
		encryptError    error
	}{
		{
			name: "Plaintext corrupted",
			encryptResponse: &kmsspb.EncryptResponse{
				Name:                    testKEKName,
				Ciphertext:              []byte("Ciphertext"),
				CiphertextCrc32C:        wrapperspb.Int64(int64(crc32c([]byte("Ciphertext")))),
				VerifiedPlaintextCrc32C: false,
			},
			encryptError: nil,
		},
		{
			name: "Ciphertext corrupted",
			encryptResponse: &kmsspb.EncryptResponse{
				Name:                    testKEKName,
				Ciphertext:              []byte("Ciphertext"),
				CiphertextCrc32C:        wrapperspb.Int64(10),
				VerifiedPlaintextCrc32C: true,
			},
			encryptError: nil,
		},
		{
			name:            "Error from encrypt",
			encryptResponse: nil,
			encryptError:    errors.New("Service unavailable"),
		},
	}

	ctx := context.Background()

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			kmsClient := &fakeKeyManagementClient{
				encryptFunc: func(_ context.Context, _ *kmsspb.EncryptRequest, _ ...gax.CallOption) (*kmsspb.EncryptResponse, error) {
					return testCase.encryptResponse, testCase.encryptError
				},
			}

			_, err := wrapKMSShare(ctx, kmsClient, plaintext, testKEKName)

			if err == nil {
				t.Errorf("wrapKMSShare(%v, %v) = nil error, want error", plaintext, testKEKName)
			}
		})
	}
}

func TestEkmSecureSessionWrap(t *testing.T) {
	ctx := context.Background()
	plaintext := []byte("this is plaintext")
	md := kekMetadata{uri: testKEKURIExternal}
	expectedCiphertext := append(plaintext, byte('E'))

	fakeEkmClient := &fakeSecureSessionClient{}

	var stetClient StetClient
	stetClient.setFakeSecureSessionClient(fakeEkmClient)

	ciphertext, err := stetClient.ekmSecureSessionWrap(ctx, plaintext, md)
	if err != nil {
		t.Fatalf("ekmSecureSessionWrap(ctx, \"%s\", \"%v\") returned error: %v", plaintext, md, err)
	}

	if !bytes.Equal(ciphertext, expectedCiphertext) {
		t.Errorf("ekmSecureSessionWrap(ctx, \"%s\", \"%v\") did not return expected wrapped share. Got %v, want %v", plaintext, md, ciphertext, expectedCiphertext)
	}

}

func TestEkmSecureSessionWrapError(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name              string
		fakeEkmClient     *fakeSecureSessionClient
		expectedErrSubstr string
	}{
		{
			name: "ConfidentialWrap returns error",
			fakeEkmClient: &fakeSecureSessionClient{
				wrapErr: errors.New("this is an error from ConfidentialWrap"),
			},
			expectedErrSubstr: "wrapping",
		},
		{
			name: "EndSession returns error",
			fakeEkmClient: &fakeSecureSessionClient{
				endSessionErr: errors.New("this is an error from EndSession"),
			},
			expectedErrSubstr: "ending secure session",
		},
	}

	for _, testCase := range testCases {
		var stetClient StetClient
		stetClient.setFakeSecureSessionClient(testCase.fakeEkmClient)

		_, err := stetClient.ekmSecureSessionWrap(ctx, []byte("this is plaintext"), kekMetadata{uri: "this is a uri"})
		if err == nil {
			t.Errorf("ekmSecureSessionWrap(context.Background, \"this is plaintext\", \"this is a uri\") returned no error, expected to return error related to %s", testCase.expectedErrSubstr)
		}
	}
}

func TestEkmSecureSessionUnwrap(t *testing.T) {
	ctx := context.Background()
	expectedPlaintext := []byte("this is plaintext")
	md := kekMetadata{uri: testKEKURIExternal}
	ciphertext := append(expectedPlaintext, byte('E'))

	fakeEkmClient := &fakeSecureSessionClient{}

	var stetClient StetClient
	stetClient.setFakeSecureSessionClient(fakeEkmClient)

	plaintext, err := stetClient.ekmSecureSessionUnwrap(ctx, ciphertext, md)
	if err != nil {
		t.Fatalf("ekmSecureSessionUnwrap(context.Background(), \"%s\", \"%v\") returned error: %v", ciphertext, md, err)
	}

	if !bytes.Equal(plaintext, expectedPlaintext) {
		t.Errorf("ekmSecureSessionUnwrap(context.Background(), \"%s\", \"%v\") did not return expected wrapped share. Got %v, want %v", ciphertext, md, plaintext, expectedPlaintext)
	}

}

func TestEkmSecureSessionUnwrapError(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name              string
		fakeEkmClient     *fakeSecureSessionClient
		expectedErrSubstr string
	}{
		{
			name: "ConfidentialUnwrap returns error",
			fakeEkmClient: &fakeSecureSessionClient{
				unwrapErr: errors.New("this is an error from ConfidentialUnwrap"),
			},
			expectedErrSubstr: "wrapping",
		},
		{
			name: "EndSession returns error",
			fakeEkmClient: &fakeSecureSessionClient{
				endSessionErr: errors.New("this is an error from EndSession"),
			},
			expectedErrSubstr: "ending secure session",
		},
	}

	for _, testCase := range testCases {
		var stetClient StetClient
		stetClient.setFakeSecureSessionClient(testCase.fakeEkmClient)

		_, err := stetClient.ekmSecureSessionUnwrap(ctx, []byte("this is ciphertext"), kekMetadata{uri: testKEKURIExternal})
		if err == nil {
			t.Errorf("ekmSecureSessionUnwrap(context.Background, \"this is ciphertext\", %v) returned no error, expected to return error related to %s", testKEKURIExternal, testCase.expectedErrSubstr)
		}
	}
}

func TestWrapSharesIndividually(t *testing.T) {
	testShare := []byte("I am a wrapped share.")
	testHashedShare := HashShare(testShare)

	testCases := []struct {
		name            string
		uri             string
		protectionLevel kmsrpb.ProtectionLevel
		expectedWrap    []byte
	}{
		{
			name:            "Software Protection Level",
			uri:             testKEKURISoftware,
			protectionLevel: kmsrpb.ProtectionLevel_SOFTWARE,
			expectedWrap:    fakeKMSWrap(testShare, testSoftwareKEKName),
		},
		{
			name:            "Hardware Protection Level",
			uri:             testKEKURIHSM,
			protectionLevel: kmsrpb.ProtectionLevel_HSM,
			expectedWrap:    fakeKMSWrap(testShare, testHSMKEKName),
		},
		{
			name:            "External Protection Level",
			uri:             testKEKURIExternal,
			protectionLevel: kmsrpb.ProtectionLevel_EXTERNAL,
			expectedWrap:    append(testShare, byte('E')),
		},
	}

	ctx := context.Background()

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fakeKMSClient := &fakeKeyManagementClient{}

			var stetClient StetClient
			stetClient.setFakeKeyManagementClient(fakeKMSClient)
			stetClient.setFakeSecureSessionClient(&fakeSecureSessionClient{})

			ki := []*configpb.KekInfo{
				&configpb.KekInfo{
					KekType: &configpb.KekInfo_KekUri{
						KekUri: testCase.uri,
					},
				},
			}

			wrappedShares, err := stetClient.wrapShares(ctx, [][]byte{testShare}, ki, &configpb.AsymmetricKeys{})

			if err != nil {
				t.Fatalf("wrapShares returned with error: %v", err)
			}

			if len(wrappedShares) != 1 {
				t.Fatalf("wrapShares(ctx, %s, %v) did not return the expected number of shares. Got %v, want 1", testShare, ki, len(wrappedShares))
			}

			if !bytes.Equal(wrappedShares[0].GetShare(), testCase.expectedWrap) {
				t.Errorf("wrapShares(ctx, %s, %v) did not return the expected wrapped share. Got %v, want %v", testShare, ki, wrappedShares[0].GetShare(), testCase.expectedWrap)
			}

			if !bytes.Equal(wrappedShares[0].GetHash(), testHashedShare[:]) {
				t.Errorf("wrapShares(ctx, %s, %v) did not return the expected hashed share. Got %v, want %v", testShare, ki, wrappedShares[0].GetHash(), testHashedShare)
			}
		})
	}
}

func TestWrapUnwrapShareAsymmetricKey(t *testing.T) {
	testShare := []byte("Foo!")
	testHashedShare := HashShare(testShare)

	ctx := context.Background()

	ki := []*configpb.KekInfo{
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_RsaFingerprint{
				RsaFingerprint: testPublicFingerprint,
			},
		},
	}

	// Write testing keys to temporary location.
	prvKeyFile, err := ioutil.TempFile(os.Getenv("TEST_TMPDIR"), "")
	if err != nil {
		t.Fatalf("Failed to create temp file for test private key: %v", err)
	}
	prvKeyFile.Write([]byte(testPrivatePEM))
	defer os.Remove(prvKeyFile.Name())

	pubKeyFile, err := ioutil.TempFile(os.Getenv("TEST_TMPDIR"), "")
	if err != nil {
		t.Fatalf("Failed to create temp file for test public key: %v", err)
	}
	pubKeyFile.Write([]byte(testPublicPEM))
	defer os.Remove(pubKeyFile.Name())

	keys := &configpb.AsymmetricKeys{
		PublicKeyFiles:  []string{pubKeyFile.Name()},
		PrivateKeyFiles: []string{prvKeyFile.Name()},
	}

	var stetClient StetClient
	wrappedShares, err := stetClient.wrapShares(ctx, [][]byte{testShare}, ki, keys)

	if err != nil {
		t.Fatalf("wrapShares returned with error: %v", err)
	}

	if len(wrappedShares) != 1 {
		t.Fatalf("wrapShares(ctx, %s, %v) did not return the expected number of shares. Got %v, want 1", testShare, ki, len(wrappedShares))
	}

	if !bytes.Equal(wrappedShares[0].GetHash(), testHashedShare[:]) {
		t.Errorf("wrapShares(ctx, %s, %v) did not return the expected hashed share. Got %v, want %v", testShare, ki, wrappedShares[0].GetHash(), testHashedShare)
	}

	unwrappedShares, err := stetClient.unwrapAndValidateShares(ctx, wrappedShares, ki, keys)

	if err != nil {
		t.Fatalf("unwrapAndValidateShares retruned with error: %v", err)
	}

	if len(unwrappedShares) != 1 {
		t.Fatalf("unwrapAndValidateShares(ctx, %s, %v, %v) did not return the expected number of shares. Got %v, want 1", wrappedShares, ki, keys, len(unwrappedShares))
	}

	if !bytes.Equal(unwrappedShares[0], testShare) {
		t.Errorf("unwrapAndValidateShares(ctx, %s, %v, %v) did not return the expected unwrapped share. Got %v, want %v", testShare, ki, keys, unwrappedShares[0], testShare)
	}
}

func TestWrapUnwrapShareAsymmetricKeyError(t *testing.T) {
	// Write testing keys to temporary location.
	prvKeyFile, err := ioutil.TempFile(os.Getenv("TEST_TMPDIR"), "")
	if err != nil {
		t.Fatalf("Failed to create temp file for test private key: %v", err)
	}
	prvKeyFile.Write([]byte(testPrivatePEM))
	defer os.Remove(prvKeyFile.Name())

	pubKeyFile, err := ioutil.TempFile(os.Getenv("TEST_TMPDIR"), "")
	if err != nil {
		t.Fatalf("Failed to create temp file for test public key: %v", err)
	}
	pubKeyFile.Write([]byte(testPublicPEM))
	defer os.Remove(pubKeyFile.Name())

	pubKeyFile2, err := ioutil.TempFile(os.Getenv("TEST_TMPDIR"), "")
	if err != nil {
		t.Fatalf("Failed to create temp file for test public key 2: %v", err)
	}
	pubKeyFile.Write([]byte(testPublicPEM2))
	defer os.Remove(pubKeyFile2.Name())

	testCases := []struct {
		name            string
		unwrappedShares [][]byte
		kekInfos        []*configpb.KekInfo
		errorOnWrap     bool
		asymmetricKeys  *configpb.AsymmetricKeys
	}{
		{
			name:            "Wrong public key for private key",
			unwrappedShares: [][]byte{[]byte("I am a wrapped share.")},
			asymmetricKeys: &configpb.AsymmetricKeys{
				PublicKeyFiles:  []string{pubKeyFile2.Name()},
				PrivateKeyFiles: []string{prvKeyFile.Name()},
			},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_RsaFingerprint{
					RsaFingerprint: testPublicFingerprint,
				},
			}},
		},
		{
			name:            "No fingerprint matches",
			unwrappedShares: [][]byte{[]byte("I am a wrapped share.")},
			asymmetricKeys: &configpb.AsymmetricKeys{
				PublicKeyFiles:  []string{pubKeyFile.Name()},
				PrivateKeyFiles: []string{prvKeyFile.Name()},
			},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_RsaFingerprint{
					RsaFingerprint: "not a real fingerprint for sure!",
				},
			}},
		},
		{
			name:            "Invalid private key file",
			unwrappedShares: [][]byte{[]byte("I am a wrapped share.")},
			asymmetricKeys: &configpb.AsymmetricKeys{
				PublicKeyFiles:  []string{pubKeyFile.Name()},
				PrivateKeyFiles: []string{"not-a-path"},
			},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_RsaFingerprint{
					RsaFingerprint: testPublicFingerprint,
				},
			}},
		},
	}

	ctx := context.Background()

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var stetClient StetClient
			wrappedShares, err := stetClient.wrapShares(ctx, testCase.unwrappedShares, testCase.kekInfos, testCase.asymmetricKeys)

			if err == nil && testCase.errorOnWrap {
				t.Errorf("wrapShares(%s, %s) expected to return error, but did not", testCase.unwrappedShares, testCase.kekInfos)
			}

			_, err = stetClient.unwrapAndValidateShares(ctx, wrappedShares, testCase.kekInfos, testCase.asymmetricKeys)

			if err == nil {
				t.Errorf("unwrapAndValidateShares(%s, %s, %v) expected to return error, but did not", wrappedShares, testCase.kekInfos, testCase.asymmetricKeys)
			}
		})
	}
}

func TestWrapSharesWithMultipleShares(t *testing.T) {
	// Create lists of shares and kekInfos of appropriate length.
	sharesList := [][]byte{[]byte("share1"), []byte("share2"), []byte("share3")}
	kekInfoList := []*configpb.KekInfo{
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{
				KekUri: testKEKURISoftware,
			},
		},
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{
				KekUri: testKEKURIHSM,
			},
		},
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{
				KekUri: testKEKURIExternal,
			},
		},
	}
	wrappedSharesList := [][]byte{
		fakeKMSWrap(sharesList[0], testSoftwareKEKName),
		fakeKMSWrap(sharesList[1], testHSMKEKName),
		append(sharesList[2], byte('E')),
	}
	ctx := context.Background()

	fakeKMSClient := &fakeKeyManagementClient{}
	var stetClient StetClient
	stetClient.setFakeKeyManagementClient(fakeKMSClient)
	stetClient.setFakeSecureSessionClient(&fakeSecureSessionClient{})

	wrapped, err := stetClient.wrapShares(ctx, sharesList, kekInfoList, &configpb.AsymmetricKeys{})

	if err != nil {
		t.Fatalf("wrapShares(%s, %s) returned with error %v", sharesList, kekInfoList, err)
	}

	if len(wrapped) != len(sharesList) {
		t.Fatalf("wrapShares(%s, %s) did not return the expected number of shares. Got %v, want %v", sharesList, kekInfoList, len(wrapped), len(sharesList))
	}

	for i, w := range wrapped {
		if !bytes.Equal(w.GetShare(), wrappedSharesList[i]) {
			t.Errorf("wrapShares(%s, %s) did not return the expected wrapped share for share %v. Got %v, want %v", sharesList, kekInfoList, sharesList[i], w.GetShare(), wrappedSharesList[i])
		}
	}
}

func TestWrapSharesError(t *testing.T) {
	testCases := []struct {
		name              string
		unwrappedShares   [][]byte
		kekInfos          []*configpb.KekInfo
		ckReturn          *kmsrpb.CryptoKey
		ckErrReturn       error
		fakeSSClient      *fakeSecureSessionClient
		encryptErrReturn  error
		expectedErrSubstr string
	}{
		{
			name:            "GetCryptoKey returns error",
			unwrappedShares: [][]byte{[]byte("I am a wrapped share.")},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{
					KekUri: testKEKURI,
				},
			}},
			ckErrReturn:       errors.New("this is an error"),
			encryptErrReturn:  nil,
			expectedErrSubstr: "key metadata",
		},
		{
			name:            "Primary CryptoKeyVersion is not enabled",
			unwrappedShares: [][]byte{[]byte("I am a wrapped share.")},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{
					KekUri: testKEKURI,
				},
			}},
			ckReturn: &kmsrpb.CryptoKey{
				Primary: &kmsrpb.CryptoKeyVersion{
					Name:            testKEKName,
					State:           kmsrpb.CryptoKeyVersion_DISABLED,
					ProtectionLevel: kmsrpb.ProtectionLevel_SOFTWARE,
				},
			},
			ckErrReturn:       nil,
			encryptErrReturn:  nil,
			expectedErrSubstr: "not enabled",
		},
		{
			name:            "Primary CryptoKeyVersion has unspecified protection level",
			unwrappedShares: [][]byte{[]byte("I am a wrapped share.")},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{
					KekUri: testKEKURI,
				},
			}},
			ckReturn:         createEnabledCryptoKey(kmsrpb.ProtectionLevel_PROTECTION_LEVEL_UNSPECIFIED),
			ckErrReturn:      nil,
			encryptErrReturn: nil, expectedErrSubstr: "protection level",
		},
		{
			name:            "Mismatched numbers of unwrapped shares and kekInfos",
			unwrappedShares: [][]byte{[]byte("I am a wrapped share."), []byte("I am a wrapped share.")},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{
					KekUri: testKEKURI,
				},
			}},
			ckReturn:          createEnabledCryptoKey(kmsrpb.ProtectionLevel_SOFTWARE),
			ckErrReturn:       nil,
			fakeSSClient:      &fakeSecureSessionClient{},
			encryptErrReturn:  nil,
			expectedErrSubstr: "number of shares",
		},
		{
			name:            "protectionLevelsAndUris returns error",
			unwrappedShares: [][]byte{[]byte("I am a wrapped share.")},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{
					KekUri: "I am an invalid URI!",
				},
			}},
			ckReturn:          createEnabledCryptoKey(kmsrpb.ProtectionLevel_SOFTWARE),
			ckErrReturn:       nil,
			fakeSSClient:      &fakeSecureSessionClient{},
			encryptErrReturn:  nil,
			expectedErrSubstr: "retrieving KEK Metadata",
		},
		{
			name:            "ekmSecureSessionWrap returns error",
			unwrappedShares: [][]byte{[]byte("I am a wrapped share.")},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{
					KekUri: testKEKURI,
				},
			}},
			ckReturn: createEnabledCryptoKey(kmsrpb.ProtectionLevel_EXTERNAL),
			fakeSSClient: &fakeSecureSessionClient{
				wrapErr: errors.New("this is an error from ConfidentialWrap"),
			},
			expectedErrSubstr: "wrapping with secure session",
		},
		{
			name:            "Encrypt returns an error",
			unwrappedShares: [][]byte{[]byte("I am a wrapped share.")},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{
					KekUri: testKEKURI,
				},
			}},
			ckReturn:          createEnabledCryptoKey(kmsrpb.ProtectionLevel_SOFTWARE),
			ckErrReturn:       nil,
			encryptErrReturn:  errors.New("encrypt error"),
			expectedErrSubstr: "encrypt error",
		},
	}

	ctx := context.Background()

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fakeKMSClient := &fakeKeyManagementClient{
				getCryptoKeyFunc: func(_ context.Context, req *kmsspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
					return testCase.ckReturn, testCase.ckErrReturn
				},
				encryptFunc: func(_ context.Context, req *kmsspb.EncryptRequest, _ ...gax.CallOption) (*kmsspb.EncryptResponse, error) {
					return ValidEncryptResponse(req), testCase.encryptErrReturn
				},
			}

			var stetClient StetClient
			stetClient.setFakeKeyManagementClient(fakeKMSClient)
			stetClient.setFakeSecureSessionClient(testCase.fakeSSClient)
			_, err := stetClient.wrapShares(ctx, testCase.unwrappedShares, testCase.kekInfos, &configpb.AsymmetricKeys{})

			if err == nil {
				t.Errorf("wrapShares(%s, %s) expected to return error, but did not", testCase.unwrappedShares, testCase.kekInfos)
			}
		})
	}
}

func TestUnwrapAndValidateSharesIndividually(t *testing.T) {
	expectedUnwrappedShare := []byte("I am a wrapped share.")
	expectedHashedShare := HashShare(expectedUnwrappedShare)

	testCases := []struct {
		name         string
		uri          string
		wrappedShare []*configpb.WrappedShare
	}{
		{
			name: "Software Protection Level",
			uri:  testKEKURISoftware,
			wrappedShare: []*configpb.WrappedShare{
				&configpb.WrappedShare{
					Share: fakeKMSWrap(expectedUnwrappedShare, testSoftwareKEKName),
					Hash:  expectedHashedShare,
				},
			},
		},
		{
			name: "Hardware Protection Level",
			uri:  testKEKURIHSM,
			wrappedShare: []*configpb.WrappedShare{
				&configpb.WrappedShare{
					Share: fakeKMSWrap(expectedUnwrappedShare, testHSMKEKName),
					Hash:  expectedHashedShare,
				},
			},
		},
		{
			name: "External Protection Level",
			uri:  testKEKURIExternal,
			wrappedShare: []*configpb.WrappedShare{
				&configpb.WrappedShare{
					Share: append(expectedUnwrappedShare, byte('E')),
					Hash:  expectedHashedShare,
				},
			},
		},
	}

	ctx := context.Background()

	fakeKmsClient := &fakeKeyManagementClient{}

	var stetClient StetClient
	stetClient.setFakeKeyManagementClient(fakeKmsClient)
	stetClient.setFakeSecureSessionClient(&fakeSecureSessionClient{})

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			unwrappedShares, err := stetClient.unwrapAndValidateShares(ctx, testCase.wrappedShare, [](*configpb.KekInfo){
				&configpb.KekInfo{
					KekType: &configpb.KekInfo_KekUri{
						KekUri: testCase.uri,
					},
				},
			}, &configpb.AsymmetricKeys{})

			if err != nil {
				t.Fatalf("unwrapAndValidateShares returned with error: %v", err)
			}

			if len(unwrappedShares) != len(testCase.wrappedShare) {
				t.Fatalf("unwrapAndValidateShares did not return the expected number of shares. Got %v, want %v", len(unwrappedShares), len(testCase.wrappedShare))
			}

			if !bytes.Equal(unwrappedShares[0], expectedUnwrappedShare) {
				t.Errorf("unwrapAndValidateShares did not return the expected unwrapped share. Got %v, want %v", unwrappedShares[0], testCase.wrappedShare)
			}
		})
	}
}

func TestUnwrapAndValidateSharesWithMultipleShares(t *testing.T) {
	// Create lists of shares and kekInfos of appropriate length.
	share := []byte("expected unwrapped share")
	shareHash := HashShare(share)
	sharesList := [][]byte{share, share, share}
	kekInfoList := []*configpb.KekInfo{
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{
				KekUri: testKEKURISoftware,
			},
		},
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{
				KekUri: testKEKURIHSM,
			},
		},
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{
				KekUri: testKEKURIExternal,
			},
		},
	}
	wrappedSharesList := []*configpb.WrappedShare{
		{
			Share: fakeKMSWrap(share, testSoftwareKEKName),
			Hash:  shareHash,
		},
		{
			Share: fakeKMSWrap(share, testHSMKEKName),
			Hash:  shareHash,
		},
		{
			Share: append(share, byte('E')),
			Hash:  shareHash,
		},
	}

	ctx := context.Background()

	fakeKmsClient := &fakeKeyManagementClient{}
	var stetClient StetClient
	stetClient.setFakeKeyManagementClient(fakeKmsClient)
	stetClient.setFakeSecureSessionClient(&fakeSecureSessionClient{})

	unwrapped, err := stetClient.unwrapAndValidateShares(ctx, wrappedSharesList, kekInfoList, &configpb.AsymmetricKeys{})

	if err != nil {
		t.Fatalf("wrapShares returned with error %v", err)
	}

	if len(unwrapped) != len(wrappedSharesList) {
		t.Fatalf("unwrapAndValidateShares(context.Background(), %v, %v) did not return the expected number of shares. Got %v, want %v", wrappedSharesList, kekInfoList, len(unwrapped), len(wrappedSharesList))
	}

	for i, unwrappedShare := range unwrapped {
		if !bytes.Equal(unwrappedShare, sharesList[i]) {
			t.Errorf("unwrapAndValidateShares(context.Background(), %v, %v) did not return the expected wrapped share %v. Got %v, want %v", sharesList, kekInfoList, i, unwrappedShare, sharesList[i])
		}
	}
}

func TestUnwrapAndValidateSharesError(t *testing.T) {
	testUnwrappedShare := []byte("I am an unwrapped share")
	testWrappedShare := &configpb.WrappedShare{
		Share: fakeKMSWrap(testUnwrappedShare, testSoftwareKEKName),
		Hash:  HashShare(testUnwrappedShare),
	}

	testCases := []struct {
		name              string
		wrappedShares     []*configpb.WrappedShare
		kekInfos          []*configpb.KekInfo
		fakeSSClient      *fakeSecureSessionClient
		decryptErrReturn  error
		expectedErrSubstr string
	}{
		{
			name:          "Mismatched numbers of unwrapped shares and KekInfos",
			wrappedShares: []*configpb.WrappedShare{testWrappedShare, testWrappedShare},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{
					KekUri: testKEKURISoftware,
				},
			}},
			fakeSSClient:      &fakeSecureSessionClient{},
			decryptErrReturn:  nil,
			expectedErrSubstr: "number of shares",
		},
		{
			name:          "getProtectionLevelsAndUris returns error",
			wrappedShares: []*configpb.WrappedShare{testWrappedShare},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{
					KekUri: "I am an invalid URI!",
				},
			}},
			fakeSSClient:      &fakeSecureSessionClient{},
			decryptErrReturn:  nil,
			expectedErrSubstr: "retrieving KEK Metadata",
		},
		{
			name: "Unwrapped share has an invalid hash",
			wrappedShares: []*configpb.WrappedShare{&configpb.WrappedShare{
				Share: fakeKMSWrap(testUnwrappedShare, testSoftwareKEKName),
				Hash:  HashShare([]byte("I am a random different share")),
			}},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{
					KekUri: testKEKURISoftware,
				},
			}},
			fakeSSClient:      &fakeSecureSessionClient{},
			decryptErrReturn:  nil,
			expectedErrSubstr: "expected hash",
		},
		{
			name:          "ekmSecureSessionUnwrap with secure session returns error",
			wrappedShares: []*configpb.WrappedShare{testWrappedShare},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{
					KekUri: testKEKURI,
				},
			}},
			decryptErrReturn: nil,
			fakeSSClient: &fakeSecureSessionClient{
				unwrapErr: errors.New("this is an error from ConfidentialUnwrap"),
			},
			expectedErrSubstr: "unwrapping with external EKM",
		},
		{
			name:          "unwrapKMSShare returns error",
			wrappedShares: []*configpb.WrappedShare{testWrappedShare},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{
					KekUri: testKEKURISoftware,
				},
			}},
			decryptErrReturn:  errors.New("service unavailable"),
			expectedErrSubstr: "service unavailable",
		},
	}

	ctx := context.Background()

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fakeKmsClient := &fakeKeyManagementClient{
				decryptFunc: func(_ context.Context, req *kmsspb.DecryptRequest, _ ...gax.CallOption) (*kmsspb.DecryptResponse, error) {
					return ValidDecryptResponse(req), testCase.decryptErrReturn
				},
			}

			var stetClient StetClient
			stetClient.setFakeKeyManagementClient(fakeKmsClient)
			stetClient.setFakeSecureSessionClient(testCase.fakeSSClient)
			_, err := stetClient.unwrapAndValidateShares(ctx, testCase.wrappedShares, testCase.kekInfos, &configpb.AsymmetricKeys{})

			if err == nil {
				t.Errorf("unwrapAndValidateShares(context.Background(), %s, %s) expected to return error, but did not", testCase.wrappedShares, testCase.kekInfos)
			}
		})
	}
}

func TestWrapAndUnwrapWorkflow(t *testing.T) {
	// Create lists of shares and kekInfos of appropriate length.
	sharesList := [][]byte{[]byte("share1"), []byte("share2"), []byte("share3")}
	kekInfoList := []*configpb.KekInfo{
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{
				KekUri: testKEKURISoftware,
			},
		},
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{
				KekUri: testKEKURIHSM,
			},
		},
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{
				KekUri: testKEKURIExternal,
			},
		},
	}

	ctx := context.Background()

	fakeKmsClient := &fakeKeyManagementClient{}
	var stetClient StetClient
	stetClient.setFakeKeyManagementClient(fakeKmsClient)
	stetClient.setFakeSecureSessionClient(&fakeSecureSessionClient{})

	wrapped, err := stetClient.wrapShares(ctx, sharesList, kekInfoList, &configpb.AsymmetricKeys{})
	if err != nil {
		t.Fatalf("wrapShares(context.Background(), %v, %v, {}) returned with error %v", sharesList, kekInfoList, err)
	}

	unwrapped, err := stetClient.unwrapAndValidateShares(ctx, wrapped, kekInfoList, &configpb.AsymmetricKeys{})
	if err != nil {
		t.Errorf("unwrapAndValidateShares(context.Background(), %v, %v, {}) returned with error %v", wrapped, kekInfoList, err)
	}

	if len(wrapped) != len(unwrapped) {
		t.Fatalf("wrapShares returned %v shares, unwrapAndValidateShares returned %v shares. Expected equal numbers.", len(wrapped), len(unwrapped))
	}

	for i, unwrappedShare := range unwrapped {
		if !bytes.Equal(unwrappedShare, sharesList[i]) {
			t.Errorf("unwrapAndValidateShares(context.Background(), %v, %v, {}) = %v, want %v", sharesList, kekInfoList, unwrappedShare, sharesList[i])
		}
	}
}

func TestEncryptAndDecryptWithNoSplitSucceeds(t *testing.T) {
	testBlobID := "I am blob."
	kekInfo := &configpb.KekInfo{
		KekType: &configpb.KekInfo_KekUri{
			KekUri: testKEKURISoftware,
		},
	}

	keyConfig := &configpb.KeyConfig{
		KekInfos:              []*configpb.KekInfo{kekInfo},
		DekAlgorithm:          configpb.DekAlgorithm_AES256_GCM,
		KeySplittingAlgorithm: &configpb.KeyConfig_NoSplit{true},
	}

	encryptConfig := &configpb.EncryptConfig{
		KeyConfig: keyConfig,
	}

	decryptConfig := &configpb.DecryptConfig{
		KeyConfigs: []*configpb.KeyConfig{keyConfig},
	}

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "\"This is data to be encrypted.\"",
			plaintext: []byte("This is data to be encrypted."),
		},
		{
			name:      "Large size plaintext.",
			plaintext: random.GetRandomBytes(1500000),
		},
	}

	ctx := context.Background()
	fakeKMSClient := &fakeKeyManagementClient{}

	var stetClient StetClient
	stetClient.setFakeKeyManagementClient(fakeKMSClient)
	stetClient.setFakeSecureSessionClient(&fakeSecureSessionClient{})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encryptedData, err := stetClient.Encrypt(ctx, tc.plaintext, encryptConfig, &configpb.AsymmetricKeys{}, testBlobID)
			if err != nil {
				t.Errorf("Encrypt(ctx, %v, %v, {}, %v) returned error \"%v\", want no error", tc.plaintext, encryptConfig, testBlobID, err)
			}

			if encryptedData == nil {
				t.Fatalf("Encrypt(ctx, %v, %v, {}, %v) = nil, want non-nil result", tc.plaintext, encryptConfig, testBlobID)
			}

			// Verify encrypted data has expected fields.
			if len(encryptedData.Metadata.GetShares()) != 1 {
				t.Fatalf("Encrypt(ctx, %v, %v, {}, %v) did not create the expected number of shares. Got %d, want 1.", tc.plaintext, encryptConfig, testBlobID, len(encryptedData.Metadata.GetShares()))
			}

			if encryptedData.Metadata.GetBlobId() != testBlobID {
				t.Errorf("Encrypt(ctx, %v, %v, {}, %v) does not contain the expected blob ID. Got %v, want %v", tc.plaintext, encryptConfig, testBlobID, encryptedData.Metadata.GetBlobId(), testBlobID)
			}

			// Decrypt the returned data and verify fields.
			decryptedData, err := stetClient.Decrypt(ctx, encryptedData, decryptConfig, &configpb.AsymmetricKeys{})
			if err != nil {
				t.Fatalf("Error calling client.Decrypt(ctx, %v, %v, {}): %v", encryptedData, decryptConfig, err)
			}

			if decryptedData.BlobID != testBlobID {
				t.Errorf("Decrypt(ctx, %v, %v, {}) does not contain the expected blob ID. Got %v, want %v", encryptedData, decryptConfig, decryptedData.BlobID, testBlobID)
			}

			if len(decryptedData.KeyUris) != len(keyConfig.GetKekInfos()) {
				t.Fatalf("Decrypt(ctx, %v, %v, {}) does not have the expected number of key URIS. Got %v, want %v", encryptedData, decryptConfig, len(decryptedData.KeyUris), len(keyConfig.GetKekInfos()))
			}
			if decryptedData.KeyUris[0] != kekInfo.GetKekUri() {
				t.Errorf("Decrypt(ctx, %v, %v, {}) does not contain the expected key URI. Got { %v }, want { %v }", encryptedData, decryptConfig, decryptedData.KeyUris[0], kekInfo.GetKekUri())
			}

			if !bytes.Equal(decryptedData.Plaintext, tc.plaintext) {
				t.Errorf("Decrypt(ctx, %v, %v, {}) returned ciphertext thatdoes not match original plaintext. Got %v, want %v.", encryptedData, decryptConfig, decryptedData.Plaintext, tc.plaintext)
			}
		})
	}
}

func TestEncryptFailsForNoSplitWithTooManyKekInfos(t *testing.T) {
	testBlobID := "I am blob."
	kekInfo := &configpb.KekInfo{
		KekType: &configpb.KekInfo_KekUri{
			KekUri: testKEKURISoftware,
		},
	}

	keyConfig := configpb.KeyConfig{
		KekInfos:              []*configpb.KekInfo{kekInfo, kekInfo, kekInfo},
		DekAlgorithm:          configpb.DekAlgorithm_AES256_GCM,
		KeySplittingAlgorithm: &configpb.KeyConfig_NoSplit{true},
	}

	encryptConfig := configpb.EncryptConfig{
		KeyConfig: &keyConfig,
	}
	plaintext := []byte("This is data to be encrypted.")

	ctx := context.Background()
	fakeKMSClient := &fakeKeyManagementClient{}

	var stetClient StetClient
	stetClient.setFakeKeyManagementClient(fakeKMSClient)
	stetClient.setFakeSecureSessionClient(&fakeSecureSessionClient{})

	_, err := stetClient.Encrypt(ctx, plaintext, &encryptConfig, &configpb.AsymmetricKeys{}, testBlobID)
	if err == nil {
		t.Errorf("Encrypt with no split option and more than one KekInfo in the KeyConfig should return an error")
	}
}

func TestEncryptAndDecryptWithShamirSucceeds(t *testing.T) {
	testBlobID := "I am blob."
	kekInfo := &configpb.KekInfo{
		KekType: &configpb.KekInfo_KekUri{
			KekUri: testKEKURI,
		},
	}

	shamirConfig := &configpb.ShamirConfig{
		Threshold: 2,
		Shares:    3,
	}

	keyConfig := &configpb.KeyConfig{
		KekInfos:              []*configpb.KekInfo{kekInfo, kekInfo, kekInfo},
		DekAlgorithm:          configpb.DekAlgorithm_AES256_GCM,
		KeySplittingAlgorithm: &configpb.KeyConfig_Shamir{shamirConfig},
	}

	encryptConfig := &configpb.EncryptConfig{
		KeyConfig: keyConfig,
	}

	decryptConfig := &configpb.DecryptConfig{
		KeyConfigs: []*configpb.KeyConfig{keyConfig},
	}

	testCases := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "\"This is data to be encrypted.\"",
			plaintext: []byte("This is data to be encrypted."),
		},
		{
			name:      "Large size plaintext.",
			plaintext: random.GetRandomBytes(1500000),
		},
	}

	ctx := context.Background()
	fakeKMSClient := &fakeKeyManagementClient{
		getCryptoKeyFunc: func(_ context.Context, req *kmsspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
			return createEnabledCryptoKey(kmsrpb.ProtectionLevel_SOFTWARE), nil
		},
	}

	var stetClient StetClient
	stetClient.setFakeKeyManagementClient(fakeKMSClient)
	stetClient.setFakeSecureSessionClient(&fakeSecureSessionClient{})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encryptedData, err := stetClient.Encrypt(ctx, tc.plaintext, encryptConfig, &configpb.AsymmetricKeys{}, testBlobID)
			if err != nil {
				t.Fatalf("Encrypt did not complete successfully: %v", err)
			}

			// Verify encrypted data has expected fields.
			if len(encryptedData.Metadata.GetShares()) != int(shamirConfig.GetShares()) {
				t.Fatalf("Encrypt did not create the expected number of shares. Got %d, want %d.",
					len(encryptedData.Metadata.GetShares()), shamirConfig.GetShares())
			}

			if encryptedData.Metadata.GetBlobId() != testBlobID {
				t.Errorf("Encrypted data does not contain the expected blob ID. Got %v, want %v", encryptedData.Metadata.GetBlobId(), testBlobID)
			}

			// Decrypt the returned data and verify fields.
			decryptedData, err := stetClient.Decrypt(ctx, encryptedData, decryptConfig, &configpb.AsymmetricKeys{})
			if err != nil {
				t.Fatalf("Error decrypting data: %v", err)
			}

			if decryptedData.BlobID != testBlobID {
				t.Errorf("Decrypted data does not contain the expected blob ID. Got %v, want %v", decryptedData.BlobID, testBlobID)
			}

			if !bytes.Equal(decryptedData.Plaintext, tc.plaintext) {
				t.Errorf("Decrypted ciphertext does not match original plaintext. Got %v, want %v.", decryptedData.Plaintext, tc.plaintext)
			}

			if len(decryptedData.KeyUris) != len(keyConfig.GetKekInfos()) {
				t.Fatalf("Decrypted data does not have the expected number of key URIS. Got %v, want %v", len(decryptedData.KeyUris), len(keyConfig.GetKekInfos()))
			}
			if decryptedData.KeyUris[0] != kekInfo.GetKekUri() {
				t.Errorf("Decrypted data does not contain the expected key URI. Got { %v }, want { %v }", decryptedData.KeyUris[0], kekInfo.GetKekUri())
			}
		})
	}
}

func TestEncryptFailsForInvalidShamirConfiguration(t *testing.T) {
	testBlobID := "I am blob."
	kekInfo := &configpb.KekInfo{
		KekType: &configpb.KekInfo_KekUri{
			KekUri: testKEKURI,
		},
	}

	// Invalid configuration due to threshold exceeding shares.
	shamirConfig := configpb.ShamirConfig{
		Threshold: 5,
		Shares:    3,
	}

	keyConfig := configpb.KeyConfig{
		KekInfos:              []*configpb.KekInfo{kekInfo, kekInfo, kekInfo},
		DekAlgorithm:          configpb.DekAlgorithm_AES256_GCM,
		KeySplittingAlgorithm: &configpb.KeyConfig_Shamir{&shamirConfig},
	}

	encryptConfig := configpb.EncryptConfig{
		KeyConfig: &keyConfig,
	}
	plaintext := []byte("This is data to be encrypted.")

	ctx := context.Background()
	fakeKMSClient := &fakeKeyManagementClient{
		getCryptoKeyFunc: func(_ context.Context, req *kmsspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
			return createEnabledCryptoKey(kmsrpb.ProtectionLevel_SOFTWARE), nil
		},
	}

	var stetClient StetClient
	stetClient.setFakeKeyManagementClient(fakeKMSClient)
	stetClient.setFakeSecureSessionClient(&fakeSecureSessionClient{})

	_, err := stetClient.Encrypt(ctx, plaintext, &encryptConfig, &configpb.AsymmetricKeys{}, testBlobID)
	if err == nil {
		t.Errorf("Encrypt expected to fail due to invalid Shamir's Secret Sharing configuration.")
	}
}

// Ensures Encrypt fills in a random blob ID if not provided in the config.
func TestEncryptGeneratesUUIDForBlobID(t *testing.T) {
	kekInfo := &configpb.KekInfo{
		KekType: &configpb.KekInfo_KekUri{
			KekUri: testKEKURI,
		},
	}

	shamirConfig := configpb.ShamirConfig{
		Threshold: 2,
		Shares:    3,
	}

	keyConfig := configpb.KeyConfig{
		KekInfos:              []*configpb.KekInfo{kekInfo, kekInfo, kekInfo},
		DekAlgorithm:          configpb.DekAlgorithm_AES256_GCM,
		KeySplittingAlgorithm: &configpb.KeyConfig_Shamir{&shamirConfig},
	}

	encryptConfig := configpb.EncryptConfig{
		KeyConfig: &keyConfig,
	}

	decryptConfig := &configpb.DecryptConfig{
		KeyConfigs: []*configpb.KeyConfig{&keyConfig},
	}

	plaintext := []byte("This is data to be encrypted.")

	ctx := context.Background()
	fakeKMSClient := &fakeKeyManagementClient{
		getCryptoKeyFunc: func(_ context.Context, req *kmsspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
			return createEnabledCryptoKey(kmsrpb.ProtectionLevel_SOFTWARE), nil
		},
	}
	var stetClient StetClient
	stetClient.setFakeKeyManagementClient(fakeKMSClient)
	stetClient.setFakeSecureSessionClient(&fakeSecureSessionClient{})

	blobIDs := []string{}

	for i := 0; i < 2; i++ {
		data, err := stetClient.Encrypt(ctx, plaintext, &encryptConfig, &configpb.AsymmetricKeys{}, "")
		if err != nil {
			t.Fatalf("Encrypt expected to succeed, but failed with: %v", err.Error())
		}

		if data.Metadata.GetBlobId() == "" {
			t.Fatalf("Expected Encrypt to fill in blob ID with UUID")
		}

		// Decrypt to ensure the data can still be decrypted based on the blob ID in the metadata.
		decryptedData, err := stetClient.Decrypt(ctx, data, decryptConfig, &configpb.AsymmetricKeys{})
		if err != nil {
			t.Fatalf("Error decrypting data: %v", err)
		}

		if decryptedData.BlobID != data.Metadata.GetBlobId() {
			t.Fatalf("Decrypted data does not contain the expected blob ID. Got %v, want %v", decryptedData.BlobID, data.Metadata.GetBlobId())
		}

		blobIDs = append(blobIDs, data.Metadata.GetBlobId())
	}

	if blobIDs[0] == blobIDs[1] {
		t.Fatal("Generated the same blob ID for distinct Encrypt calls")
	}
}

func TestUnwrapKMSShareSucceeds(t *testing.T) {
	expectedShare := []byte("Google, let me into the office for fooooddd")
	testCases := []struct {
		name    string
		kekName string
	}{
		{
			name:    "HSM",
			kekName: testHSMKEKName,
		},
		{
			name:    "Software",
			kekName: testSoftwareKEKName,
		},
	}

	ctx := context.Background()
	kmsClient := &fakeKeyManagementClient{}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			wrappedShare := fakeKMSWrap(expectedShare, testCase.kekName)
			unwrappedShare, err := unwrapKMSShare(ctx, kmsClient, wrappedShare, testCase.kekName)
			if err != nil {
				t.Fatalf("unwrapKMSShare(ctx, kmsClient, %v, %v) = %v error, want nil error", wrappedShare, testCase.kekName, err)
			}
			if !bytes.Equal(unwrappedShare, expectedShare) {
				t.Errorf("unwrapKMSShare(ctx, kmsClient, %v, %v) = %v, want %v", wrappedShare, testCase.kekName, unwrappedShare, expectedShare)
			}
		})
	}
}

func TestUnwrapKMSShareFails(t *testing.T) {
	plaintext := []byte("Plaintext")
	testCases := []struct {
		name            string
		decryptResponse *kmsspb.DecryptResponse
		decryptError    error
	}{
		{
			name: "Plaintext corrupted",
			decryptResponse: &kmsspb.DecryptResponse{
				Plaintext:       []byte("Plaintext"),
				PlaintextCrc32C: wrapperspb.Int64(10),
			},
			decryptError: nil,
		},
		{
			name:            "Error from decrypt",
			decryptResponse: nil,
			decryptError:    errors.New("Service unavailable"),
		},
	}

	ctx := context.Background()

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			kmsClient := &fakeKeyManagementClient{
				decryptFunc: func(_ context.Context, _ *kmsspb.DecryptRequest, _ ...gax.CallOption) (*kmsspb.DecryptResponse, error) {
					return testCase.decryptResponse, testCase.decryptError
				},
			}

			_, err := unwrapKMSShare(ctx, kmsClient, plaintext, testKEKName)

			if err == nil {
				t.Errorf("unwrapKMSShare(ctx, kmsClient, %v, %v) = nil error, want error", plaintext, testKEKName)
			}
		})
	}
}

// Tests Decrypt with various error cases.
func TestDecryptErrors(t *testing.T) {
	ciphertext := []byte("I am ciphertext.")

	shamirConfig := configpb.ShamirConfig{
		Threshold: 2,
		Shares:    2,
	}

	kekInfos := []*configpb.KekInfo{
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{
				KekUri: testKEKURI,
			},
		},
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{
				KekUri: testKEKURI,
			},
		},
	}

	// Create test shares and corresponding hashes.
	testShare := []byte("I am a wrapped share.")
	testHashedShare := HashShare(testShare)
	testInvalidHashedShare := HashShare([]byte("I am a different share."))

	wrapped := &configpb.WrappedShare{
		Share: append(testShare, byte('E')),
		Hash:  testHashedShare,
	}

	// Create test KeyConfig and unknown KeyConfig.
	keyCfg := configpb.KeyConfig{
		KekInfos:              kekInfos,
		DekAlgorithm:          configpb.DekAlgorithm_AES256_GCM,
		KeySplittingAlgorithm: &configpb.KeyConfig_Shamir{&shamirConfig},
	}

	missingKeyCfg := configpb.KeyConfig{
		KekInfos:              kekInfos,
		DekAlgorithm:          configpb.DekAlgorithm_UNKNOWN,
		KeySplittingAlgorithm: &configpb.KeyConfig_Shamir{&shamirConfig},
	}

	singleURIKeyCfg := configpb.KeyConfig{
		KekInfos: []*configpb.KekInfo{&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{
				KekUri: testKEKURI,
			},
		}},
		DekAlgorithm:          configpb.DekAlgorithm_AES256_GCM,
		KeySplittingAlgorithm: &configpb.KeyConfig_Shamir{&shamirConfig},
	}

	decryptCfg := configpb.DecryptConfig{
		KeyConfigs: []*configpb.KeyConfig{&keyCfg},
	}

	testCases := []struct {
		name      string
		data      *configpb.EncryptedData
		config    *configpb.DecryptConfig
		errSubstr string
	}{
		{
			name: "Missing matching KeyConfig during decryption",
			data: &configpb.EncryptedData{
				Ciphertext: ciphertext,
				Metadata: &configpb.Metadata{
					Shares:    []*configpb.WrappedShare{wrapped},
					BlobId:    "I am blob.",
					KeyConfig: &missingKeyCfg,
				},
			},
			config:    &decryptCfg,
			errSubstr: "KeyConfig",
		},
		{
			name: "Mismatched wrapped and hashed shares",
			data: &configpb.EncryptedData{
				Ciphertext: ciphertext,
				Metadata: &configpb.Metadata{
					Shares: []*configpb.WrappedShare{{
						Share: testShare,
						Hash:  testInvalidHashedShare,
					}, wrapped},
					BlobId:    "I am blob.",
					KeyConfig: &keyCfg,
				},
			},
			config:    &decryptCfg,
			errSubstr: "unwrapped share",
		},
		{
			name: "Too few shares for recombining DEK",
			data: &configpb.EncryptedData{
				Ciphertext: ciphertext,
				Metadata: &configpb.Metadata{
					Shares:    []*configpb.WrappedShare{wrapped},
					BlobId:    "I am blob.",
					KeyConfig: &singleURIKeyCfg,
				},
			},
			config: &configpb.DecryptConfig{
				KeyConfigs: []*configpb.KeyConfig{&singleURIKeyCfg},
			},
			errSubstr: "combining",
		},
	}

	ctx := context.Background()
	fakeKMSClient := &fakeKeyManagementClient{
		getCryptoKeyFunc: func(_ context.Context, req *kmsspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
			return createEnabledCryptoKey(kmsrpb.ProtectionLevel_SOFTWARE), nil
		},
	}
	var stetClient StetClient
	stetClient.setFakeKeyManagementClient(fakeKMSClient)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := stetClient.Decrypt(ctx, tc.data, tc.config, &configpb.AsymmetricKeys{}); err == nil {
				t.Errorf("Got no error, want error related to %q.", tc.errSubstr)
			}
		})
	}
}
