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
	"io/ioutil"
	"os"
	"testing"

	"github.com/GoogleCloudPlatform/stet/client/cloudkms"
	confspace "github.com/GoogleCloudPlatform/stet/client/confidentialspace"
	"github.com/GoogleCloudPlatform/stet/client/shares"
	"github.com/GoogleCloudPlatform/stet/client/testutil"
	"github.com/google/go-cmp/cmp"
	"github.com/google/tink/go/subtle/random"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	kmsrpb "cloud.google.com/go/kms/apiv1/kmspb"
	kmsspb "cloud.google.com/go/kms/apiv1/kmspb"
	configpb "github.com/GoogleCloudPlatform/stet/proto/config_go_proto"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

func TestParseEKMKeyURI(t *testing.T) {
	keyURI := "https://test.ekm.io/endpoints/123456"
	expectedAddr := "https://test.ekm.io"
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

func TestGetKekCryptoKey(t *testing.T) {
	ctx := context.Background()

	testcases := []struct {
		name    string
		testKEK *testutil.KEK
	}{
		{
			name:    "HSM Protection Level",
			testKEK: testutil.HSMKEK,
		},
		{
			name:    "Software Protection Level",
			testKEK: testutil.SoftwareKEK,
		},
		{
			name:    "External Protection Level",
			testKEK: testutil.ExternalKEK,
		},
		{
			name:    "External VPC Protection Level",
			testKEK: testutil.VPCKEK,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			kmsClient := &testutil.FakeKeyManagementClient{
				GetCryptoKeyFunc: func(_ context.Context, req *kmsspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
					if req.GetName() != tc.testKEK.Name {
						t.Fatalf("GetCryptoKey called with unexpected name: got %v, want %v", req.GetName(), tc.testKEK.Name)
					}
					ck := testutil.CreateEnabledCryptoKey(tc.testKEK.ProtectionLevel, tc.testKEK.Name)
					return ck, nil
				},
			}

			kekInfo := &configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{KekUri: tc.testKEK.URI()},
			}

			// At this point we're only interested in getKekCryptoKey returning successfully.
			_, err := getKekCryptoKey(ctx, kmsClient, kekInfo)
			if err != nil {
				t.Fatalf("getKekCryptoKey returned with error %v", err)
			}

		})
	}
}

func TestGetKekCryptoKeyRSAFingerprint(t *testing.T) {
	ctx := context.Background()

	kekInfo := &configpb.KekInfo{
		KekType: &configpb.KekInfo_RsaFingerprint{RsaFingerprint: testPublicFingerprint},
	}

	kmsClient := &testutil.FakeKeyManagementClient{
		GetCryptoKeyFunc: func(_ context.Context, req *kmsspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
			t.Fatalf("This should not be called.")
			return nil, nil
		},
	}

	if _, err := getKekCryptoKey(ctx, kmsClient, kekInfo); err == nil {
		t.Errorf("getKekCryptoKey returned successful, expect error.")
	}
}

func TestGetKekCryptoKeyErrors(t *testing.T) {
	ctx := context.Background()
	validKekInfo := &configpb.KekInfo{
		KekType: &configpb.KekInfo_KekUri{KekUri: testutil.SoftwareKEK.URI()},
	}

	testCases := []struct {
		name              string
		fakeKmsClient     *testutil.FakeKeyManagementClient
		kekInfo           *configpb.KekInfo
		expectedErrSubstr string
	}{
		{
			name: "GetCryptoKey returns error",
			fakeKmsClient: &testutil.FakeKeyManagementClient{
				GetCryptoKeyFunc: func(_ context.Context, req *kmsspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
					return nil, errors.New("this is an error from GetCryptoKey")
				},
			},
			kekInfo:           validKekInfo,
			expectedErrSubstr: "retrieving key metadata",
		},
		{
			name: "Primary GetCryptoKeyVersion is not enabled",
			fakeKmsClient: &testutil.FakeKeyManagementClient{
				GetCryptoKeyFunc: func(_ context.Context, req *kmsspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
					return &kmsrpb.CryptoKey{
						Primary: &kmsrpb.CryptoKeyVersion{
							Name:            "projects/test/locations/test/keyRings/test/cryptoKeys/test/cryptoKeyVersions/test",
							State:           kmsrpb.CryptoKeyVersion_DISABLED,
							ProtectionLevel: kmsrpb.ProtectionLevel_SOFTWARE,
						},
					}, nil
				},
			},
			kekInfo:           validKekInfo,
			expectedErrSubstr: "not enabled",
		},
		{
			name: "Unspecified protection level",
			fakeKmsClient: &testutil.FakeKeyManagementClient{
				GetCryptoKeyFunc: func(_ context.Context, req *kmsspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
					return testutil.CreateEnabledCryptoKey(kmsrpb.ProtectionLevel_PROTECTION_LEVEL_UNSPECIFIED, "unspecified/uri"), nil
				},
			},
			kekInfo:           validKekInfo,
			expectedErrSubstr: "unspecified protection level",
		},
		{
			name:          "KEK URI lacks GCP KMS identifying prefix",
			fakeKmsClient: &testutil.FakeKeyManagementClient{},
			kekInfo: &configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{
					KekUri: "invalid uri",
				},
			},
			expectedErrSubstr: "expected URI prefix",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := getKekCryptoKey(ctx, testCase.fakeKmsClient, testCase.kekInfo)

			if err == nil {
				t.Errorf("getKekMetadata returned no error, expected error related to \"%s\"", testCase.expectedErrSubstr)
			}
		})
	}
}

func TestExternalKEKMetadata(t *testing.T) {
	cryptoKey := &kmsrpb.CryptoKey{
		Primary: &kmsrpb.CryptoKeyVersion{
			State:           kmsrpb.CryptoKeyVersion_ENABLED,
			ProtectionLevel: kmsrpb.ProtectionLevel_EXTERNAL,
			ExternalProtectionLevelOptions: &kmsrpb.ExternalProtectionLevelOptions{
				ExternalKeyUri: testutil.ExternalEKMURI,
			},
		},
	}

	kekInfo := &configpb.KekInfo{
		KekType: &configpb.KekInfo_KekUri{KekUri: testutil.ExternalKEK.URI()},
	}

	expectedMD := &kekMetadata{
		protectionLevel: kmsrpb.ProtectionLevel_EXTERNAL,
		uri:             testutil.ExternalEKMURI,
		resourceName:    testutil.ExternalKEK.Name,
	}

	md, err := externalKEKMetadata(cryptoKey, kekInfo)
	if err != nil {
		t.Fatalf("getKekMetadata returned error: %v", err)
	}

	if !cmp.Equal(md, expectedMD, cmp.AllowUnexported(kekMetadata{})) {
		t.Errorf("getKekMetadata returned wrapped share. Got %v, want %v", md, expectedMD)
	}
}

func TestExternalKEKMetadataError(t *testing.T) {
	cryptoKey := &kmsrpb.CryptoKey{
		Primary: &kmsrpb.CryptoKeyVersion{
			State:           kmsrpb.CryptoKeyVersion_ENABLED,
			ProtectionLevel: kmsrpb.ProtectionLevel_SOFTWARE,
		},
	}

	kekInfo := &configpb.KekInfo{
		KekType: &configpb.KekInfo_KekUri{KekUri: testutil.ExternalKEK.URI()},
	}

	_, err := externalKEKMetadata(cryptoKey, kekInfo)
	if err == nil {
		t.Errorf("getKekMetadata returned successfully, expected error")
	}
}

func TestEkmSecureSessionWrap(t *testing.T) {
	ctx := context.Background()
	plaintext := []byte("this is plaintext")
	md := kekMetadata{uri: testutil.ExternalKEK.URI()}
	expectedCiphertext := append(plaintext, byte('E'))

	stetClient := &StetClient{testSecureSessionClient: &testutil.FakeSecureSessionClient{}}

	ciphertext, err := stetClient.ekmSecureSessionWrap(ctx, plaintext, md, nil)
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
		fakeEkmClient     *testutil.FakeSecureSessionClient
		expectedErrSubstr string
	}{
		{
			name: "ConfidentialWrap returns error",
			fakeEkmClient: &testutil.FakeSecureSessionClient{
				WrapErr: errors.New("this is an error from ConfidentialWrap"),
			},
			expectedErrSubstr: "wrapping",
		},
		{
			name: "EndSession returns error",
			fakeEkmClient: &testutil.FakeSecureSessionClient{
				EndSessionErr: errors.New("this is an error from EndSession"),
			},
			expectedErrSubstr: "ending secure session",
		},
	}

	for _, testCase := range testCases {
		stetClient := &StetClient{testSecureSessionClient: testCase.fakeEkmClient}

		_, err := stetClient.ekmSecureSessionWrap(ctx, []byte("this is plaintext"), kekMetadata{uri: "this is a uri"}, nil)
		if err == nil {
			t.Errorf("ekmSecureSessionWrap(context.Background, \"this is plaintext\", \"this is a uri\") returned no error, expected to return error related to %s", testCase.expectedErrSubstr)
		}
	}
}

func TestEkmSecureSessionUnwrap(t *testing.T) {
	ctx := context.Background()
	expectedPlaintext := []byte("this is plaintext")
	md := kekMetadata{uri: testutil.ExternalKEK.URI()}
	ciphertext := append(expectedPlaintext, byte('E'))

	stetClient := &StetClient{testSecureSessionClient: &testutil.FakeSecureSessionClient{}}

	plaintext, err := stetClient.ekmSecureSessionUnwrap(ctx, ciphertext, md, nil)
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
		fakeEkmClient     *testutil.FakeSecureSessionClient
		expectedErrSubstr string
	}{
		{
			name: "ConfidentialUnwrap returns error",
			fakeEkmClient: &testutil.FakeSecureSessionClient{
				UnwrapErr: errors.New("this is an error from ConfidentialUnwrap"),
			},
			expectedErrSubstr: "wrapping",
		},
		{
			name: "EndSession returns error",
			fakeEkmClient: &testutil.FakeSecureSessionClient{
				EndSessionErr: errors.New("this is an error from EndSession"),
			},
			expectedErrSubstr: "ending secure session",
		},
	}

	for _, testCase := range testCases {
		stetClient := &StetClient{testSecureSessionClient: testCase.fakeEkmClient}

		_, err := stetClient.ekmSecureSessionUnwrap(ctx, []byte("this is ciphertext"), kekMetadata{uri: testutil.ExternalKEK.URI()}, nil)
		if err == nil {
			t.Errorf("ekmSecureSessionUnwrap(context.Background, \"this is ciphertext\", %v) returned no error, expected to return error related to %s", testutil.ExternalKEK.URI(), testCase.expectedErrSubstr)
		}
	}
}

func TestWrapSharesIndividually(t *testing.T) {
	testShare := []byte("I am a wrapped share.")
	testHashedShare := shares.HashShare(testShare)

	testCases := []struct {
		name            string
		uri             string
		protectionLevel kmsrpb.ProtectionLevel
		expectedWrap    []byte
	}{
		{
			name:            "Software Protection Level",
			uri:             testutil.SoftwareKEK.URI(),
			protectionLevel: kmsrpb.ProtectionLevel_SOFTWARE,
			expectedWrap:    testutil.FakeKMSWrap(testShare, testutil.SoftwareKEK.Name),
		},
		{
			name:            "Hardware Protection Level",
			uri:             testutil.HSMKEK.URI(),
			protectionLevel: kmsrpb.ProtectionLevel_HSM,
			expectedWrap:    testutil.FakeKMSWrap(testShare, testutil.HSMKEK.Name),
		},
		{
			name:            "External Protection Level",
			uri:             testutil.ExternalKEK.URI(),
			protectionLevel: kmsrpb.ProtectionLevel_EXTERNAL,
			expectedWrap:    append(testShare, byte('E')),
		},
	}

	ctx := context.Background()

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			stetClient := &StetClient{
				testKMSClients: &cloudkms.ClientFactory{
					CredsMap: map[string]cloudkms.Client{"": &testutil.FakeKeyManagementClient{}},
				},
				testSecureSessionClient: &testutil.FakeSecureSessionClient{},
			}

			ki := []*configpb.KekInfo{
				&configpb.KekInfo{
					KekType: &configpb.KekInfo_KekUri{
						KekUri: testCase.uri,
					},
				},
			}

			opts := sharesOpts{kekInfos: ki, asymmetricKeys: &configpb.AsymmetricKeys{}}
			wrappedShares, _, err := stetClient.wrapShares(ctx, [][]byte{testShare}, opts)

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
	testHashedShare := shares.HashShare(testShare)

	ctx := context.Background()

	ki := []*configpb.KekInfo{
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_RsaFingerprint{RsaFingerprint: testPublicFingerprint},
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
	opts := sharesOpts{kekInfos: ki, asymmetricKeys: keys}
	wrappedShares, keyURIs, err := stetClient.wrapShares(ctx, [][]byte{testShare}, opts)

	if err != nil {
		t.Fatalf("wrapShares returned with error: %v", err)
	}

	if len(wrappedShares) != 1 {
		t.Fatalf("wrapShares(ctx, %s, %v) did not return the expected number of shares. Got %v, want 1", testShare, ki, len(wrappedShares))
	}

	if !bytes.Equal(wrappedShares[0].GetHash(), testHashedShare[:]) {
		t.Errorf("wrapShares(ctx, %s, %v) did not return the expected hashed share. Got %v, want %v", testShare, ki, wrappedShares[0].GetHash(), testHashedShare)
	}

	if len(keyURIs) != 0 {
		t.Fatalf("wrapShares(ctx, %s, %v) expected to return 0 key URIs, got %v", testShare, ki, len(keyURIs))
	}

	unwrappedShares, err := stetClient.unwrapAndValidateShares(ctx, wrappedShares, opts)

	if err != nil {
		t.Fatalf("unwrapAndValidateShares returned with error: %v", err)
	}

	if len(unwrappedShares) != 1 {
		t.Fatalf("unwrapAndValidateShares(ctx, %s, %v, %v) did not return the expected number of shares. Got %v, want 1", wrappedShares, ki, keys, len(unwrappedShares))
	}

	if !bytes.Equal(unwrappedShares[0].Share, testShare) {
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
			opts := sharesOpts{kekInfos: testCase.kekInfos, asymmetricKeys: testCase.asymmetricKeys}
			wrappedShares, _, err := stetClient.wrapShares(ctx, testCase.unwrappedShares, opts)

			if err == nil && testCase.errorOnWrap {
				t.Errorf("wrapShares(%s, %s) expected to return error, but did not", testCase.unwrappedShares, testCase.kekInfos)
			}

			_, err = stetClient.unwrapAndValidateShares(ctx, wrappedShares, opts)

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
			KekType: &configpb.KekInfo_KekUri{KekUri: testutil.SoftwareKEK.URI()},
		},
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{KekUri: testutil.HSMKEK.URI()},
		},
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{KekUri: testutil.ExternalKEK.URI()},
		},
	}
	wrappedSharesList := [][]byte{
		testutil.FakeKMSWrap(sharesList[0], testutil.SoftwareKEK.Name),
		testutil.FakeKMSWrap(sharesList[1], testutil.HSMKEK.Name),
		append(sharesList[2], byte('E')),
	}
	ctx := context.Background()

	expectedURIs := []string{testutil.SoftwareKEK.URI(), testutil.HSMKEK.URI(), testutil.ExternalEKMURI}

	stetClient := &StetClient{
		testKMSClients: &cloudkms.ClientFactory{
			CredsMap: map[string]cloudkms.Client{"": &testutil.FakeKeyManagementClient{}},
		},
		testSecureSessionClient: &testutil.FakeSecureSessionClient{},
	}

	wrapOpts := sharesOpts{kekInfos: kekInfoList, asymmetricKeys: &configpb.AsymmetricKeys{}}
	wrapped, uris, err := stetClient.wrapShares(ctx, sharesList, wrapOpts)

	if err != nil {
		t.Fatalf("wrapShares(%s, %s) returned with error %v", sharesList, kekInfoList, err)
	}

	if len(wrapped) != len(sharesList) {
		t.Fatalf("wrapShares(%s, %s) did not return the expected number of shares. Got %v, want %v", sharesList, kekInfoList, len(wrapped), len(sharesList))
	}

	if len(uris) != len(expectedURIs) {
		t.Errorf("wrapShares(%s, %s) did not return the expected URIs. Got %v, want %v", sharesList, kekInfoList, len(uris), len(expectedURIs))
	}

	for i, w := range wrapped {
		if !bytes.Equal(w.GetShare(), wrappedSharesList[i]) {
			t.Errorf("wrapShares(%s, %s) did not return the expected wrapped share for share %v. Got %v, want %v", sharesList, kekInfoList, sharesList[i], w.GetShare(), wrappedSharesList[i])
		}

		if uris[i] != expectedURIs[i] {
			t.Errorf("wrapShares(%s, %s) did not return the expected URI for share %v. Got %v, want %v", sharesList, kekInfoList, sharesList[i], uris[i], expectedURIs[i])
		}
	}
}

func TestWrapSharesWithConfidentialSpace(t *testing.T) {
	ctx := context.Background()
	tokenFile := testutil.CreateTempTokenFile(t)

	// Define three test KEKs, each of which should map to a different KMS client.
	keks := []struct {
		kekURI         string
		plaintext      []byte
		expectedSuffix []byte
	}{
		{"gcp-kms://test-kek-0", []byte("Share 0"), []byte("-with-credentials")},
		{"gcp-kms://test-kek-1", []byte("Share 1"), []byte("-wip-only-credentials")},
		{"gcp-kms://test-kek-2", []byte("Share 2"), []byte("-no-credentials")},
	}

	// Define credentials for only the KEKs that require them.
	csProto := &configpb.ConfidentialSpaceConfigs{
		KekCredentials: []*configpb.KekCredentialConfig{
			{
				// A set of credentials.
				KekUriPattern:  keks[0].kekURI,
				WipName:        "test WIP name",
				ServiceAccount: "test@system.gserviceaccount.com",
			},
			{
				// Same credentials, but without service account.
				KekUriPattern: keks[1].kekURI,
				WipName:       "test WIP name",
			},
		},
	}

	createFakeKMSClient := func(index int) *testutil.FakeKeyManagementClient {
		return &testutil.FakeKeyManagementClient{
			GetCryptoKeyFunc: func(_ context.Context, req *kmsspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
				return &kmsrpb.CryptoKey{
					Primary: &kmsrpb.CryptoKeyVersion{
						Name:            req.GetName(),
						State:           kmsrpb.CryptoKeyVersion_ENABLED,
						ProtectionLevel: kmsrpb.ProtectionLevel_SOFTWARE,
					},
				}, nil
			},
			EncryptFunc: func(_ context.Context, req *kmsspb.EncryptRequest, _ ...gax.CallOption) (*kmsspb.EncryptResponse, error) {
				wrappedShare := append(req.GetPlaintext(), keks[index].expectedSuffix...)

				return &kmsspb.EncryptResponse{
					Name:                    req.GetName(),
					Ciphertext:              wrappedShare,
					CiphertextCrc32C:        wrapperspb.Int64(int64(testutil.CRC32C(wrappedShare))),
					VerifiedPlaintextCrc32C: true,
				}, nil
			},
		}
	}

	// Define a fake Client for each KEK credentials (including no credentials).
	kmsClients := cloudkms.ClientFactory{
		CredsMap: map[string]cloudkms.Client{
			confspace.CreateJSONCredentials(csProto.GetKekCredentials()[0], tokenFile): createFakeKMSClient(0),
			confspace.CreateJSONCredentials(csProto.GetKekCredentials()[1], tokenFile): createFakeKMSClient(1),
			"": createFakeKMSClient(2),
		},
	}

	var kekInfos []*configpb.KekInfo
	var shares [][]byte
	for i := 0; i < len(keks); i++ {
		shares = append(shares, keks[i].plaintext)
		kekInfos = append(kekInfos, &configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{KekUri: keks[i].kekURI},
		})
	}

	client := &StetClient{testKMSClients: &kmsClients}

	opts := sharesOpts{
		kekInfos:        kekInfos,
		asymmetricKeys:  &configpb.AsymmetricKeys{},
		confSpaceConfig: confspace.NewConfigWithTokenFile(csProto, tokenFile),
	}
	wrappedShares, keyURIs, err := client.wrapShares(ctx, shares, opts)
	if err != nil {
		t.Fatalf("wrapShares returned with error %v", err)
	}
	if len(keyURIs) != len(shares) {
		t.Fatalf("wrapShares did not return the expected number of keyURIs. Got %v, want %v", len(keyURIs), len(shares))
	}

	for i := 0; i < len(keks); i++ {
		i := i
		expectedShare := append(shares[i], keks[i].expectedSuffix...)
		if !bytes.Equal(wrappedShares[i].GetShare(), expectedShare) {
			t.Errorf("wrapShares did not return the expected wrapped share for share %v. Got %s, want %s", i, wrappedShares[i].GetShare(), expectedShare)
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
		fakeSSClient      *testutil.FakeSecureSessionClient
		encryptErrReturn  error
		expectedErrSubstr string
	}{
		{
			name:            "GetCryptoKey returns error",
			unwrappedShares: [][]byte{[]byte("I am a wrapped share.")},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{KekUri: testutil.SoftwareKEK.URI()},
			}},
			ckErrReturn:       errors.New("this is an error"),
			encryptErrReturn:  nil,
			expectedErrSubstr: "key metadata",
		},
		{
			name:            "Primary CryptoKeyVersion is not enabled",
			unwrappedShares: [][]byte{[]byte("I am a wrapped share.")},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{KekUri: testutil.SoftwareKEK.URI()},
			}},
			ckReturn: &kmsrpb.CryptoKey{
				Primary: &kmsrpb.CryptoKeyVersion{
					Name:            testutil.SoftwareKEK.Name,
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
				KekType: &configpb.KekInfo_KekUri{KekUri: testutil.SoftwareKEK.URI()},
			}},
			ckReturn:         testutil.CreateEnabledCryptoKey(kmsrpb.ProtectionLevel_PROTECTION_LEVEL_UNSPECIFIED, "I am an invalid protection level!"),
			ckErrReturn:      nil,
			encryptErrReturn: nil, expectedErrSubstr: "protection level",
		},
		{
			name:            "Mismatched numbers of unwrapped shares and kekInfos",
			unwrappedShares: [][]byte{[]byte("I am a wrapped share."), []byte("I am a wrapped share.")},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{KekUri: testutil.SoftwareKEK.URI()},
			}},
			ckReturn:          testutil.CreateEnabledCryptoKey(kmsrpb.ProtectionLevel_SOFTWARE, ""),
			ckErrReturn:       nil,
			fakeSSClient:      &testutil.FakeSecureSessionClient{},
			encryptErrReturn:  nil,
			expectedErrSubstr: "number of shares",
		},
		{
			name:            "protectionLevelsAndUris returns error",
			unwrappedShares: [][]byte{[]byte("I am a wrapped share.")},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{KekUri: "I am an invalid URI!"},
			}},
			ckReturn:          testutil.CreateEnabledCryptoKey(kmsrpb.ProtectionLevel_SOFTWARE, ""),
			ckErrReturn:       nil,
			fakeSSClient:      &testutil.FakeSecureSessionClient{},
			encryptErrReturn:  nil,
			expectedErrSubstr: "retrieving KEK Metadata",
		},
		{
			name:            "ekmSecureSessionWrap returns error",
			unwrappedShares: [][]byte{[]byte("I am a wrapped share.")},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{KekUri: testutil.ExternalKEK.URI()},
			}},
			ckReturn: testutil.CreateEnabledCryptoKey(kmsrpb.ProtectionLevel_EXTERNAL, testutil.ExternalKEK.Name),
			fakeSSClient: &testutil.FakeSecureSessionClient{
				WrapErr: errors.New("this is an error from ConfidentialWrap"),
			},
			expectedErrSubstr: "wrapping with secure session",
		},
		{
			name:            "Encrypt returns an error",
			unwrappedShares: [][]byte{[]byte("I am a wrapped share.")},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{KekUri: testutil.SoftwareKEK.URI()},
			}},
			ckReturn:          testutil.CreateEnabledCryptoKey(kmsrpb.ProtectionLevel_SOFTWARE, testutil.SoftwareKEK.Name),
			ckErrReturn:       nil,
			encryptErrReturn:  errors.New("encrypt error"),
			expectedErrSubstr: "encrypt error",
		},
	}

	ctx := context.Background()

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fakeKMSClient := &testutil.FakeKeyManagementClient{
				GetCryptoKeyFunc: func(_ context.Context, req *kmsspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
					return testCase.ckReturn, testCase.ckErrReturn
				},
				EncryptFunc: func(_ context.Context, req *kmsspb.EncryptRequest, _ ...gax.CallOption) (*kmsspb.EncryptResponse, error) {
					return testutil.ValidEncryptResponse(req), testCase.encryptErrReturn
				},
			}

			stetClient := &StetClient{
				testKMSClients: &cloudkms.ClientFactory{
					CredsMap: map[string]cloudkms.Client{"": fakeKMSClient},
				},
				testSecureSessionClient: testCase.fakeSSClient,
			}
			opts := sharesOpts{kekInfos: testCase.kekInfos, asymmetricKeys: &configpb.AsymmetricKeys{}}
			_, _, err := stetClient.wrapShares(ctx, testCase.unwrappedShares, opts)

			if err == nil {
				t.Errorf("wrapShares(%s, %s) expected to return error, but did not", testCase.unwrappedShares, testCase.kekInfos)
			}
		})
	}
}

func TestUnwrapAndValidateSharesIndividually(t *testing.T) {
	expectedUnwrappedShare := []byte("I am a wrapped share.")
	expectedHashedShare := shares.HashShare(expectedUnwrappedShare)

	testCases := []struct {
		name         string
		uri          string
		wrappedShare []*configpb.WrappedShare
		expectedURI  string
	}{
		{
			name: "Software Protection Level",
			uri:  testutil.SoftwareKEK.URI(),
			wrappedShare: []*configpb.WrappedShare{
				&configpb.WrappedShare{
					Share: testutil.FakeKMSWrap(expectedUnwrappedShare, testutil.SoftwareKEK.Name),
					Hash:  expectedHashedShare,
				},
			},
			expectedURI: testutil.SoftwareKEK.URI(),
		},
		{
			name: "Hardware Protection Level",
			uri:  testutil.HSMKEK.URI(),
			wrappedShare: []*configpb.WrappedShare{
				&configpb.WrappedShare{
					Share: testutil.FakeKMSWrap(expectedUnwrappedShare, testutil.HSMKEK.Name),
					Hash:  expectedHashedShare,
				},
			},
			expectedURI: testutil.HSMKEK.URI(),
		},
		{
			name: "External Protection Level",
			uri:  testutil.ExternalKEK.URI(),
			wrappedShare: []*configpb.WrappedShare{
				&configpb.WrappedShare{
					Share: append(expectedUnwrappedShare, byte('E')),
					Hash:  expectedHashedShare,
				},
			},
			expectedURI: testutil.ExternalEKMURI,
		},
	}

	ctx := context.Background()

	stetClient := &StetClient{
		testKMSClients: &cloudkms.ClientFactory{
			CredsMap: map[string]cloudkms.Client{"": &testutil.FakeKeyManagementClient{}},
		},
		testSecureSessionClient: &testutil.FakeSecureSessionClient{},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			opts := sharesOpts{
				kekInfos: []*configpb.KekInfo{
					&configpb.KekInfo{KekType: &configpb.KekInfo_KekUri{KekUri: testCase.uri}},
				},
				asymmetricKeys: &configpb.AsymmetricKeys{},
			}
			unwrappedShares, err := stetClient.unwrapAndValidateShares(ctx, testCase.wrappedShare, opts)

			if err != nil {
				t.Fatalf("unwrapAndValidateShares returned with error: %v", err)
			}

			if len(unwrappedShares) != len(testCase.wrappedShare) {
				t.Fatalf("unwrapAndValidateShares did not return the expected number of shares. Got %v, want %v", len(unwrappedShares), len(testCase.wrappedShare))
			}

			if unwrappedShares[0].URI != testCase.expectedURI {
				t.Errorf("unwrapAndValidateShares did not return the expected hashed share. Got %v, want %v", unwrappedShares[0].URI, testCase.expectedURI)
			}

			if !bytes.Equal(unwrappedShares[0].Share, expectedUnwrappedShare) {
				t.Errorf("unwrapAndValidateShares did not return the expected unwrapped share. Got %v, want %v", unwrappedShares[0], expectedUnwrappedShare)
			}
		})
	}
}

func TestUnwrapAndValidateSharesWithConfidentialSpace(t *testing.T) {
	ctx := context.Background()
	tokenFile := testutil.CreateTempTokenFile(t)

	// Define three test KEKs, each of which should map to a different KMS client.
	keks := []struct {
		kekURI         string
		ciphertext     []byte
		expectedSuffix []byte
	}{
		{"gcp-kms://test-kek-0", []byte("Share 0"), []byte("-with-credentials")},
		{"gcp-kms://test-kek-1", []byte("Share 1"), []byte("-wip-only-credentials")},
		{"gcp-kms://test-kek-2", []byte("Share 2"), []byte("-no-credentials")},
	}

	// Define credentials for only the KEKs that require them.
	csProto := &configpb.ConfidentialSpaceConfigs{
		KekCredentials: []*configpb.KekCredentialConfig{
			{
				// A set of credentials.
				KekUriPattern:  keks[0].kekURI,
				WipName:        "test WIP name",
				ServiceAccount: "test@system.gserviceaccount.com",
			},
			{
				// Same credentials, but without service account.
				KekUriPattern: keks[1].kekURI,
				WipName:       "test WIP name",
			},
		},
	}

	createFakeKMSClient := func(index int) *testutil.FakeKeyManagementClient {
		return &testutil.FakeKeyManagementClient{
			GetCryptoKeyFunc: func(_ context.Context, req *kmsspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
				return &kmsrpb.CryptoKey{
					Primary: &kmsrpb.CryptoKeyVersion{
						Name:            req.GetName(),
						State:           kmsrpb.CryptoKeyVersion_ENABLED,
						ProtectionLevel: kmsrpb.ProtectionLevel_SOFTWARE,
					},
				}, nil
			},
			DecryptFunc: func(ctx context.Context, req *kmsspb.DecryptRequest, opts ...gax.CallOption) (*kmsspb.DecryptResponse, error) {
				unwrappedShare := append(req.GetCiphertext(), keks[index].expectedSuffix...)

				return &kmsspb.DecryptResponse{
					Plaintext:       unwrappedShare,
					PlaintextCrc32C: wrapperspb.Int64(int64(testutil.CRC32C(unwrappedShare))),
				}, nil
			},
		}
	}

	// Define a fake Client for each KEK credentials (including no credentials).
	kmsClients := cloudkms.ClientFactory{
		CredsMap: map[string]cloudkms.Client{
			confspace.CreateJSONCredentials(csProto.GetKekCredentials()[0], tokenFile): createFakeKMSClient(0),
			confspace.CreateJSONCredentials(csProto.GetKekCredentials()[1], tokenFile): createFakeKMSClient(1),
			"": createFakeKMSClient(2),
		},
	}

	var kekInfos []*configpb.KekInfo
	var wrapped []*configpb.WrappedShare
	for i := 0; i < len(keks); i++ {
		wrapped = append(wrapped, &configpb.WrappedShare{
			Share: keks[i].ciphertext,
			Hash:  shares.HashShare(append(keks[i].ciphertext, keks[i].expectedSuffix...)),
		})
		kekInfos = append(kekInfos, &configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{KekUri: keks[i].kekURI},
		})
	}

	client := &StetClient{testKMSClients: &kmsClients}

	opts := sharesOpts{
		kekInfos:        kekInfos,
		asymmetricKeys:  &configpb.AsymmetricKeys{},
		confSpaceConfig: confspace.NewConfigWithTokenFile(csProto, tokenFile),
	}
	unwrappedShares, err := client.unwrapAndValidateShares(ctx, wrapped, opts)
	if err != nil {
		t.Fatalf("wrapShares returned with error %v", err)
	}

	for i := 0; i < len(keks); i++ {
		i := i
		expectedShare := append(wrapped[i].GetShare(), keks[i].expectedSuffix...)
		if !bytes.Equal(unwrappedShares[i].Share, expectedShare) {
			t.Errorf("wrapShares did not return the expected wrapped share for share %v. Got %s, want %s", i, unwrappedShares[i].Share, expectedShare)
		}
	}
}

func TestUnwrapAndValidateSharesWithMultipleShares(t *testing.T) {
	// Create lists of shares and kekInfos of appropriate length.
	share := []byte("expected unwrapped share")
	shareHash := shares.HashShare(share)
	sharesList := [][]byte{share, share, share}
	kekInfoList := []*configpb.KekInfo{
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{KekUri: testutil.SoftwareKEK.URI()},
		},
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{KekUri: testutil.HSMKEK.URI()},
		},
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{KekUri: testutil.ExternalKEK.URI()},
		},
	}
	wrappedSharesList := []*configpb.WrappedShare{
		{
			Share: testutil.FakeKMSWrap(share, testutil.SoftwareKEK.Name),
			Hash:  shareHash,
		},
		{
			Share: testutil.FakeKMSWrap(share, testutil.HSMKEK.Name),
			Hash:  shareHash,
		},
		{
			Share: append(share, byte('E')),
			Hash:  shareHash,
		},
	}

	ctx := context.Background()

	stetClient := &StetClient{
		testKMSClients: &cloudkms.ClientFactory{
			CredsMap: map[string]cloudkms.Client{"": &testutil.FakeKeyManagementClient{}},
		},

		testSecureSessionClient: &testutil.FakeSecureSessionClient{},
	}

	opts := sharesOpts{kekInfos: kekInfoList, asymmetricKeys: &configpb.AsymmetricKeys{}}
	unwrapped, err := stetClient.unwrapAndValidateShares(ctx, wrappedSharesList, opts)

	if err != nil {
		t.Fatalf("wrapShares returned with error %v", err)
	}

	if len(unwrapped) != len(wrappedSharesList) {
		t.Fatalf("unwrapAndValidateShares(context.Background(), %v, %v) did not return the expected number of shares. Got %v, want %v", wrappedSharesList, kekInfoList, len(unwrapped), len(wrappedSharesList))
	}

	for i, unwrappedShare := range unwrapped {
		if !bytes.Equal(unwrappedShare.Share, sharesList[i]) {
			t.Errorf("unwrapAndValidateShares(context.Background(), %v, %v) did not return the expected wrapped share %v. Got %v, want %v", sharesList, kekInfoList, i, unwrappedShare, sharesList[i])
		}
	}
}

// Because unwrapAndValidateShares() tries unwrapping all shares and doesn't
// fail early, 0 shares returned indicates an error occurred.
func TestUnwrapAndValidateSharesError(t *testing.T) {
	testUnwrappedShare := []byte("I am an unwrapped share")
	testWrappedShare := &configpb.WrappedShare{
		Share: testutil.FakeKMSWrap(testUnwrappedShare, testutil.SoftwareKEK.Name),
		Hash:  shares.HashShare(testUnwrappedShare),
	}

	testCases := []struct {
		name              string
		wrappedShares     []*configpb.WrappedShare
		kekInfos          []*configpb.KekInfo
		fakeSSClient      *testutil.FakeSecureSessionClient
		decryptErrReturn  error
		expectedErrSubstr string
	}{
		{
			name:          "Mismatched numbers of unwrapped shares and KekInfos",
			wrappedShares: []*configpb.WrappedShare{testWrappedShare, testWrappedShare},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{KekUri: testutil.SoftwareKEK.URI()},
			}},
			fakeSSClient:      &testutil.FakeSecureSessionClient{},
			decryptErrReturn:  nil,
			expectedErrSubstr: "number of shares",
		},
		{
			name:          "getProtectionLevelsAndUris returns error",
			wrappedShares: []*configpb.WrappedShare{testWrappedShare},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{KekUri: "I am an invalid URI!"},
			}},
			fakeSSClient:     &testutil.FakeSecureSessionClient{},
			decryptErrReturn: nil,
		},
		{
			name: "Unwrapped share has an invalid hash",
			wrappedShares: []*configpb.WrappedShare{&configpb.WrappedShare{
				Share: testutil.FakeKMSWrap(testUnwrappedShare, testutil.SoftwareKEK.Name),
				Hash:  shares.HashShare([]byte("I am a random different share")),
			}},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{KekUri: testutil.SoftwareKEK.URI()},
			}},
			fakeSSClient:     &testutil.FakeSecureSessionClient{},
			decryptErrReturn: nil,
		},
		{
			name:          "ekmSecureSessionUnwrap with secure session returns error",
			wrappedShares: []*configpb.WrappedShare{testWrappedShare},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{KekUri: testutil.ExternalKEK.URI()},
			}},
			decryptErrReturn: nil,
			fakeSSClient: &testutil.FakeSecureSessionClient{
				UnwrapErr: errors.New("this is an error from ConfidentialUnwrap"),
			},
		},
		{
			name:          "unwrapKMSShare returns error",
			wrappedShares: []*configpb.WrappedShare{testWrappedShare},
			kekInfos: []*configpb.KekInfo{&configpb.KekInfo{
				KekType: &configpb.KekInfo_KekUri{KekUri: testutil.SoftwareKEK.URI()},
			}},
			decryptErrReturn: errors.New("service unavailable"),
		},
	}

	ctx := context.Background()

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fakeKmsClient := &testutil.FakeKeyManagementClient{
				DecryptFunc: func(_ context.Context, req *kmsspb.DecryptRequest, _ ...gax.CallOption) (*kmsspb.DecryptResponse, error) {
					return testutil.ValidDecryptResponse(req), testCase.decryptErrReturn
				},
			}

			stetClient := &StetClient{
				testKMSClients: &cloudkms.ClientFactory{
					CredsMap: map[string]cloudkms.Client{"": fakeKmsClient},
				},
				testSecureSessionClient: testCase.fakeSSClient,
			}

			opts := sharesOpts{kekInfos: testCase.kekInfos, asymmetricKeys: &configpb.AsymmetricKeys{}}
			shares, err := stetClient.unwrapAndValidateShares(ctx, testCase.wrappedShares, opts)

			if testCase.expectedErrSubstr != "" && err == nil {
				t.Errorf("unwrapAndValidateShares(context.Background(), %s, %s) expected to return error, but did not", testCase.wrappedShares, testCase.kekInfos)
			}

			if len(shares) != 0 {
				t.Errorf("unwrapAndValidateShares(context.Background(), %s, %s) got %v shares, but want 0", testCase.wrappedShares, testCase.kekInfos, len(shares))
			}
		})
	}
}

func TestWrapAndUnwrapWorkflow(t *testing.T) {
	// Create lists of shares and kekInfos of appropriate length.
	sharesList := [][]byte{[]byte("share1"), []byte("share2"), []byte("share3")}
	kekInfoList := []*configpb.KekInfo{
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{KekUri: testutil.SoftwareKEK.URI()},
		},
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{KekUri: testutil.HSMKEK.URI()},
		},
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{KekUri: testutil.ExternalKEK.URI()},
		},
	}

	ctx := context.Background()

	stetClient := &StetClient{
		testKMSClients: &cloudkms.ClientFactory{
			CredsMap: map[string]cloudkms.Client{"": &testutil.FakeKeyManagementClient{}},
		},
		testSecureSessionClient: &testutil.FakeSecureSessionClient{},
	}

	opts := sharesOpts{kekInfos: kekInfoList, asymmetricKeys: &configpb.AsymmetricKeys{}}
	wrapped, _, err := stetClient.wrapShares(ctx, sharesList, opts)
	if err != nil {
		t.Fatalf("wrapShares(context.Background(), %v, %v, {}) returned with error %v", sharesList, kekInfoList, err)
	}

	unwrapped, err := stetClient.unwrapAndValidateShares(ctx, wrapped, opts)
	if err != nil {
		t.Errorf("unwrapAndValidateShares(context.Background(), %v, %v, {}) returned with error %v", wrapped, kekInfoList, err)
	}

	if len(wrapped) != len(unwrapped) {
		t.Fatalf("wrapShares returned %v shares, unwrapAndValidateShares returned %v shares. Expected equal numbers.", len(wrapped), len(unwrapped))
	}

	for i, unwrappedShare := range unwrapped {
		if !bytes.Equal(unwrappedShare.Share, sharesList[i]) {
			t.Errorf("unwrapAndValidateShares(context.Background(), %v, %v, {}) = %v, want %v", sharesList, kekInfoList, unwrappedShare, sharesList[i])
		}
	}
}

func TestEncryptAndDecryptWithNoSplitSucceeds(t *testing.T) {
	testBlobID := "I am blob."
	kekInfo := &configpb.KekInfo{
		KekType: &configpb.KekInfo_KekUri{KekUri: testutil.SoftwareKEK.URI()},
	}

	keyConfig := &configpb.KeyConfig{
		KekInfos:              []*configpb.KekInfo{kekInfo},
		DekAlgorithm:          configpb.DekAlgorithm_AES256_GCM,
		KeySplittingAlgorithm: &configpb.KeyConfig_NoSplit{true},
	}

	stetConfig := &configpb.StetConfig{
		EncryptConfig:  &configpb.EncryptConfig{KeyConfig: keyConfig},
		DecryptConfig:  &configpb.DecryptConfig{KeyConfigs: []*configpb.KeyConfig{keyConfig}},
		AsymmetricKeys: &configpb.AsymmetricKeys{},
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

	stetClient := &StetClient{
		testKMSClients: &cloudkms.ClientFactory{
			CredsMap: map[string]cloudkms.Client{"": &testutil.FakeKeyManagementClient{}},
		},
		testSecureSessionClient: &testutil.FakeSecureSessionClient{},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			plaintextBuf := bytes.NewReader(tc.plaintext)

			var ciphertextBuf bytes.Buffer
			if _, err := stetClient.Encrypt(ctx, plaintextBuf, &ciphertextBuf, stetConfig, testBlobID); err != nil {
				t.Errorf("Encrypt(ctx, %v, buf, %v, {}, %v) returned error \"%v\", want no error", tc.plaintext, stetConfig.GetEncryptConfig(), testBlobID, err)
			}

			// Decrypt the returned data and verify fields.
			var output bytes.Buffer
			decryptedMd, err := stetClient.Decrypt(ctx, &ciphertextBuf, &output, stetConfig)
			if err != nil {
				t.Fatalf("Error calling client.Decrypt(ctx, buf, buf, %v, {}): %v", stetConfig.GetDecryptConfig(), err)
			}

			if decryptedMd.BlobID != testBlobID {
				t.Errorf("Decrypt(ctx, input, output, %v, {}) does not contain the expected blob ID. Got %v, want %v", stetConfig.GetDecryptConfig(), decryptedMd.BlobID, testBlobID)
			}

			if len(decryptedMd.KeyUris) != len(keyConfig.GetKekInfos()) {
				t.Fatalf("Decrypt(ctx, input, output, %v, {}) does not have the expected number of key URIS. Got %v, want %v", stetConfig.GetDecryptConfig(), len(decryptedMd.KeyUris), len(keyConfig.GetKekInfos()))
			}
			if decryptedMd.KeyUris[0] != kekInfo.GetKekUri() {
				t.Errorf("Decrypt(ctx, input, output, %v, {}) does not contain the expected key URI. Got { %v }, want { %v }", stetConfig.GetDecryptConfig(), decryptedMd.KeyUris[0], kekInfo.GetKekUri())
			}

			if !bytes.Equal(output.Bytes(), tc.plaintext) {
				t.Errorf("Decrypt(ctx, input, output, %v, {}) returned ciphertext that does not match original plaintext. Got %v, want %v.", stetConfig.GetDecryptConfig(), output.Bytes(), tc.plaintext)
			}
		})
	}
}

func TestEncryptFailsForNoSplitWithTooManyKekInfos(t *testing.T) {
	testBlobID := "I am blob."
	kekInfo := &configpb.KekInfo{
		KekType: &configpb.KekInfo_KekUri{KekUri: testutil.SoftwareKEK.URI()},
	}

	keyConfig := configpb.KeyConfig{
		KekInfos:              []*configpb.KekInfo{kekInfo, kekInfo, kekInfo},
		DekAlgorithm:          configpb.DekAlgorithm_AES256_GCM,
		KeySplittingAlgorithm: &configpb.KeyConfig_NoSplit{true},
	}

	stetConfig := &configpb.StetConfig{
		EncryptConfig:  &configpb.EncryptConfig{KeyConfig: &keyConfig},
		AsymmetricKeys: &configpb.AsymmetricKeys{},
	}
	plaintext := []byte("This is data to be encrypted.")

	ctx := context.Background()

	stetClient := &StetClient{
		testKMSClients: &cloudkms.ClientFactory{
			CredsMap: map[string]cloudkms.Client{"": &testutil.FakeKeyManagementClient{}},
		},
		testSecureSessionClient: &testutil.FakeSecureSessionClient{},
	}

	plaintextBuf := bytes.NewReader(plaintext)
	var ciphertextBuf bytes.Buffer
	if _, err := stetClient.Encrypt(ctx, plaintextBuf, &ciphertextBuf, stetConfig, testBlobID); err == nil {
		t.Errorf("Encrypt with no split option and more than one KekInfo in the KeyConfig should return an error")
	}
}

func TestEncryptAndDecryptWithShamirSucceeds(t *testing.T) {
	testBlobID := "I am blob."
	kekInfo := &configpb.KekInfo{
		KekType: &configpb.KekInfo_KekUri{KekUri: testutil.SoftwareKEK.URI()},
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

	stetConfig := &configpb.StetConfig{
		EncryptConfig: &configpb.EncryptConfig{KeyConfig: keyConfig},
		DecryptConfig: &configpb.DecryptConfig{
			KeyConfigs: []*configpb.KeyConfig{keyConfig},
		},
		AsymmetricKeys: &configpb.AsymmetricKeys{},
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
	fakeKMSClient := &testutil.FakeKeyManagementClient{
		GetCryptoKeyFunc: func(_ context.Context, req *kmsspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
			return testutil.CreateEnabledCryptoKey(kmsrpb.ProtectionLevel_SOFTWARE, ""), nil
		},
	}

	stetClient := &StetClient{
		testKMSClients: &cloudkms.ClientFactory{
			CredsMap: map[string]cloudkms.Client{"": fakeKMSClient},
		},
		testSecureSessionClient: &testutil.FakeSecureSessionClient{},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			plaintextBuf := bytes.NewReader(tc.plaintext)
			var ciphertextBuf bytes.Buffer
			if _, err := stetClient.Encrypt(ctx, plaintextBuf, &ciphertextBuf, stetConfig, testBlobID); err != nil {
				t.Fatalf("Encrypt did not complete successfully: %v", err)
			}

			// Decrypt the returned data and verify fields.
			var output bytes.Buffer
			decryptedMd, err := stetClient.Decrypt(ctx, &ciphertextBuf, &output, stetConfig)
			if err != nil {
				t.Fatalf("Error decrypting data: %v", err)
			}

			if decryptedMd.BlobID != testBlobID {
				t.Errorf("Decrypted data does not contain the expected blob ID. Got %v, want %v", decryptedMd.BlobID, testBlobID)
			}

			if !bytes.Equal(output.Bytes(), tc.plaintext) {
				t.Errorf("Decrypted ciphertext does not match original plaintext. Got %v, want %v.", output.Bytes(), tc.plaintext)
			}

			if len(decryptedMd.KeyUris) != len(keyConfig.GetKekInfos()) {
				t.Fatalf("Decrypted data does not have the expected number of key URIS. Got %v, want %v", len(decryptedMd.KeyUris), len(keyConfig.GetKekInfos()))
			}
			if decryptedMd.KeyUris[0] != kekInfo.GetKekUri() {
				t.Errorf("Decrypted data does not contain the expected key URI. Got { %v }, want { %v }", decryptedMd.KeyUris[0], kekInfo.GetKekUri())
			}
		})
	}
}

func TestEncryptFailsForInvalidShamirConfiguration(t *testing.T) {
	testBlobID := "I am blob."
	kekInfo := &configpb.KekInfo{
		KekType: &configpb.KekInfo_KekUri{KekUri: testutil.SoftwareKEK.URI()},
	}

	// Invalid configuration due to threshold exceeding shares.
	shamirConfig := configpb.ShamirConfig{Threshold: 5, Shares: 3}

	keyConfig := configpb.KeyConfig{
		KekInfos:              []*configpb.KekInfo{kekInfo, kekInfo, kekInfo},
		DekAlgorithm:          configpb.DekAlgorithm_AES256_GCM,
		KeySplittingAlgorithm: &configpb.KeyConfig_Shamir{&shamirConfig},
	}

	stetConfig := &configpb.StetConfig{
		EncryptConfig: &configpb.EncryptConfig{
			KeyConfig: &keyConfig,
		},
	}
	plaintext := []byte("This is data to be encrypted.")

	ctx := context.Background()
	fakeKMSClient := &testutil.FakeKeyManagementClient{
		GetCryptoKeyFunc: func(_ context.Context, req *kmsspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
			return testutil.CreateEnabledCryptoKey(kmsrpb.ProtectionLevel_SOFTWARE, ""), nil
		},
	}

	stetClient := &StetClient{
		testKMSClients: &cloudkms.ClientFactory{
			CredsMap: map[string]cloudkms.Client{"": fakeKMSClient},
		},
		testSecureSessionClient: &testutil.FakeSecureSessionClient{},
	}

	plaintextBuf := bytes.NewReader(plaintext)
	var ciphertextBuf bytes.Buffer
	if _, err := stetClient.Encrypt(ctx, plaintextBuf, &ciphertextBuf, stetConfig, testBlobID); err == nil {
		t.Errorf("Encrypt expected to fail due to invalid Shamir's Secret Sharing configuration.")
	}
}

// Ensures Encrypt fills in a random blob ID if not provided in the config.
func TestEncryptGeneratesUUIDForBlobID(t *testing.T) {
	kekInfo := &configpb.KekInfo{
		KekType: &configpb.KekInfo_KekUri{KekUri: testutil.SoftwareKEK.URI()},
	}

	shamirConfig := configpb.ShamirConfig{Threshold: 2, Shares: 3}

	keyConfig := configpb.KeyConfig{
		KekInfos:              []*configpb.KekInfo{kekInfo, kekInfo, kekInfo},
		DekAlgorithm:          configpb.DekAlgorithm_AES256_GCM,
		KeySplittingAlgorithm: &configpb.KeyConfig_Shamir{&shamirConfig},
	}

	stetConfig := &configpb.StetConfig{
		EncryptConfig: &configpb.EncryptConfig{
			KeyConfig: &keyConfig,
		},
		DecryptConfig: &configpb.DecryptConfig{
			KeyConfigs: []*configpb.KeyConfig{&keyConfig},
		},
	}

	plaintext := []byte("This is data to be encrypted.")

	ctx := context.Background()
	fakeKMSClient := &testutil.FakeKeyManagementClient{
		GetCryptoKeyFunc: func(_ context.Context, req *kmsspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
			return testutil.CreateEnabledCryptoKey(kmsrpb.ProtectionLevel_SOFTWARE, ""), nil
		},
	}
	stetClient := &StetClient{
		testKMSClients: &cloudkms.ClientFactory{
			CredsMap: map[string]cloudkms.Client{"": fakeKMSClient},
		},
		testSecureSessionClient: &testutil.FakeSecureSessionClient{},
	}

	blobIDs := []string{}

	for i := 0; i < 2; i++ {
		plaintextBuf := bytes.NewReader(plaintext)

		var ciphertextBuf bytes.Buffer
		encryptedMd, err := stetClient.Encrypt(ctx, plaintextBuf, &ciphertextBuf, stetConfig, "")
		if err != nil {
			t.Fatalf("Encrypt expected to succeed, but failed with: %v", err.Error())
		}

		// Decrypt to ensure the data can still be decrypted based on the blob ID in the metadata.
		var output bytes.Buffer
		decryptedMd, err := stetClient.Decrypt(ctx, &ciphertextBuf, &output, stetConfig)
		if err != nil {
			t.Fatalf("Error decrypting data: %v", err)
		}

		if decryptedMd.BlobID != encryptedMd.BlobID {
			t.Fatalf("Decrypted blob ID doesn't match encrypted blob ID: want %v, got %v", encryptedMd.BlobID, decryptedMd.BlobID)
		}

		blobIDs = append(blobIDs, decryptedMd.BlobID)
	}

	if blobIDs[0] == blobIDs[1] {
		t.Fatal("Generated the same blob ID for distinct Encrypt calls")
	}
}

func TestEncryptFailsWithNilConfig(t *testing.T) {
	var stetClient StetClient

	plaintextBuf := bytes.NewReader([]byte("This is data to be encrypted."))
	var ciphertextBuf bytes.Buffer

	stetConfig := &configpb.StetConfig{EncryptConfig: nil}
	if _, err := stetClient.Encrypt(context.Background(), plaintextBuf, &ciphertextBuf, stetConfig, ""); err == nil {
		t.Errorf("Encrypt expected to fail due to nil EncryptConfig.")
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
			KekType: &configpb.KekInfo_KekUri{KekUri: testutil.SoftwareKEK.URI()},
		},
		&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{KekUri: testutil.SoftwareKEK.URI()},
		},
	}

	// Create test shares and corresponding hashes.
	testShare := []byte("I am a wrapped share.")
	testHashedShare := shares.HashShare(testShare)
	testInvalidHashedShare := shares.HashShare([]byte("I am a different share."))

	wrapped := &configpb.WrappedShare{
		Share: append(testShare, byte('E')),
		Hash:  testHashedShare,
	}

	validKeyCfg := &configpb.KeyConfig{
		KekInfos: []*configpb.KekInfo{&configpb.KekInfo{
			KekType: &configpb.KekInfo_KekUri{KekUri: testutil.SoftwareKEK.URI()},
		}},
		DekAlgorithm:          configpb.DekAlgorithm_AES256_GCM,
		KeySplittingAlgorithm: &configpb.KeyConfig_Shamir{&shamirConfig},
	}

	decryptCfg := configpb.DecryptConfig{
		KeyConfigs: []*configpb.KeyConfig{validKeyCfg},
	}

	testCases := []struct {
		name      string
		metadata  *configpb.Metadata
		config    *configpb.DecryptConfig
		errSubstr string
	}{
		{
			name: "No DecryptConfig passed to Decrypt",
			metadata: &configpb.Metadata{
				Shares: []*configpb.WrappedShare{wrapped},
				BlobId: "I am blob.",
				KeyConfig: &configpb.KeyConfig{
					KekInfos: []*configpb.KekInfo{&configpb.KekInfo{
						KekType: &configpb.KekInfo_KekUri{KekUri: testutil.SoftwareKEK.URI()},
					}},
					DekAlgorithm:          configpb.DekAlgorithm_AES256_GCM,
					KeySplittingAlgorithm: &configpb.KeyConfig_Shamir{&shamirConfig},
				},
			},
			config:    nil,
			errSubstr: "DecryptConfig",
		},
		{
			name: "Missing matching KeyConfig during decryption",
			metadata: &configpb.Metadata{
				Shares: []*configpb.WrappedShare{wrapped},
				BlobId: "I am blob.",
				KeyConfig: &configpb.KeyConfig{
					KekInfos:              kekInfos,
					DekAlgorithm:          configpb.DekAlgorithm_UNKNOWN_DEK_ALGORITHM,
					KeySplittingAlgorithm: &configpb.KeyConfig_Shamir{&shamirConfig},
				},
			},
			config:    &decryptCfg,
			errSubstr: "KeyConfig",
		},
		{
			name: "Mismatched wrapped and hashed shares",
			metadata: &configpb.Metadata{
				Shares: []*configpb.WrappedShare{{
					Share: testShare,
					Hash:  testInvalidHashedShare,
				}, wrapped},
				BlobId:    "I am blob.",
				KeyConfig: validKeyCfg,
			},
			config:    &decryptCfg,
			errSubstr: "unwrapped share",
		},
		{
			name: "Too few shares for recombining DEK",
			metadata: &configpb.Metadata{
				Shares: []*configpb.WrappedShare{wrapped},
				BlobId: "I am blob.",
				KeyConfig: &configpb.KeyConfig{
					KekInfos: []*configpb.KekInfo{&configpb.KekInfo{
						KekType: &configpb.KekInfo_KekUri{KekUri: testutil.SoftwareKEK.URI()},
					}},
					DekAlgorithm:          configpb.DekAlgorithm_AES256_GCM,
					KeySplittingAlgorithm: &configpb.KeyConfig_Shamir{&shamirConfig},
				},
			},
			config: &configpb.DecryptConfig{
				KeyConfigs: []*configpb.KeyConfig{&configpb.KeyConfig{
					KekInfos: []*configpb.KekInfo{&configpb.KekInfo{
						KekType: &configpb.KekInfo_KekUri{KekUri: testutil.SoftwareKEK.URI()},
					}},
					DekAlgorithm:          configpb.DekAlgorithm_AES256_GCM,
					KeySplittingAlgorithm: &configpb.KeyConfig_Shamir{&shamirConfig},
				}},
			},
			errSubstr: "combining",
		},
	}

	ctx := context.Background()
	fakeKMSClient := &testutil.FakeKeyManagementClient{
		GetCryptoKeyFunc: func(_ context.Context, req *kmsspb.GetCryptoKeyRequest, _ ...gax.CallOption) (*kmsrpb.CryptoKey, error) {
			return testutil.CreateEnabledCryptoKey(kmsrpb.ProtectionLevel_SOFTWARE, ""), nil
		},
	}

	stetClient := StetClient{
		testKMSClients: &cloudkms.ClientFactory{CredsMap: map[string]cloudkms.Client{"": fakeKMSClient}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Simulate encryption and write to `input` buffer.
			metadataBytes, err := proto.Marshal(tc.metadata)
			if err != nil {
				t.Fatalf("Failed to marshal metadata bytes: %v", err)
			}

			var input bytes.Buffer
			if err := WriteSTETHeader(&input, len(metadataBytes)); err != nil {
				t.Fatalf("Failed to write STET encrypted file header: %v", err)
			}
			if _, err := input.Write(metadataBytes); err != nil {
				t.Fatalf("Failed to write metadata: %v", err)
			}
			input.Write(ciphertext)

			stetConfig := &configpb.StetConfig{
				DecryptConfig:  tc.config,
				AsymmetricKeys: &configpb.AsymmetricKeys{},
			}

			var output bytes.Buffer
			if _, err := stetClient.Decrypt(ctx, &input, &output, stetConfig); err == nil {
				t.Errorf("Got no error, want error related to %q.", tc.errSubstr)
			}
		})
	}
}

func TestNewConfspaceConfig(t *testing.T) {
	tokenFile := testutil.CreateTempTokenFile(t)
	testStetCfg := &configpb.StetConfig{
		ConfidentialSpaceConfigs: &configpb.ConfidentialSpaceConfigs{
			KekCredentials: []*configpb.KekCredentialConfig{&configpb.KekCredentialConfig{
				KekUriPattern:  "test/kek",
				WipName:        "test-wip",
				ServiceAccount: "testsa@google.com",
			}},
		},
	}
	testCSCfg := confspace.NewConfigWithTokenFile(testStetCfg.GetConfidentialSpaceConfigs(), tokenFile)

	realStetCfg := &configpb.StetConfig{
		ConfidentialSpaceConfigs: &configpb.ConfidentialSpaceConfigs{
			KekCredentials: []*configpb.KekCredentialConfig{&configpb.KekCredentialConfig{
				KekUriPattern:  "real/kek",
				WipName:        "real-wip",
				ServiceAccount: "realsa@google.com",
			}},
		},
	}

	testcases := []struct {
		name        string
		protoConfig *configpb.StetConfig
		testConfig  *confspace.Config
		expected    *confspace.Config
	}{
		{
			name:        "test config",
			protoConfig: realStetCfg,
			testConfig:  testCSCfg,
			expected:    testCSCfg,
		},
		{
			name:        "proto config",
			protoConfig: realStetCfg,
			expected:    confspace.NewConfig(realStetCfg.GetConfidentialSpaceConfigs()),
		},
		{
			name:        "no config",
			protoConfig: nil,
			expected:    nil,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			client := &StetClient{
				testConfspaceConfig: tc.testConfig,
			}

			clientConfig := client.newConfSpaceConfig(tc.protoConfig)

			if diff := cmp.Diff(tc.expected, clientConfig, cmp.AllowUnexported(confspace.Config{}), protocmp.Transform()); diff != "" {
				t.Errorf("NewConfspaceConfig(%v) returned diff (-want +got):\n%s", tc.protoConfig, diff)
			}
		})
	}
}

func TestEnoughUnwrappedShares(t *testing.T) {
	testShare := shares.UnwrappedShare{[]byte("test share"), "test hash"}
	testcases := []struct {
		name      string
		shares    []shares.UnwrappedShare
		config    *configpb.KeyConfig
		expectErr bool
	}{
		{
			name:   "With no split",
			shares: []shares.UnwrappedShare{testShare},
			config: &configpb.KeyConfig{
				KeySplittingAlgorithm: &configpb.KeyConfig_NoSplit{true},
			},
		},
		{
			name:   "With shamir config",
			shares: []shares.UnwrappedShare{testShare, testShare},
			config: &configpb.KeyConfig{
				KeySplittingAlgorithm: &configpb.KeyConfig_Shamir{&configpb.ShamirConfig{Threshold: 2, Shares: 2}},
			},
		},
		{
			name:   "Zero shares",
			shares: []shares.UnwrappedShare{},
			config: &configpb.KeyConfig{
				KeySplittingAlgorithm: &configpb.KeyConfig_NoSplit{true},
			},
			expectErr: true,
		},
		{
			name:   "Less shares than shamir threshold",
			shares: []shares.UnwrappedShare{testShare},
			config: &configpb.KeyConfig{
				KeySplittingAlgorithm: &configpb.KeyConfig_Shamir{&configpb.ShamirConfig{Threshold: 2, Shares: 2}},
			},
			expectErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err := enoughUnwrappedShares(tc.shares, tc.config)

			if (err != nil) != tc.expectErr {
				t.Errorf("enoughWrappedShares did not return expected output: want (err == nil) == %v, got %v", tc.expectErr, err)
			}
		})
	}
}
