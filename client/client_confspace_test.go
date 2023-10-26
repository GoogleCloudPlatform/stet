// Copyright 2023 Google LLC
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
	"fmt"
	"testing"

	rpb "cloud.google.com/go/kms/apiv1/kmspb"
	spb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/GoogleCloudPlatform/stet/client/cloudkms"
	confspace "github.com/GoogleCloudPlatform/stet/client/confidentialspace"
	"github.com/GoogleCloudPlatform/stet/client/testutil"
	configpb "github.com/GoogleCloudPlatform/stet/proto/config_go_proto"
	"github.com/googleapis/gax-go/v2"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

var wrappedSuffix = []byte("_wrapped")

type clientType int

const (
	encryptAndDecrypt clientType = iota
	encryptOnly
	decryptOnly
	errorOnly
)

func createTestKMSClient(t *testing.T, cType clientType) *testutil.FakeKeyManagementClient {
	return &testutil.FakeKeyManagementClient{
		GetCryptoKeyFunc: func(_ context.Context, req *spb.GetCryptoKeyRequest, _ ...gax.CallOption) (*rpb.CryptoKey, error) {
			if cType == errorOnly {
				t.Fatalf("GetCryptoKey should not be called for this client")

				return &rpb.CryptoKey{}, nil
			}

			return &rpb.CryptoKey{
				Primary: &rpb.CryptoKeyVersion{
					Name:            req.GetName(),
					State:           rpb.CryptoKeyVersion_ENABLED,
					ProtectionLevel: rpb.ProtectionLevel_SOFTWARE,
				}}, nil
		},
		EncryptFunc: func(_ context.Context, req *spb.EncryptRequest, _ ...gax.CallOption) (*spb.EncryptResponse, error) {
			if cType == errorOnly || cType == decryptOnly {
				t.Fatalf("Encrypt should not be called for this client")

				return &spb.EncryptResponse{}, nil
			}

			wrappedShare := append(req.GetPlaintext(), wrappedSuffix...)

			return &spb.EncryptResponse{
				Name:                    req.GetName(),
				Ciphertext:              wrappedShare,
				CiphertextCrc32C:        wrapperspb.Int64(int64(testutil.CRC32C(wrappedShare))),
				VerifiedPlaintextCrc32C: true,
			}, nil
		},
		DecryptFunc: func(_ context.Context, req *spb.DecryptRequest, _ ...gax.CallOption) (*spb.DecryptResponse, error) {
			if cType == errorOnly || cType == encryptOnly {
				t.Fatalf("Decrypt should not be called for this client")

				return &spb.DecryptResponse{}, nil
			}

			if !bytes.HasSuffix(req.GetCiphertext(), wrappedSuffix) {
				return nil, fmt.Errorf("not expected ciphertext: got %v, want suffix %v", req.GetCiphertext(), wrappedSuffix)
			}

			plain := bytes.TrimSuffix(req.GetCiphertext(), wrappedSuffix)

			return &spb.DecryptResponse{
				Plaintext:       plain,
				PlaintextCrc32C: wrapperspb.Int64(int64(testutil.CRC32C(plain))),
			}, nil
		},
	}
}

// Test cases where only one set of Confidential Space credentials is in the config.
func TestSingleCreds(t *testing.T) {
	ctx := context.Background()
	tokenFile := testutil.CreateTempTokenFile(t)

	noSplitConfig := &configpb.KeyConfig{
		KekInfos: []*configpb.KekInfo{
			{KekType: &configpb.KekInfo_KekUri{KekUri: testutil.TestConfSpaceKEKURI}},
		},
		DekAlgorithm:          configpb.DekAlgorithm_AES256_GCM,
		KeySplittingAlgorithm: &configpb.KeyConfig_NoSplit{true},
	}

	testcases := []struct {
		name            string
		keyConfig       *configpb.KeyConfig
		credsURIPattern string
		credsMode       configpb.CredentialMode
		credsClient     *testutil.FakeKeyManagementClient // Test client to map to ConfSpace creds.
		defaultClient   *testutil.FakeKeyManagementClient // Test client to map to default creds.
	}{
		{
			name:            "single share with encrypt_and_decrypt_mode",
			keyConfig:       noSplitConfig,
			credsURIPattern: testutil.TestConfSpaceKEKURI,
			credsMode:       configpb.CredentialMode_DEFAULT_ENCRYPT_AND_DECRYPT_MODE,
			credsClient:     createTestKMSClient(t, encryptAndDecrypt),
			defaultClient:   createTestKMSClient(t, errorOnly),
		},
		{
			name:            "single share with encrypt_only_mode",
			keyConfig:       noSplitConfig,
			credsURIPattern: testutil.TestConfSpaceKEKURI,
			credsMode:       configpb.CredentialMode_ENCRYPT_ONLY_MODE,
			credsClient:     createTestKMSClient(t, encryptOnly),
			defaultClient:   createTestKMSClient(t, decryptOnly),
		},
		{
			name:            "single share with decrypt_only_mode",
			keyConfig:       noSplitConfig,
			credsURIPattern: testutil.TestConfSpaceKEKURI,
			credsMode:       configpb.CredentialMode_DECRYPT_ONLY_MODE,
			credsClient:     createTestKMSClient(t, decryptOnly),
			defaultClient:   createTestKMSClient(t, encryptOnly),
		},
		{
			name: "multiple shares using same credentials",
			keyConfig: &configpb.KeyConfig{
				KekInfos: []*configpb.KekInfo{
					{KekType: &configpb.KekInfo_KekUri{KekUri: gcpKeyPrefix + "key/0"}},
					{KekType: &configpb.KekInfo_KekUri{KekUri: gcpKeyPrefix + "key/1"}},
				},
				DekAlgorithm: configpb.DekAlgorithm_AES256_GCM,
				KeySplittingAlgorithm: &configpb.KeyConfig_Shamir{
					&configpb.ShamirConfig{Threshold: 2, Shares: 2},
				},
			},
			credsURIPattern: gcpKeyPrefix + "key/.*",
			credsMode:       configpb.CredentialMode_DEFAULT_ENCRYPT_AND_DECRYPT_MODE,
			credsClient:     createTestKMSClient(t, encryptAndDecrypt),
			defaultClient:   createTestKMSClient(t, errorOnly),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			kekCreds := &configpb.KekCredentialConfig{
				KekUriPattern:  tc.credsURIPattern,
				Mode:           tc.credsMode,
				WipName:        "test-wip",
				ServiceAccount: "testsa@google.com",
			}

			stetConfig := &configpb.StetConfig{
				EncryptConfig:  &configpb.EncryptConfig{KeyConfig: tc.keyConfig},
				DecryptConfig:  &configpb.DecryptConfig{KeyConfigs: []*configpb.KeyConfig{tc.keyConfig}},
				AsymmetricKeys: &configpb.AsymmetricKeys{},
				ConfidentialSpaceConfigs: &configpb.ConfidentialSpaceConfigs{
					KekCredentials: []*configpb.KekCredentialConfig{kekCreds},
				},
			}

			creds := confspace.CreateJSONCredentials(kekCreds, tokenFile)

			stetClient := &StetClient{
				testKMSClients: &cloudkms.ClientFactory{
					CredsMap: map[string]cloudkms.Client{
						creds: tc.credsClient,
						"":    tc.defaultClient,
					},
				},
				testConfspaceConfig:     confspace.NewConfigWithTokenFile(stetConfig.GetConfidentialSpaceConfigs(), tokenFile),
				testSecureSessionClient: &fakeSecureSessionClient{},
			}

			plaintext := "test data"

			var ciphertextBuf bytes.Buffer
			if _, err := stetClient.Encrypt(ctx, bytes.NewReader([]byte(plaintext)), &ciphertextBuf, stetConfig, "I am blob."); err != nil {
				t.Fatalf("Encrypt returned error \"%v\", want no error", err)
			}

			var decrypted bytes.Buffer
			if _, err := stetClient.Decrypt(ctx, &ciphertextBuf, &decrypted, stetConfig); err != nil {
				t.Fatalf("Decrypt returned error: %v", err)
			}

			if decrypted.String() != plaintext {
				t.Errorf("Did not get expected plaintext: got %v, want %v", decrypted.String(), plaintext)
			}
		})
	}
}

// Test cases where only multiple sets of Confidential Space credentials are in the config.
func TestMultipleCreds(t *testing.T) {
	ctx := context.Background()
	tokenFile := testutil.CreateTempTokenFile(t)

	testcases := []struct {
		name           string
		keyConfig      *configpb.KeyConfig
		kekCreds       []*configpb.KekCredentialConfig
		createCredsMap func([]string) map[string]cloudkms.Client
	}{
		{
			name: "multiple shares using different credentials",
			keyConfig: &configpb.KeyConfig{
				KekInfos: []*configpb.KekInfo{
					{KekType: &configpb.KekInfo_KekUri{KekUri: gcpKeyPrefix + "key/0"}},
					{KekType: &configpb.KekInfo_KekUri{KekUri: gcpKeyPrefix + "key/1"}},
				},
				DekAlgorithm: configpb.DekAlgorithm_AES256_GCM,
				KeySplittingAlgorithm: &configpb.KeyConfig_Shamir{
					&configpb.ShamirConfig{Threshold: 2, Shares: 2},
				},
			},
			kekCreds: []*configpb.KekCredentialConfig{
				&configpb.KekCredentialConfig{
					KekUriPattern:  gcpKeyPrefix + "key/0",
					WipName:        "test-wip-0",
					ServiceAccount: "testsa-0@google.com",
				},
				&configpb.KekCredentialConfig{
					KekUriPattern:  gcpKeyPrefix + "key/1",
					WipName:        "test-wip-1",
					ServiceAccount: "testsa-1@google.com",
				},
			},
			createCredsMap: func(creds []string) map[string]cloudkms.Client {
				return map[string]cloudkms.Client{
					creds[0]: createTestKMSClient(t, encryptAndDecrypt),
					creds[1]: createTestKMSClient(t, encryptAndDecrypt),
					"":       createTestKMSClient(t, errorOnly),
				}
			},
		},
		{
			name: "single share only uses first matching credentials",
			keyConfig: &configpb.KeyConfig{
				KekInfos: []*configpb.KekInfo{
					{KekType: &configpb.KekInfo_KekUri{KekUri: gcpKeyPrefix + "key/uri/0"}},
				},
				DekAlgorithm:          configpb.DekAlgorithm_AES256_GCM,
				KeySplittingAlgorithm: &configpb.KeyConfig_NoSplit{true},
			},
			kekCreds: []*configpb.KekCredentialConfig{
				// Config expected to match.
				{
					KekUriPattern:  gcpKeyPrefix + "key/uri/.*",
					WipName:        "foo-wip",
					ServiceAccount: "foosa-@google.com",
				},
				// Also a matching config, but not expected to use.
				{
					KekUriPattern:  gcpKeyPrefix + "key/.*",
					WipName:        "bar-wip",
					ServiceAccount: "barsa-@google.com",
				},
			},
			createCredsMap: func(creds []string) map[string]cloudkms.Client {
				return map[string]cloudkms.Client{
					creds[0]: createTestKMSClient(t, encryptAndDecrypt),
					creds[1]: createTestKMSClient(t, errorOnly),
					"":       createTestKMSClient(t, errorOnly),
				}
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			stetConfig := &configpb.StetConfig{
				EncryptConfig:  &configpb.EncryptConfig{KeyConfig: tc.keyConfig},
				DecryptConfig:  &configpb.DecryptConfig{KeyConfigs: []*configpb.KeyConfig{tc.keyConfig}},
				AsymmetricKeys: &configpb.AsymmetricKeys{},
				ConfidentialSpaceConfigs: &configpb.ConfidentialSpaceConfigs{
					KekCredentials: tc.kekCreds,
				},
			}

			var creds []string
			for _, c := range tc.kekCreds {
				creds = append(creds, confspace.CreateJSONCredentials(c, tokenFile))
			}

			stetClient := &StetClient{
				testKMSClients: &cloudkms.ClientFactory{
					CredsMap: tc.createCredsMap(creds),
				},
				testConfspaceConfig:     confspace.NewConfigWithTokenFile(stetConfig.GetConfidentialSpaceConfigs(), tokenFile),
				testSecureSessionClient: &fakeSecureSessionClient{},
			}

			plaintext := "test data"

			var ciphertextBuf bytes.Buffer
			if _, err := stetClient.Encrypt(ctx, bytes.NewReader([]byte(plaintext)), &ciphertextBuf, stetConfig, "I am blob."); err != nil {
				t.Fatalf("Encrypt returned error \"%v\", want no error", err)
			}

			var decrypted bytes.Buffer
			if _, err := stetClient.Decrypt(ctx, &ciphertextBuf, &decrypted, stetConfig); err != nil {
				t.Fatalf("Decrypt returned error: %v", err)
			}

			if decrypted.String() != plaintext {
				t.Errorf("Did not get expected plaintext: got %v, want %v", decrypted.String(), plaintext)
			}
		})
	}
}

// If there is a matching ConfSpace Config but ConfSpace token is not present, ignore the config.
func TestCredsIgnoredIfNotInConfspace(t *testing.T) {
	kek0 := "key/uri/0"

	kekCreds := &configpb.KekCredentialConfig{
		KekUriPattern:  gcpKeyPrefix + "key/uri/.*",
		WipName:        "foo-wip",
		ServiceAccount: "foosa-@google.com",
	}

	keyConfig := &configpb.KeyConfig{
		KekInfos: []*configpb.KekInfo{
			{KekType: &configpb.KekInfo_KekUri{KekUri: gcpKeyPrefix + kek0}},
		},
		DekAlgorithm:          configpb.DekAlgorithm_AES256_GCM,
		KeySplittingAlgorithm: &configpb.KeyConfig_NoSplit{true},
	}

	stetConfig := &configpb.StetConfig{
		EncryptConfig:  &configpb.EncryptConfig{KeyConfig: keyConfig},
		DecryptConfig:  &configpb.DecryptConfig{KeyConfigs: []*configpb.KeyConfig{keyConfig}},
		AsymmetricKeys: &configpb.AsymmetricKeys{},
		ConfidentialSpaceConfigs: &configpb.ConfidentialSpaceConfigs{
			KekCredentials: []*configpb.KekCredentialConfig{kekCreds},
		},
	}

	tokenFile := "does/not/exist"
	creds := confspace.CreateJSONCredentials(kekCreds, tokenFile)

	ctx := context.Background()
	stetClient := &StetClient{
		testKMSClients: &cloudkms.ClientFactory{
			CredsMap: map[string]cloudkms.Client{
				"":    createTestKMSClient(t, encryptAndDecrypt),
				creds: createTestKMSClient(t, errorOnly),
			},
		},
		testConfspaceConfig:     confspace.NewConfigWithTokenFile(stetConfig.GetConfidentialSpaceConfigs(), tokenFile),
		testSecureSessionClient: &fakeSecureSessionClient{},
	}

	plaintext := "test data"
	plaintextBuf := bytes.NewReader([]byte(plaintext))

	var ciphertextBuf bytes.Buffer
	if _, err := stetClient.Encrypt(ctx, plaintextBuf, &ciphertextBuf, stetConfig, "I am blob."); err != nil {
		t.Fatalf("Encrypt returned error \"%v\", want no error", err)
	}

	var decrypted bytes.Buffer
	if _, err := stetClient.Decrypt(ctx, &ciphertextBuf, &decrypted, stetConfig); err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}

	if decrypted.String() != plaintext {
		t.Errorf("Did not get expected plaintext: got %v, want %v", decrypted.String(), plaintext)
	}
}
