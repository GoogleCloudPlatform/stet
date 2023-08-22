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

package confidentialspace

import (
	"os"
	"testing"

	"github.com/GoogleCloudPlatform/stet/client/testutil"

	configpb "github.com/GoogleCloudPlatform/stet/proto/config_go_proto"
)

func createTempTokenFile(t *testing.T) string {
	// Create token file.
	tempDir := t.TempDir()
	tokenFile := tempDir + tokenFileName
	if err := os.WriteFile(tokenFile, []byte("test token"), 0755); err != nil {
		t.Fatalf("Error creating token file at %v: %v", tokenFile, err)
	}

	return tokenFile
}

func TestFileExists(t *testing.T) {
	tempDir := t.TempDir()

	tokenFile := tempDir + tokenFileName

	// Expect false, since token file does not exist at this point.
	if fileExists(tokenFile) {
		t.Errorf("fileExists returned true, expected false.")
	}

	// Create token file.
	if err := os.WriteFile(tokenFile, []byte("test token"), 0755); err != nil {
		t.Fatalf("Error creating file at %v: %v", tokenFile, err)
	}

	// Expect true, since token file exists now.
	if !fileExists(tokenFile) {
		t.Errorf("fileExists returned false, expected true.")
	}
}

func TestFindMatchingCredentials(t *testing.T) {
	// Create token file.
	tokenFile := testutil.CreateTempTokenFile(t)

	testCfg := &configpb.ConfidentialSpaceConfigs{
		KekCredentials: []*configpb.KekCredentialConfig{
			{
				KekUriPattern:  "default-uri",
				WipName:        "default-wip",
				ServiceAccount: "default-service-account",
			},
			{
				KekUriPattern:  "encrypt-uri",
				WipName:        "encrypt-wip",
				ServiceAccount: "encrypt-service-account",
				Mode:           configpb.CredentialMode_ENCRYPT_ONLY_MODE,
			},
			{
				KekUriPattern:  "decrypt-uri",
				WipName:        "decrypt-wip",
				ServiceAccount: "decrypt-service-account",
				Mode:           configpb.CredentialMode_DECRYPT_ONLY_MODE,
			},
			{
				KekUriPattern: "no-sa-uri",
				WipName:       "no-sa-wip",
			},
			{
				KekUriPattern:  "regex-uri-.*",
				WipName:        "regex-wip",
				ServiceAccount: "regex-service-account",
			},
		},
	}

	testcases := []struct {
		name   string
		kekURI string
		mode   configpb.CredentialMode
		want   string
	}{
		{
			name:   "Default mode",
			kekURI: testCfg.GetKekCredentials()[0].GetKekUriPattern(),
			mode:   configpb.CredentialMode_ENCRYPT_ONLY_MODE, // Input ENCRYPT_ONLY, but should match ENCRYPT_AND_DECRYPT mode.
			want:   CreateJSONCredentials(testCfg.GetKekCredentials()[0], tokenFile),
		},
		{
			name:   "Encrypt-only mode",
			kekURI: testCfg.GetKekCredentials()[1].GetKekUriPattern(),
			mode:   configpb.CredentialMode_ENCRYPT_ONLY_MODE,
			want:   CreateJSONCredentials(testCfg.GetKekCredentials()[1], tokenFile),
		},
		{
			name:   "Decrypt-only mode",
			kekURI: testCfg.GetKekCredentials()[2].GetKekUriPattern(),
			mode:   configpb.CredentialMode_DECRYPT_ONLY_MODE,
			want:   CreateJSONCredentials(testCfg.GetKekCredentials()[2], tokenFile),
		},
		{
			name:   "No service account in credentials",
			kekURI: testCfg.GetKekCredentials()[3].GetKekUriPattern(),
			mode:   configpb.CredentialMode_ENCRYPT_ONLY_MODE,
			want:   CreateJSONCredentials(testCfg.GetKekCredentials()[3], tokenFile),
		},
		{
			name:   "Regex URI",
			kekURI: "regex-uri-foobar",
			mode:   configpb.CredentialMode_ENCRYPT_ONLY_MODE,
			want:   CreateJSONCredentials(testCfg.GetKekCredentials()[4], tokenFile),
		},
	}

	config := NewConfigWithTokenFile(testCfg, tokenFile)

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := config.FindMatchingCredentials(tc.kekURI, tc.mode)
			if got != tc.want {
				t.Errorf("FindMatchingCredentials(%v, %v) = %v, want: %v", tc.kekURI, tc.mode, got, tc.want)
			}
		})
	}
}

func TestFindMatchingCredentialsWithoutConfidentialSpace(t *testing.T) {
	config := &Config{}

	if creds := config.FindMatchingCredentials("fake uri", configpb.CredentialMode_ENCRYPT_ONLY_MODE); len(creds) > 0 {
		t.Errorf("Expected no credentials returned, got %v", creds)
	}
}

// Tests scenarios where we don't expect FindMatchingCredentials to return a match.
func TestFindMatchingCredentialsWithoutMatch(t *testing.T) {
	// Create token file.
	tokenFile := testutil.CreateTempTokenFile(t)

	testCfg := &configpb.ConfidentialSpaceConfigs{
		KekCredentials: []*configpb.KekCredentialConfig{
			{
				KekUriPattern:  "test-uri",
				WipName:        "test-wip",
				ServiceAccount: "test-service-account",
				Mode:           configpb.CredentialMode_ENCRYPT_ONLY_MODE,
			},
		},
	}

	testcases := []struct {
		name   string
		kekURI string
		mode   configpb.CredentialMode
	}{
		{
			name:   "No matching URI",
			kekURI: "not-a-valid-uri",
			mode:   configpb.CredentialMode_ENCRYPT_ONLY_MODE,
		},
		{
			name:   "Matching URI but not mode",
			kekURI: testCfg.GetKekCredentials()[0].GetKekUriPattern(),
			mode:   configpb.CredentialMode_DECRYPT_ONLY_MODE, // Differs from testCfg above.
		},
	}

	config := NewConfigWithTokenFile(testCfg, tokenFile)

	// Ensure tokenFileFound == false is not the cause of empty return from FindMatchingCredentials.
	if !config.tokenFileFound {
		t.Errorf("config.tokenFileFound = false, expected true.")
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := config.FindMatchingCredentials(tc.kekURI, tc.mode)
			// Expect empty return.
			if len(got) != 0 {
				t.Errorf("FindMatchingCredentials(%v, %v) = %v, want empty string.", tc.kekURI, tc.mode, got)
			}
		})
	}
}
