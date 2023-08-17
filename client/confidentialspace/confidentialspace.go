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

// Package confidentialspace defines methods for integration with Confidential Space.
package confidentialspace

import (
	"errors"
	"fmt"
	"os"
	"regexp"

	configpb "github.com/GoogleCloudPlatform/stet/proto/config_go_proto"
	glog "github.com/golang/glog"
)

const (
	tokenFilePath       = "/run/container_launcher/"
	tokenFileName       = "attestation_verifier_claims_token"
	audiencePrefix      = "//iam.googleapis.com/"
	impersonationURLFmt = `"service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%v:generateAccessToken",`
	credentialConfigFmt = `{
		"type": "external_account",
		"audience": "%s",
		"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
		"token_url": "https://sts.googleapis.com/v1/token",
		%s
		"credential_source": {
			"file": "%s"
		}
		}`
)

// Config wraps ConfidentialSpaceConfigs for STET.
type Config struct {
	inner          *configpb.ConfidentialSpaceConfigs
	tokenFile      string
	tokenFileFound bool
}

// NewConfig initializes a Config containing the provided 'config' proto.
func NewConfig(config *configpb.ConfidentialSpaceConfigs) *Config {
	tokenFile := tokenFilePath + tokenFileName
	return NewConfigWithTokenFile(config, tokenFile)
}

// NewConfigWithTokenFile initializes a Config containing the provided 'config' proto and
// tokenFile. This allows our tests to use a custom tokenFile path.
func NewConfigWithTokenFile(config *configpb.ConfidentialSpaceConfigs, tokenFile string) *Config {
	cfg := &Config{
		inner:          config,
		tokenFile:      tokenFile,
		tokenFileFound: fileExists(tokenFile),
	}

	return cfg
}

// fileExists checks whether the provided file exists. If the os.Stat operation fails for a reason
// other than os.ErrNotExist (meaning the file may or may not exist), log the error and return
// false.
func fileExists(filepath string) bool {
	_, err := os.Stat(filepath)

	// If the err is not os.ErrNotExist, log it.
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		glog.Errorf("error looking for file: %v", err)
	}

	return err == nil
}

// CreateJSONCredentials returns a JSON credential config containing the provided info.
func CreateJSONCredentials(cred *configpb.KekCredentialConfig, sourceFile string) string {
	aud := audiencePrefix + cred.WipName

	impersonationURL := ""
	if len(cred.ServiceAccount) > 0 {
		impersonationURL = fmt.Sprintf(impersonationURLFmt, cred.ServiceAccount)
	}

	return fmt.Sprintf(credentialConfigFmt, aud, impersonationURL, sourceFile)
}

// FindMatchingCredentials searches the config for an entry with a URI pattern and credential mode
// matching 'kekURI' and 'mode' respectively.
// If a match is found, it returns a Credential Config JSON containing the information in the
// matching config.
func (c *Config) FindMatchingCredentials(kekURI string, mode configpb.CredentialMode) string {
	// Return empty if not in Confidential Space.
	if !c.tokenFileFound {
		return ""
	}

	for _, cred := range c.inner.GetKekCredentials() {
		// Check the mode matches.
		if cred.GetMode() == configpb.CredentialMode_DEFAULT_ENCRYPT_AND_DECRYPT_MODE || cred.GetMode() == mode {
			// Check the KEK pattern matches.
			match, err := regexp.MatchString(cred.GetKekUriPattern(), kekURI)

			// If there was an error, log and move to the next set of credentials.
			if err != nil {
				glog.Errorf("Invalid KEK URI pattern: %s", cred.GetKekUriPattern())
				continue
			}

			if match {
				return CreateJSONCredentials(cred, c.tokenFile)
			}
		}
	}

	return ""
}
