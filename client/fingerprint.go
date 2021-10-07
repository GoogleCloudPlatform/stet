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

// Utility functions for dealing with RSA keys and fingerprints.

package client

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	configpb "github.com/GoogleCloudPlatform/stet/proto/config_go_proto"
)

// Iterates through the public keys defined in `keys`, searching for one that
// matches `kek`. If one is found, returns it, otherwise returns nil.
func publicKeyForRSAFingerprint(kek *configpb.KekInfo, keys *configpb.AsymmetricKeys) (*rsa.PublicKey, error) {
	for _, path := range keys.GetPublicKeyFiles() {
		keyBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open public key file: %w", err)
		}

		block, _ := pem.Decode(keyBytes)
		if block == nil || block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("failed to decode PEM block containing public key")
		}

		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key from PEM: %v", err)
		}
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("failed to parse RSA public key: %v", err)
		}
		// Compute SHA-256 digest of the DER-encoded public key.
		sha := sha256.Sum256(block.Bytes)
		fingerprint := base64.StdEncoding.EncodeToString(sha[:])
		if fingerprint == kek.GetRsaFingerprint() {
			return key, nil
		}
	}

	return nil, fmt.Errorf("no RSA public key found for fingerprint: %s", kek.GetRsaFingerprint())
}

// Iterates through the private keys defined in `keys`, searching for one that
// matches `kek`. If one is found, returns it, otherwise returns nil.
func privateKeyForRSAFingerprint(kek *configpb.KekInfo, keys *configpb.AsymmetricKeys) (*rsa.PrivateKey, error) {
	for _, path := range keys.GetPrivateKeyFiles() {
		keyBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open private key file: %w", err)
		}

		block, _ := pem.Decode(keyBytes)
		if block == nil || block.Type != "RSA PRIVATE KEY" {
			return nil, fmt.Errorf("failed to decode PEM block containing RSA private key")
		}

		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 private key from PEM: %v", err)
		}

		// Compute SHA-256 digest of the DER-encoded public key.
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal public key from private key: %w", err)
		}
		sha := sha256.Sum256(der)
		fingerprint := base64.StdEncoding.EncodeToString(sha[:])
		if fingerprint == kek.GetRsaFingerprint() {
			return key, nil
		}
	}

	return nil, fmt.Errorf("no RSA private key found for fingerprint: %s", kek.GetRsaFingerprint())
}
