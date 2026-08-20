// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"crypto/mlkem"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"

	configpb "github.com/GoogleCloudPlatform/stet/proto/config_go_proto"
	"github.com/tink-crypto/tink-go/v2/hybrid"
	"github.com/tink-crypto/tink-go/v2/hybrid/hpke"
	"github.com/tink-crypto/tink-go/v2/insecuresecretdataaccess"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/secretdata"
)

type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type openSSLMLKEMPrivateKey struct {
	Seed []byte
}

var (
	oidPublicKeyMLKEM768  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
	oidPublicKeyMLKEM1024 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 3}
)

// mlkemPublicKey represents a public key that can be serialized to bytes.
type mlkemPublicKey interface {
	Bytes() []byte
}

// mlkemPrivateKey represents a private key that can be serialized to bytes.
type mlkemPrivateKey interface {
	Bytes() []byte
}

// publicKeyForMLKEMFingerprint iterates through the public keys defined in `keys`, searching for one
// that matches `kek`. If one is found, returns it (either a *mlkem.EncapsulationKey768 or *mlkem.EncapsulationKey1024), otherwise returns nil.
func publicKeyForMLKEMFingerprint(kek *configpb.KekInfo, keys *configpb.AsymmetricKeys) (mlkemPublicKey, hpke.KEMID, error) {
	for _, path := range keys.GetPublicKeyFiles() {
		keyBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, hpke.UnknownKEMID, fmt.Errorf("failed to open public key file: %w", err)
		}

		block, _ := pem.Decode(keyBytes)
		if block == nil || block.Type != "PUBLIC KEY" {
			continue
		}

		// Compute SHA-256 digest of the DER-encoded public key.
		sha := sha256.Sum256(block.Bytes)
		fingerprint := base64.StdEncoding.EncodeToString(sha[:])

		if fingerprint != kek.GetMlkemFingerprint() {
			continue
		}

		var spki subjectPublicKeyInfo
		if _, err := asn1.Unmarshal(block.Bytes, &spki); err != nil {
			return nil, hpke.UnknownKEMID, fmt.Errorf("failed to parse SubjectPublicKeyInfo from PEM: %w", err)
		}

		if spki.Algorithm.Algorithm.Equal(oidPublicKeyMLKEM768) {
			pubKey, err := mlkem.NewEncapsulationKey768(spki.SubjectPublicKey.Bytes)
			if err != nil {
				return nil, hpke.UnknownKEMID, fmt.Errorf("failed to parse ML-KEM-768 public key: %w", err)
			}
			return pubKey, hpke.ML_KEM768, nil
		}
		if spki.Algorithm.Algorithm.Equal(oidPublicKeyMLKEM1024) {
			pubKey, err := mlkem.NewEncapsulationKey1024(spki.SubjectPublicKey.Bytes)
			if err != nil {
				return nil, hpke.UnknownKEMID, fmt.Errorf("failed to parse ML-KEM-1024 public key: %w", err)
			}
			return pubKey, hpke.ML_KEM1024, nil
		}
		return nil, hpke.UnknownKEMID, fmt.Errorf("unsupported ML-KEM public key algorithm OID: %s", spki.Algorithm.Algorithm)
	}

	return nil, hpke.UnknownKEMID, fmt.Errorf("no ML-KEM public key found for fingerprint: %s", kek.GetMlkemFingerprint())
}

// calculateFingerprint calculates the ML-KEM fingerprint from the encapsulation key and OID.
func calculateFingerprint(ek []byte, oid asn1.ObjectIdentifier) string {
	spki := subjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm: oid,
		},
		SubjectPublicKey: asn1.BitString{
			Bytes:     ek,
			BitLength: len(ek) * 8,
		},
	}
	pubDer, _ := asn1.Marshal(spki)
	sha := sha256.Sum256(pubDer)
	return base64.StdEncoding.EncodeToString(sha[:])
}

// privateKeyForMLKEMFingerprint iterates through the private keys defined in `keys`, searching for
// one that matches `kek`. If one is found, returns it (either a *mlkem.DecapsulationKey768 or *mlkem.DecapsulationKey1024), otherwise returns nil.
func privateKeyForMLKEMFingerprint(kek *configpb.KekInfo, keys *configpb.AsymmetricKeys) (mlkemPrivateKey, hpke.KEMID, error) {
	for _, path := range keys.GetPrivateKeyFiles() {
		keyBytes, err := os.ReadFile(path)
		if err != nil {
			return nil, hpke.UnknownKEMID, fmt.Errorf("failed to open private key file: %w", err)
		}

		block, _ := pem.Decode(keyBytes)
		if block == nil || (block.Type != "PRIVATE KEY" && block.Type != "ML-KEM PRIVATE KEY") {
			continue
		}

		var p8 pkcs8
		if _, err := asn1.Unmarshal(block.Bytes, &p8); err != nil {
			continue
		}

		var seed []byte
		if len(p8.PrivateKey) == mlkem.SeedSize {
			seed = p8.PrivateKey
		} else {
			var keyStruct openSSLMLKEMPrivateKey
			if _, err := asn1.Unmarshal(p8.PrivateKey, &keyStruct); err != nil {
				continue
			}
			seed = keyStruct.Seed
		}

		if len(seed) != mlkem.SeedSize {
			continue
		}

		var fingerprint string
		var privKey mlkemPrivateKey
		var kemID hpke.KEMID

		if p8.Algo.Algorithm.Equal(oidPublicKeyMLKEM768) {
			kemID = hpke.ML_KEM768
			dk, _ := mlkem.NewDecapsulationKey768(seed)
			privKey = dk
			ek := dk.EncapsulationKey()
			fingerprint = calculateFingerprint(ek.Bytes(), oidPublicKeyMLKEM768)
		} else if p8.Algo.Algorithm.Equal(oidPublicKeyMLKEM1024) {
			kemID = hpke.ML_KEM1024
			dk, _ := mlkem.NewDecapsulationKey1024(seed)
			privKey = dk
			ek := dk.EncapsulationKey()
			fingerprint = calculateFingerprint(ek.Bytes(), oidPublicKeyMLKEM1024)
		} else {
			continue
		}

		if fingerprint == kek.GetMlkemFingerprint() {
			return privKey, kemID, nil
		}
	}

	return nil, hpke.UnknownKEMID, fmt.Errorf("no ML-KEM private key found for fingerprint: %s", kek.GetMlkemFingerprint())
}

// wrapShareWithMLKEM encrypts the given share using the ML-KEM key specified in `kek` and the
// asymmetric keys defined in `asymmetricKeys`.
func wrapShareWithMLKEM(share []byte, kek *configpb.KekInfo, asymmetricKeys *configpb.AsymmetricKeys) ([]byte, error) {
	key, kemID, err := publicKeyForMLKEMFingerprint(kek, asymmetricKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to find public key for MLKEM fingerprint: %w", err)
	}

	params, err := newHPKEParameters(kemID)
	if err != nil {
		return nil, fmt.Errorf("failed to create HPKE parameters: %w", err)
	}

	publicKey, err := hpke.NewPublicKey(key.Bytes(), 0, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create HPKE public key: %w", err)
	}

	manager := keyset.NewManager()
	keyID, err := manager.AddKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to add HPKE public key to keyset manager: %w", err)
	}
	if err := manager.SetPrimary(keyID); err != nil {
		return nil, fmt.Errorf("failed to set primary key: %w", err)
	}
	h, err := manager.Handle()
	if err != nil {
		return nil, fmt.Errorf("failed to get keyset handle: %w", err)
	}

	enc, err := hybrid.NewHybridEncrypt(h)
	if err != nil {
		return nil, fmt.Errorf("failed to create HybridEncrypt primitive: %w", err)
	}

	return enc.Encrypt(share, nil)
}

func newHPKEParameters(kemID hpke.KEMID) (*hpke.Parameters, error) {
	return hpke.NewParameters(hpke.ParametersOpts{
		KEMID:   kemID,
		KDFID:   hpke.HKDFSHA256,
		AEADID:  hpke.AES256GCM,
		Variant: hpke.VariantNoPrefix,
	})
}

// unwrapShareWithMLKEM decrypts the given share using the ML-KEM key specified in `kek` and the
// asymmetric keys defined in `asymmetricKeys`.
func unwrapShareWithMLKEM(share []byte, kek *configpb.KekInfo, asymmetricKeys *configpb.AsymmetricKeys) ([]byte, error) {
	key, kemID, err := privateKeyForMLKEMFingerprint(kek, asymmetricKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to find private key for MLKEM fingerprint: %w", err)
	}

	params, err := newHPKEParameters(kemID)
	if err != nil {
		return nil, fmt.Errorf("failed to create HPKE parameters: %w", err)
	}

	privBytes := secretdata.NewBytesFromData(key.Bytes(), insecuresecretdataaccess.Token{})
	privateKey, err := hpke.NewPrivateKey(privBytes, 0, params)
	if err != nil {
		return nil, fmt.Errorf("failed to create HPKE private key: %w", err)
	}

	manager := keyset.NewManager()
	keyID, err := manager.AddKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to add HPKE private key to keyset manager: %w", err)
	}
	if err := manager.SetPrimary(keyID); err != nil {
		return nil, fmt.Errorf("failed to set primary key: %w", err)
	}
	h, err := manager.Handle()
	if err != nil {
		return nil, fmt.Errorf("failed to get keyset handle: %w", err)
	}

	dec, err := hybrid.NewHybridDecrypt(h)
	if err != nil {
		return nil, fmt.Errorf("failed to create HybridDecrypt primitive: %w", err)
	}
	return dec.Decrypt(share, nil)
}
