// Copyright 2026 Google LLC
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
	"crypto/mlkem"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/GoogleCloudPlatform/stet/client/shares"
	configpb "github.com/GoogleCloudPlatform/stet/proto/config_go_proto"
	"github.com/tink-crypto/tink-go/v2/hybrid/hpke"
)

func generateTestMLKEMKey(t *testing.T, is1024 bool) (privPEM, pubPEM []byte, fp string, seed []byte) {
	t.Helper()
	var oid asn1.ObjectIdentifier
	var dkBytes, ekBytes []byte
	if is1024 {
		oid = oidPublicKeyMLKEM1024
		dk, err := mlkem.GenerateKey1024()
		if err != nil {
			t.Fatalf("GenerateKey1024: %v", err)
		}
		dkBytes, ekBytes = dk.Bytes(), dk.EncapsulationKey().Bytes()
	} else {
		oid = oidPublicKeyMLKEM768
		dk, err := mlkem.GenerateKey768()
		if err != nil {
			t.Fatalf("GenerateKey768: %v", err)
		}
		dkBytes, ekBytes = dk.Bytes(), dk.EncapsulationKey().Bytes()
	}

	p8Der, _ := asn1.Marshal(pkcs8{Algo: pkix.AlgorithmIdentifier{Algorithm: oid}, PrivateKey: dkBytes})
	spki := subjectPublicKeyInfo{Algorithm: pkix.AlgorithmIdentifier{Algorithm: oid}, SubjectPublicKey: asn1.BitString{Bytes: ekBytes, BitLength: len(ekBytes) * 8}}
	spkiDer, _ := asn1.Marshal(spki)
	sha := sha256.Sum256(spkiDer)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8Der}),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spkiDer}),
		base64.StdEncoding.EncodeToString(sha[:]),
		dkBytes
}

func TestCalculateFingerprint(t *testing.T) {
	for _, tc := range []struct {
		name   string
		is1024 bool
		oid    asn1.ObjectIdentifier
	}{
		{
			name:   "MLKEM768",
			is1024: false,
			oid:    oidPublicKeyMLKEM768,
		},
		{
			name:   "MLKEM1024",
			is1024: true,
			oid:    oidPublicKeyMLKEM1024,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, pubPEM, expectedFP, _ := generateTestMLKEMKey(t, tc.is1024)
			block, _ := pem.Decode(pubPEM)
			var spki subjectPublicKeyInfo
			asn1.Unmarshal(block.Bytes, &spki)

			fp := calculateFingerprint(spki.SubjectPublicKey.Bytes, tc.oid)
			if fp != expectedFP {
				t.Errorf("got %v, want %v", fp, expectedFP)
			}
		})
	}
}

func TestPublicKeyForMLKEMFingerprint(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, data, 0600)
		return p
	}

	_, pub768, fp768, _ := generateTestMLKEMKey(t, false)
	_, pub1024, fp1024, _ := generateTestMLKEMKey(t, true)

	// Public PEM files for MLKEM768 and MLKEM1024 successful parsing.
	f768 := writeFile("pub768.pem", pub768)
	f1024 := writeFile("pub1024.pem", pub1024)

	// Incorrect PEM files that don't match the expected format for MLKEM768 or MLKEM1024
	// to test various error conditions.
	fBadPEM := writeFile("bad.pem", []byte("bad pem"))
	fCert := writeFile("cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("cert")}))
	badSPKIDer := []byte("bad")
	badSPKISha := sha256.Sum256(badSPKIDer)
	fBadSPKI := writeFile("bad_spki.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: badSPKIDer}))
	badOIDDer, _ := asn1.Marshal(subjectPublicKeyInfo{Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}}, SubjectPublicKey: asn1.BitString{Bytes: []byte{1}}})
	badOIDSha := sha256.Sum256(badOIDDer)
	fBadOID := writeFile("bad_oid.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: badOIDDer}))
	invalidKeyDer, _ := asn1.Marshal(subjectPublicKeyInfo{Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyMLKEM768}, SubjectPublicKey: asn1.BitString{Bytes: []byte("short"), BitLength: 40}})
	invalidKeySha := sha256.Sum256(invalidKeyDer)
	fInvalidKey := writeFile("invalid_key.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: invalidKeyDer}))
	invalidKey1024Der, _ := asn1.Marshal(subjectPublicKeyInfo{Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyMLKEM1024}, SubjectPublicKey: asn1.BitString{Bytes: []byte("short"), BitLength: 40}})
	invalidKey1024Sha := sha256.Sum256(invalidKey1024Der)
	fInvalidKey1024 := writeFile("invalid_key1024.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: invalidKey1024Der}))

	tests := []struct {
		name       string
		files      []string
		fp         string
		wantKEM    hpke.KEMID
		wantErr    bool
		errContain string
	}{
		{
			name:    "MLKEM768",
			files:   []string{f768},
			fp:      fp768,
			wantKEM: hpke.ML_KEM768,
		},
		{
			name:    "MLKEM1024",
			files:   []string{f1024},
			fp:      fp1024,
			wantKEM: hpke.ML_KEM1024,
		},
		{
			name:    "MultipleFiles_FindsMatch",
			files:   []string{fCert, fBadPEM, f1024},
			fp:      fp1024,
			wantKEM: hpke.ML_KEM1024,
		},
		{
			name:    "FileNotFound",
			files:   []string{filepath.Join(dir, "missing.pem")},
			fp:      fp768,
			wantErr: true,
		},
		{
			name:       "BadSPKI",
			files:      []string{fBadSPKI},
			fp:         base64.StdEncoding.EncodeToString(badSPKISha[:]),
			wantErr:    true,
			errContain: "SubjectPublicKeyInfo",
		},
		{
			name:    "UnsupportedOID",
			files:   []string{fBadOID},
			fp:      base64.StdEncoding.EncodeToString(badOIDSha[:]),
			wantErr: true, errContain: "unsupported ML-KEM",
		},
		{
			name:       "InvalidKeyLength",
			files:      []string{fInvalidKey},
			fp:         base64.StdEncoding.EncodeToString(invalidKeySha[:]),
			wantErr:    true,
			errContain: "ML-KEM-768 public key"},
		{
			name:       "InvalidKeyLength1024",
			files:      []string{fInvalidKey1024},
			fp:         base64.StdEncoding.EncodeToString(invalidKey1024Sha[:]),
			wantErr:    true,
			errContain: "ML-KEM-1024 public key"},
		{
			name:       "MismatchFP",
			files:      []string{f768},
			fp:         "wrong",
			wantErr:    true,
			errContain: "no ML-KEM public key found",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kek := &configpb.KekInfo{KekType: &configpb.KekInfo_MlkemFingerprint{MlkemFingerprint: tc.fp}}
			keys := &configpb.AsymmetricKeys{PublicKeyFiles: tc.files}
			k, kemID, err := publicKeyForMLKEMFingerprint(kek, keys)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if tc.wantErr && tc.errContain != "" && !strings.Contains(err.Error(), tc.errContain) {
				t.Errorf("err = %v, want substring %q", err, tc.errContain)
			}
			if !tc.wantErr && (kemID != tc.wantKEM || k == nil) {
				t.Errorf("got (%v, %v), want (%v, non-nil)", k, kemID, tc.wantKEM)
			}
		})
	}
}

func TestPrivateKeyForMLKEMFingerprint(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, data, 0600)
		return p
	}

	priv768, _, fp768, seed768 := generateTestMLKEMKey(t, false)
	priv1024, _, fp1024, seed1024 := generateTestMLKEMKey(t, true)

	// Private PEM files for MLKEM768 and MLKEM1024 successful parsing.
	f768 := writeFile("priv768.pem", priv768)
	f1024 := writeFile("priv1024.pem", priv1024)

	// OpenSSL-compatible private key files for MLKEM768 and MLKEM1024.
	openSSL768Der, _ := asn1.Marshal(openSSLMLKEMPrivateKey{Seed: seed768})
	openSSLP8_768, _ := asn1.Marshal(pkcs8{Algo: pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyMLKEM768}, PrivateKey: openSSL768Der})
	fOpenSSL768 := writeFile("openssl768.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: openSSLP8_768}))

	openSSL1024Der, _ := asn1.Marshal(openSSLMLKEMPrivateKey{Seed: seed1024})
	openSSLP8_1024, _ := asn1.Marshal(pkcs8{Algo: pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyMLKEM1024}, PrivateKey: openSSL1024Der})
	fOpenSSL1024 := writeFile("openssl1024.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: openSSLP8_1024}))

	// Alternative PEM file for MLKEM768 with a different block type.
	p8Der, _ := asn1.Marshal(pkcs8{Algo: pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyMLKEM768}, PrivateKey: seed768})
	fAltType := writeFile("alt.pem", pem.EncodeToMemory(&pem.Block{Type: "ML-KEM PRIVATE KEY", Bytes: p8Der}))

	// OpenSSL-compatible private key with a bad seed length.
	openSSLBadSeedDer, _ := asn1.Marshal(openSSLMLKEMPrivateKey{Seed: []byte("short_seed")})
	openSSLBadSeedP8, _ := asn1.Marshal(pkcs8{Algo: pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyMLKEM768}, PrivateKey: openSSLBadSeedDer})
	fOpenSSLBadSeed := writeFile("openssl_bad_seed.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: openSSLBadSeedP8}))

	// Incorrect PEM files that don't match the expected format for MLKEM768 or MLKEM1024
	// to test various error conditions.
	fBadPEM := writeFile("bad.pem", []byte("not pem"))
	fWrongType := writeFile("wrong_type.pem", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("dummy")}))
	fBadPKCS8 := writeFile("bad_p8.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("bad")}))
	badSeedP8, _ := asn1.Marshal(pkcs8{Algo: pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyMLKEM768}, PrivateKey: []byte("short")})
	fBadSeed := writeFile("bad_seed.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: badSeedP8}))
	badOIDP8, _ := asn1.Marshal(pkcs8{Algo: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}}, PrivateKey: seed768})
	fBadOID := writeFile("bad_oid.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: badOIDP8}))

	tests := []struct {
		name    string
		files   []string
		fp      string
		wantKEM hpke.KEMID
		wantErr bool
	}{
		{
			name:    "MLKEM768",
			files:   []string{f768},
			fp:      fp768,
			wantKEM: hpke.ML_KEM768,
		},
		{
			name:    "MLKEM1024",
			files:   []string{f1024},
			fp:      fp1024,
			wantKEM: hpke.ML_KEM1024,
		},
		{
			name:    "OpenSSL768",
			files:   []string{fOpenSSL768},
			fp:      fp768,
			wantKEM: hpke.ML_KEM768,
		},
		{
			name:    "OpenSSL1024",
			files:   []string{fOpenSSL1024},
			fp:      fp1024,
			wantKEM: hpke.ML_KEM1024,
		},
		{
			name:    "AltBlockType",
			files:   []string{fAltType},
			fp:      fp768,
			wantKEM: hpke.ML_KEM768,
		},
		{
			name:    "SkipInvalidAndFind",
			files:   []string{fBadPEM, fWrongType, fBadPKCS8, fBadSeed, fOpenSSLBadSeed, fBadOID, f768},
			fp:      fp768,
			wantKEM: hpke.ML_KEM768,
		},
		{
			name:    "FileNotFound",
			files:   []string{filepath.Join(dir, "missing.pem")},
			fp:      fp768,
			wantErr: true,
		},
		{
			name:    "MismatchFP",
			files:   []string{f768},
			fp:      "wrong",
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kek := &configpb.KekInfo{KekType: &configpb.KekInfo_MlkemFingerprint{MlkemFingerprint: tc.fp}}
			keys := &configpb.AsymmetricKeys{PrivateKeyFiles: tc.files}
			k, kemID, err := privateKeyForMLKEMFingerprint(kek, keys)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if !tc.wantErr && (kemID != tc.wantKEM || k == nil) {
				t.Errorf("got (%v, %v), want (%v, non-nil)", k, kemID, tc.wantKEM)
			}
		})
	}
}

func TestWrapUnwrapShareWithMLKEM(t *testing.T) {
	dir := t.TempDir()
	writeFile := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, data, 0600)
		return p
	}

	priv768, pub768, fp768, seed768 := generateTestMLKEMKey(t, false)
	priv1024, pub1024, fp1024, _ := generateTestMLKEMKey(t, true)
	fPub768 := writeFile("pub768.pem", pub768)
	fPriv768 := writeFile("priv768.pem", priv768)
	fPub1024 := writeFile("pub1024.pem", pub1024)
	fPriv1024 := writeFile("priv1024.pem", priv1024)

	openSSL768Der, _ := asn1.Marshal(openSSLMLKEMPrivateKey{Seed: seed768})
	openSSLP8, _ := asn1.Marshal(pkcs8{Algo: pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyMLKEM768}, PrivateKey: openSSL768Der})
	fOpenSSL768 := writeFile("openssl768.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: openSSLP8}))

	testShare := []byte("super secret share 12345")

	for _, tc := range []struct {
		name     string
		pubFiles []string
		prvFiles []string
		fp       string
	}{
		{
			name:     "MLKEM768",
			pubFiles: []string{fPub768},
			prvFiles: []string{fPriv768},
			fp:       fp768,
		},
		{
			name:     "MLKEM1024",
			pubFiles: []string{fPub1024},
			prvFiles: []string{fPriv1024},
			fp:       fp1024,
		},
		{
			name:     "OpenSSL768",
			pubFiles: []string{fPub768},
			prvFiles: []string{fOpenSSL768},
			fp:       fp768,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kek := &configpb.KekInfo{KekType: &configpb.KekInfo_MlkemFingerprint{MlkemFingerprint: tc.fp}}
			keys := &configpb.AsymmetricKeys{PublicKeyFiles: tc.pubFiles, PrivateKeyFiles: tc.prvFiles}
			ct, err := wrapShareWithMLKEM(testShare, kek, keys)
			if err != nil {
				t.Fatalf("wrapShareWithMLKEM: %v", err)
			}
			pt, err := unwrapShareWithMLKEM(ct, kek, keys)
			if err != nil {
				t.Fatalf("unwrapShareWithMLKEM: %v", err)
			}
			if !bytes.Equal(pt, testShare) {
				t.Errorf("got %q, want %q", pt, testShare)
			}
		})
	}

	t.Run("Errors", func(t *testing.T) {
		kek := &configpb.KekInfo{KekType: &configpb.KekInfo_MlkemFingerprint{MlkemFingerprint: fp768}}
		keys := &configpb.AsymmetricKeys{PublicKeyFiles: []string{fPub768}, PrivateKeyFiles: []string{fPriv768}}
		badKek := &configpb.KekInfo{KekType: &configpb.KekInfo_MlkemFingerprint{MlkemFingerprint: "missing"}}

		if _, err := wrapShareWithMLKEM(testShare, badKek, keys); err == nil {
			t.Error("wrap: expected error for missing public key")
		}
		if _, err := unwrapShareWithMLKEM([]byte("ct"), badKek, keys); err == nil {
			t.Error("unwrap: expected error for missing private key")
		}
		ct, err := wrapShareWithMLKEM(testShare, kek, keys)
		if err != nil {
			t.Fatalf("wrap: %v", err)
		}
		corrupted := bytes.Clone(ct)
		corrupted[len(corrupted)-1] ^= 0xFF
		if _, err := unwrapShareWithMLKEM(corrupted, kek, keys); err == nil {
			t.Error("unwrap: expected error for corrupted ciphertext")
		}

		priv768Other, _, fp768Other, _ := generateTestMLKEMKey(t, false)
		fPriv768Other := writeFile("priv768_other.pem", priv768Other)
		kek768Other := &configpb.KekInfo{KekType: &configpb.KekInfo_MlkemFingerprint{MlkemFingerprint: fp768Other}}
		keys768Other := &configpb.AsymmetricKeys{PrivateKeyFiles: []string{fPriv768Other}}
		if _, err := unwrapShareWithMLKEM(ct, kek768Other, keys768Other); err == nil {
			t.Error("unwrap: expected error for wrong private key")
		}
	})
}

func TestWrapUnwrapShareMLKEMAsymmetricKey(t *testing.T) {
	for _, tc := range []struct {
		name   string
		is1024 bool
	}{
		{
			name:   "MLKEM768",
			is1024: false,
		},
		{
			name:   "MLKEM1024",
			is1024: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			priv, pub, fp, _ := generateTestMLKEMKey(t, tc.is1024)
			pubFile := filepath.Join(dir, "pub.pem")
			privFile := filepath.Join(dir, "priv.pem")
			os.WriteFile(pubFile, pub, 0600)
			os.WriteFile(privFile, priv, 0600)

			testShare := []byte("Foo! 012345678901234567890123456")
			testHashedShare := shares.HashShare(testShare)
			ki := []*configpb.KekInfo{{KekType: &configpb.KekInfo_MlkemFingerprint{MlkemFingerprint: fp}}}
			keys := &configpb.AsymmetricKeys{PublicKeyFiles: []string{pubFile}, PrivateKeyFiles: []string{privFile}}
			opts := sharesOpts{kekInfos: ki, asymmetricKeys: keys}

			var client StetClient
			wrapped, keyURIs, err := client.wrapShares(t.Context(), [][]byte{testShare}, opts)
			if err != nil {
				t.Fatalf("wrapShares: %v", err)
			}
			if len(wrapped) != 1 || !bytes.Equal(wrapped[0].GetHash(), testHashedShare[:]) || len(keyURIs) != 0 {
				t.Fatalf("unexpected wrapShares output")
			}
			unwrapped, err := client.unwrapAndValidateShares(t.Context(), wrapped, opts)
			if err != nil {
				t.Fatalf("unwrapAndValidateShares: %v", err)
			}
			if len(unwrapped) != 1 || !bytes.Equal(unwrapped[0].Share, testShare) {
				t.Errorf("unwrapped = %v, want %v", unwrapped, testShare)
			}
		})
	}
}
