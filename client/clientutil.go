// Copyright 2021 Google LLC
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
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/GoogleCloudPlatform/stet/client/shares"
	configpb "github.com/GoogleCloudPlatform/stet/proto/config_go_proto"
	"github.com/google/tink/go/streamingaead/subtle"
	"google.golang.org/protobuf/proto"
)

const (
	// DEKBytes is the size of the DEK in bytes.

	// Parameters for streaming AEAD, required by Tink's subtle API.
	aeadHKDFAlg            = "SHA256"
	aeadSegmentSize        = 1048576
	aeadFirstSegmentOffset = 0
	aeadChunkSize          = 128
)

/////////////////////////////////////////
// For AEAD encryption and decryption. //
/////////////////////////////////////////

// AeadEncrypt uses the provided key and AAD to encrypt the plaintext passed in
// via `input`, writing the output to `output`.
func AeadEncrypt(key shares.DEK, input io.Reader, output io.Writer, aad []byte) error {
	cipher, err := subtle.NewAESGCMHKDF(key[:], aeadHKDFAlg, int(shares.DEKBytes), aeadSegmentSize, aeadFirstSegmentOffset)
	if err != nil {
		return fmt.Errorf("unable to create new cipher: %v", err)
	}

	writer, err := cipher.NewEncryptingWriter(output, aad)
	if err != nil {
		return fmt.Errorf("unable to create encrypt writer: %v", err)
	}

	if _, err := io.Copy(writer, input); err != nil {
		return fmt.Errorf("failed to encrypt: %v", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("error closing writer: %v", err)
	}

	return nil
}

// AeadDecrypt uses the provided key and AAD to decode the ciphertext passed
// in via `input`, writing the output to `output.
func AeadDecrypt(key shares.DEK, input io.Reader, output io.Writer, aad []byte) error {
	cipher, err := subtle.NewAESGCMHKDF(key[:], aeadHKDFAlg, int(shares.DEKBytes), aeadSegmentSize, aeadFirstSegmentOffset)
	if err != nil {
		return fmt.Errorf("unable to create new cipher: %v", err)
	}

	reader, err := cipher.NewDecryptingReader(input, aad)
	if err != nil {
		return fmt.Errorf("unable to create decrypt reader: %v", err)
	}

	if _, err := io.Copy(output, reader); err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}

	return nil
}

///////////////////////////////////////////////////
// For reading and writing STET-encrypted files. //
///////////////////////////////////////////////////
//
// The v1 file format of a STET-encrypted file is a concatenation of
// a 16 byte STET header, a serialized configpb.Metadata proto, and
// the raw ciphertext bytes, with no padding.
//
// STET Header (16 bytes):
// - "STETENCRYPTED" magic string (13 bytes)
// - file format version (1 byte)
// - serialized metadata length (2 bytes)
//
// Metadata:
// - serialized proto with the length specified in the header
//
// Ciphertext:
// - raw encrypted bytes, extending to the end of the file

// STETMagic is the magic string for a STET encrypted file header ("STETENCRYPTED").
var STETMagic = [13]byte{'S', 'T', 'E', 'T', 'E', 'N', 'C', 'R', 'Y', 'P', 'T', 'E', 'D'}

// STETHeader is the file header for the encrypted STET file format.
type STETHeader struct {
	Magic       [13]byte // len([]byte(STETMagic)) == 13
	Version     uint8    // 1 byte
	MetadataLen uint16   // 2 bytes
}

// ReadSTETHeader reads a STET encrypted file header from `input`, returning a STETHeader.
func ReadSTETHeader(input io.Reader) (*STETHeader, error) {
	var header STETHeader
	if err := binary.Read(input, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("failed to read STET encrypted header: %v", err)
	}

	if !bytes.Equal(header.Magic[:], STETMagic[:]) {
		return nil, fmt.Errorf("data is not a known STET encryption format")
	}

	return &header, nil
}

// WriteSTETHeader writes a STET encrypted file header with the given properties to `output`.
func WriteSTETHeader(output io.Writer, metadataLen int) error {
	header := STETHeader{
		Magic:       STETMagic,
		Version:     1,
		MetadataLen: uint16(metadataLen),
	}

	return binary.Write(output, binary.LittleEndian, header)
}

/////////////////////////////////////////////////
// For dealing with RSA keys and fingerprints. //
/////////////////////////////////////////////////

// PublicKeyForRSAFingerprint Iterates through the public keys defined in `keys`, searching for one
// that matches `kek`. If one is found, returns it, otherwise returns nil.
func PublicKeyForRSAFingerprint(kek *configpb.KekInfo, keys *configpb.AsymmetricKeys) (*rsa.PublicKey, error) {
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

// PrivateKeyForRSAFingerprint iterates through the private keys defined in `keys`, searching for
// one that matches `kek`. If one is found, returns it, otherwise returns nil.
func PrivateKeyForRSAFingerprint(kek *configpb.KekInfo, keys *configpb.AsymmetricKeys) (*rsa.PrivateKey, error) {
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

////////////////////////////////////////////
// For metadata serialization operations. //
////////////////////////////////////////////

// MetadataToAAD processes metadata to use as AAD for AEAD Encryption.
// The serialization scheme is as follows (given n := len(md.shares)):
//
//	len(md.shares[0].wrappedShare)      || md.shares[0].wrappedShare
//	|| len(md.shares[0].hash)           || md.shares[0].hash
//	...
//	|| len(md.shares[n-1].wrappedShare) || md.shares[n-1].wrappedShare
//	|| len(md.shares[n-1].hash)         || md.shares[n-1].hash
//	|| len(md.blobID)                   || md.blobID
//
// Note that KeyConfig is explicitly omitted from the serialization,
// as its presence is not important to the AAD.
func MetadataToAAD(md *configpb.Metadata) ([]byte, error) {
	buf := new(bytes.Buffer)
	for _, share := range md.GetShares() {
		// Serialize share.wrappedShare
		if err := binary.Write(buf, binary.LittleEndian, uint64(len(share.GetShare()))); err != nil {
			return nil, fmt.Errorf("unable to serialize length of wrapped share: %v", err)
		}

		if _, err := buf.Write(share.GetShare()); err != nil {
			return nil, fmt.Errorf("unable to serialize wrapped share: %v", err)
		}

		// Serialize share.hash
		if err := binary.Write(buf, binary.LittleEndian, uint64(sha256.Size)); err != nil {
			return nil, fmt.Errorf("unable to serialize length of hashed share: %v", err)
		}

		if _, err := buf.Write(share.GetHash()); err != nil {
			return nil, fmt.Errorf("unable to serialize hashed share: %v", err)
		}
	}

	// Serialize blobID.
	if err := binary.Write(buf, binary.LittleEndian, uint64(len([]byte(md.GetBlobId())))); err != nil {
		return nil, fmt.Errorf("unable to serialize length of blobID: %v", err)
	}

	if _, err := buf.WriteString(md.GetBlobId()); err != nil {
		return nil, fmt.Errorf("unable to serialize blobID: %v", md.GetBlobId())
	}

	return buf.Bytes(), nil
}

// ReadMetadata parses and returns metadata from the input.
func ReadMetadata(input io.Reader) (*configpb.Metadata, error) {
	// Read the STET header from the given `input`.
	header, err := ReadSTETHeader(input)
	if err != nil {
		return nil, fmt.Errorf("failed to read STET encrypted file header: %v", err)
	}

	// Based on the metadata length in `header`, read metadata from `input`.
	metadataBytes := make([]byte, header.MetadataLen)
	if _, err := input.Read(metadataBytes); err != nil {
		return nil, fmt.Errorf("failed to read encrypted file metadata: %v", err)
	}

	metadata := &configpb.Metadata{}
	if err := proto.Unmarshal(metadataBytes, metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata proto: %v", err)
	}

	return metadata, nil
}
