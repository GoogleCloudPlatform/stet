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

// Package client is the client library for STET.
package client

import (
	"context"
	"fmt"
	"hash/crc32"
	"net/url"
	"path"
	"strings"

	"cloud.google.com/go/kms/apiv1"
	configpb "github.com/GoogleCloudPlatform/stet/proto/config_go_proto"
	"github.com/google/uuid"
	"github.com/googleapis/gax-go"
	rpb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	spb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/protobuf/proto"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	// Identifier for GCP KMS used in KEK URIs, from https://developers.google.com/tink/get-key-uri
	gcpKeyPrefix = "gcp-kms://"
	proxyPort    = 8842
)

// DecryptedData represents data decrypted by the client and the associated metadata.
type DecryptedData struct {
	Plaintext []byte
	KeyUris   []string
	BlobID    string
}

type cloudKMSClient interface {
	GetCryptoKey(context.Context, *spb.GetCryptoKeyRequest, ...gax.CallOption) (*rpb.CryptoKey, error)
	Encrypt(context.Context, *spb.EncryptRequest, ...gax.CallOption) (*spb.EncryptResponse, error)
	Decrypt(context.Context, *spb.DecryptRequest, ...gax.CallOption) (*spb.DecryptResponse, error)
	Close() error
}

type secureSessionClient interface {
	ConfidentialWrap(ctx context.Context, keyPath string, resourceName string, plaintext []byte) ([]byte, error)
	ConfidentialUnwrap(ctx context.Context, keyPath string, resourceName string, wrappedBlob []byte) ([]byte, error)
	EndSession(context.Context) error
}

// StetClient provides Encryption and Decryption services through the Split Trust Encryption Tool.
type StetClient struct {
	// Fake Cloud KMS Client for testing purposes.
	fakeKeyManagementClient cloudKMSClient

	// Fake Secure Session Client for testing purposes.
	fakeSecureSessionClient secureSessionClient
}

// setFakeKeyManagementClient allows a fake Cloud KMS client to be configured for testing purposes.
func (c *StetClient) setFakeKeyManagementClient(fakeClient cloudKMSClient) {
	c.fakeKeyManagementClient = fakeClient
}

// setFakeSecureSessionClient allows a fake Secure Session client to be configured for testing purposes.
func (c *StetClient) setFakeSecureSessionClient(fakeClient secureSessionClient) {
	c.fakeSecureSessionClient = fakeClient
}

// parseEKMKeyURI takes in the key URI for a key stored in an EKM, and returns
// the address for connecting to the EKM, and the key path for the resource.
func parseEKMKeyURI(keyURI string) (string, string, error) {
	u, err := url.Parse(keyURI)
	if err != nil {
		return "", "", fmt.Errorf("could not parse: %v", err)
	}

	addr := fmt.Sprintf("%s://%s:%v", u.Scheme, u.Hostname(), proxyPort)
	return addr, path.Base(keyURI), nil
}

// ekmSecureSessionWrap creates a secure session with the external EKM denoted by the given URI, and uses it to encrypt unwrappedShare.
func (c *StetClient) ekmSecureSessionWrap(ctx context.Context, unwrappedShare []byte, md kekMetadata) ([]byte, error) {
	addr, keyPath, err := parseEKMKeyURI(md.uri)
	if err != nil {
		return nil, err
	}

	var ekmClient secureSessionClient
	if c.fakeSecureSessionClient != nil {
		ekmClient = c.fakeSecureSessionClient
	} else {
		authToken, err := generateTokenFromEKMAddress(ctx, addr)
		if err != nil {
			return nil, err
		}

		rpcAddr, err := removeSchemeFromURL(addr)
		if err != nil {
			return nil, err
		}

		ekmClient, err = EstablishSecureSession(ctx, rpcAddr, authToken)
		if err != nil {
			return nil, fmt.Errorf("error establishing secure session: %v", err)
		}
	}

	wrappedBlob, err := ekmClient.ConfidentialWrap(ctx, keyPath, md.resourceName, unwrappedShare)
	if err != nil {
		return nil, fmt.Errorf("error wrapping with secure session: %v", err)
	}

	if err := ekmClient.EndSession(ctx); err != nil {
		return nil, fmt.Errorf("error ending secure session: %v", err)
	}

	return wrappedBlob, nil
}

// ekmSecureSessionUnwrap creates a secure session with the external EKM denoted by the given URI, and uses it to decrypt wrappedShare.
func (c *StetClient) ekmSecureSessionUnwrap(ctx context.Context, wrappedShare []byte, md kekMetadata) ([]byte, error) {
	addr, keyPath, err := parseEKMKeyURI(md.uri)
	if err != nil {
		return nil, err
	}

	var ekmClient secureSessionClient
	if c.fakeSecureSessionClient != nil {
		ekmClient = c.fakeSecureSessionClient
	} else {
		authToken, err := generateTokenFromEKMAddress(ctx, addr)
		if err != nil {
			return nil, err
		}

		rpcAddr, err := removeSchemeFromURL(addr)
		if err != nil {
			return nil, err
		}

		ekmClient, err = EstablishSecureSession(ctx, rpcAddr, authToken)
		if err != nil {
			return nil, fmt.Errorf("error establishing secure session: %v", err)
		}
	}

	unwrappedBlob, err := ekmClient.ConfidentialUnwrap(ctx, keyPath, md.resourceName, wrappedShare)
	if err != nil {
		return nil, fmt.Errorf("error unwrapping with secure session: %v", err)
	}

	if err := ekmClient.EndSession(ctx); err != nil {
		return nil, fmt.Errorf("error ending secure session: %v", err)
	}

	return unwrappedBlob, nil
}

// Generates an JWT with the FQDN of the given address as its audience.
func generateTokenFromEKMAddress(ctx context.Context, address string) (string, error) {
	u, err := url.Parse(address)
	if err != nil {
		return "", fmt.Errorf("could not parse EKM address: %v", err)
	}

	audience := fmt.Sprintf("%v://%v", u.Scheme, u.Hostname())

	var authToken string
	if authToken, err = GenerateJWT(ctx, audience); err != nil {
		return "", fmt.Errorf("failed to generate JWT: %v", err)
	}

	return authToken, nil
}

// Remove scheme from the EKM address URL to dial gRPC correctly.
func removeSchemeFromURL(ekmURL string) (string, error) {
	u, err := url.Parse(ekmURL)
	if err != nil {
		return "", fmt.Errorf("could not extract host from EKM address: %v", err)
	}

	return u.Host, nil
}

func crc32c(data []byte) uint32 {
	t := crc32.MakeTable(crc32.Castagnoli)
	return crc32.Checksum(data, t)
}

func wrapKMSShare(ctx context.Context, kmsClient cloudKMSClient, share []byte, keyName string) ([]byte, error) {
	req := &spb.EncryptRequest{
		Name:            keyName,
		Plaintext:       share,
		PlaintextCrc32C: wrapperspb.Int64(int64(crc32c(share))),
	}

	result, err := kmsClient.Encrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %v", err)
	}

	if !result.VerifiedPlaintextCrc32C {
		return nil, fmt.Errorf("Encrypt: request corrupted in-transit")
	}
	if int64(crc32c(result.Ciphertext)) != result.CiphertextCrc32C.Value {
		return nil, fmt.Errorf("Encrypt: response corrupted in-transit")
	}
	return result.Ciphertext, nil
}

type kekMetadata struct {
	protectionLevel rpb.ProtectionLevel
	uri             string
	resourceName    string
}

// protectionLevelsAndUris takes a list of KekInfos and queries Cloud KMS for the corresponding protection levels and URIs.
func protectionLevelsAndUris(ctx context.Context, kmsClient cloudKMSClient, kekInfos []*configpb.KekInfo) ([]kekMetadata, error) {
	var kekMetadatas []kekMetadata
	for _, kekInfo := range kekInfos {
		uri := kekInfo.GetKekUri()
		// Verify that the URI indicates a GCP KMS key.
		if !strings.HasPrefix(uri, gcpKeyPrefix) {
			return nil, fmt.Errorf("%v does not have the expected URI prefix, want %v", uri, gcpKeyPrefix)
		}

		cryptoKey, err := kmsClient.GetCryptoKey(ctx, &spb.GetCryptoKeyRequest{Name: strings.TrimPrefix(uri, gcpKeyPrefix)})
		if err != nil {
			return nil, fmt.Errorf("error retrieving key metadata: %v", err)
		}

		cryptoKeyVer := cryptoKey.GetPrimary()
		if cryptoKeyVer.GetState() != rpb.CryptoKeyVersion_ENABLED {
			return nil, fmt.Errorf("CryptoKeyVersion for %v is not enabled", uri)
		}

		if cryptoKeyVer.ProtectionLevel == rpb.ProtectionLevel_PROTECTION_LEVEL_UNSPECIFIED {
			return nil, fmt.Errorf("unspecified protection level %v", cryptoKeyVer.GetProtectionLevel())
		}

		kmd := kekMetadata{
			protectionLevel: cryptoKeyVer.GetProtectionLevel(),
		}

		if cryptoKeyVer.ProtectionLevel == rpb.ProtectionLevel_EXTERNAL {
			if cryptoKeyVer.ExternalProtectionLevelOptions == nil {
				return nil, fmt.Errorf("CryptoKeyVersion for KEK %s does not have external protection level options despite being EXTERNAL protection level", uri)
			}

			// Use external URI to unwrap with.
			kmd.uri = cryptoKeyVer.GetExternalProtectionLevelOptions().GetExternalKeyUri()
		} else {
			kmd.uri = uri
		}

		kmd.resourceName = strings.TrimPrefix(uri, gcpKeyPrefix)

		kekMetadatas = append(kekMetadatas, kmd)
	}

	return kekMetadatas, nil
}

// wrapShares encrypts the given shares based on their URIs.
func (c *StetClient) wrapShares(ctx context.Context, unwrappedShares [][]byte, kekInfos []*configpb.KekInfo) ([]*configpb.WrappedShare, error) {
	var kmsClient cloudKMSClient
	// Use the fake key management client if one was configured, otherwise initialize a real one.
	if c.fakeKeyManagementClient != nil {
		kmsClient = c.fakeKeyManagementClient
	} else {
		var err error
		kmsClient, err = kms.NewKeyManagementClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("error creating KMS client: %v", err)
		}
	}
	defer kmsClient.Close()

	if len(unwrappedShares) != len(kekInfos) {
		return nil, fmt.Errorf("number of shares to wrap (%d) does not match number of KEKs (%d)", len(unwrappedShares), len(kekInfos))
	}

	kekMetadatas, err := protectionLevelsAndUris(ctx, kmsClient, kekInfos)
	if err != nil {
		return nil, fmt.Errorf("Error retrieving KEK Metadata: %v", err)
	}

	var wrappedShares []*configpb.WrappedShare
	for i, share := range unwrappedShares {
		wrapped := &configpb.WrappedShare{
			Hash: HashShare(share),
		}

		switch pl := kekMetadatas[i].protectionLevel; pl {
		case rpb.ProtectionLevel_SOFTWARE, rpb.ProtectionLevel_HSM:
			wrapped.Share, err = wrapKMSShare(ctx, kmsClient, share, kekMetadatas[i].resourceName)
			if err != nil {
				return nil, fmt.Errorf("error wrapping key share: %v", err)
			}
		case rpb.ProtectionLevel_EXTERNAL:
			ekmWrappedShare, err := c.ekmSecureSessionWrap(ctx, share, kekMetadatas[i])
			if err != nil {
				return nil, fmt.Errorf("error wrapping with secure session: %v", err)
			}

			wrapped.Share = ekmWrappedShare
		default:
			return nil, fmt.Errorf("unsupported protection level %v", pl)
		}

		wrappedShares = append(wrappedShares, wrapped)
	}

	return wrappedShares, nil
}

func unwrapKMSShare(ctx context.Context, kmsClient cloudKMSClient, wrappedShare []byte, keyName string) ([]byte, error) {

	req := &spb.DecryptRequest{
		Name:             keyName,
		Ciphertext:       wrappedShare,
		CiphertextCrc32C: wrapperspb.Int64(int64(crc32c(wrappedShare))),
	}

	result, err := kmsClient.Decrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext: %v", err)
	}

	if int64(crc32c(result.Plaintext)) != result.PlaintextCrc32C.Value {
		return nil, fmt.Errorf("Decrypt: response corrupted in-transit")
	}
	return result.Plaintext, nil
}

// unwrapAndValidateShares decrypts the given wrapped share based on its URI.
func (c *StetClient) unwrapAndValidateShares(ctx context.Context, wrappedShares []*configpb.WrappedShare, kekInfos []*configpb.KekInfo) ([][]byte, error) {
	var kmsClient cloudKMSClient
	// Use the fake key management client if one was configured, otherwise initialize a real one.
	if c.fakeKeyManagementClient != nil {
		kmsClient = c.fakeKeyManagementClient
	} else {
		var err error
		kmsClient, err = kms.NewKeyManagementClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("error creating KMS client: %v", err)
		}
	}
	defer kmsClient.Close()

	if len(wrappedShares) != len(kekInfos) {
		return nil, fmt.Errorf("number of shares to unwrap (%d) does not match number of KEKs (%d)", len(wrappedShares), len(kekInfos))
	}

	kekMetadatas, err := protectionLevelsAndUris(ctx, kmsClient, kekInfos)
	if err != nil {
		return nil, fmt.Errorf("Error retrieving KEK Metadata: %v", err)
	}

	var unwrappedShares [][]byte
	for i, wrapped := range wrappedShares {
		var unwrapped []byte
		switch pl := kekMetadatas[i].protectionLevel; pl {
		case rpb.ProtectionLevel_SOFTWARE, rpb.ProtectionLevel_HSM:
			unwrapped, err = unwrapKMSShare(ctx, kmsClient, wrapped.GetShare(), kekMetadatas[i].resourceName)
			if err != nil {
				return nil, fmt.Errorf("error unwrapping key share: %v", err)
			}
		case rpb.ProtectionLevel_EXTERNAL:
			unwrapped, err = c.ekmSecureSessionUnwrap(ctx, wrapped.GetShare(), kekMetadatas[i])
			if err != nil {
				return nil, fmt.Errorf("error unwrapping with external EKM for %v: %v", kekMetadatas[i].uri, err)
			}
		default:
			return nil, fmt.Errorf("unsupported protection level %v", pl)
		}

		if !ValidateShare(unwrapped, wrapped.GetHash()) {
			return nil, fmt.Errorf("unwrapped share %v does not have the expected hash", i)
		}

		unwrappedShares = append(unwrappedShares, unwrapped)
	}

	return unwrappedShares, nil
}

// Encrypt generates a DEK and creates EncryptedData in accordance with the EKM encryption protocol.
func (c *StetClient) Encrypt(ctx context.Context, plaintext []byte, config *configpb.EncryptConfig, blobID string) (*configpb.EncryptedData, error) {
	// Create metadata.
	metadata := &configpb.Metadata{}

	// Set blob ID if specified, otherwise generate UUID.
	if blobID == "" {
		blobID = uuid.NewString()
	}
	metadata.BlobId = blobID

	keyCfg := config.GetKeyConfig()

	dataEncryptionKey := NewDEK()
	var shares [][]byte

	// Depending on the key splitting algorithm given in the KeyConfig, take
	// the DEK and split it, wrapping the resulting shares and writing them
	// back to the `Shares` field of `metadata`.
	switch keyCfg.KeySplittingAlgorithm.(type) {

	// Don't split the DEK.
	case *configpb.KeyConfig_NoSplit:
		if len(keyCfg.GetKekInfos()) != 1 {
			return nil, fmt.Errorf("invalid Encrypt configuration, number of KekInfos is %v but expected 1 for 'no split' option", len(keyCfg.GetKekInfos()))
		}

		shares = [][]byte{dataEncryptionKey[:]}

	// Split DEK with Shamir's Secret Sharing.
	case *configpb.KeyConfig_Shamir:
		shamirConfig := keyCfg.GetShamir()
		shamirShares := int(shamirConfig.GetShares())
		shamirThreshold := int(shamirConfig.GetThreshold())

		// The number of KEK Infos should match the number of shares to generate
		if len(keyCfg.GetKekInfos()) != shamirShares {
			return nil, fmt.Errorf("invalid Encrypt configuration, number of KEK Infos does not match the number of shares to generate: found %v KEK Infos, %v shares", len(keyCfg.GetKekInfos()), shamirShares)
		}

		var err error
		shares, err = SplitShares(dataEncryptionKey[:], shamirShares, shamirThreshold)
		if err != nil {
			return nil, fmt.Errorf("error splitting encryption key: %v", err)
		}

	default:
		return nil, fmt.Errorf("Unknown key splitting algorithm")
	}

	metadata.KeyConfig = keyCfg

	var err error
	metadata.Shares, err = c.wrapShares(ctx, shares, keyCfg.GetKekInfos())
	if err != nil {
		return nil, fmt.Errorf("Error wrapping shares: %v", err)
	}

	// Create AAD from metadata and perform AEAD encryption.
	aad, err := metadataToAAD(metadata)
	if err != nil {
		return nil, fmt.Errorf("Error serializing metadata: %v", err)
	}

	ciphertext, err := aeadEncrypt(dataEncryptionKey, plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("error encrypting data: %v", err)
	}

	return &configpb.EncryptedData{
		Ciphertext: ciphertext,
		Metadata:   metadata,
	}, nil
}

// Decrypt returns the plaintext as bytes, the key URIs used during decryption,
// and the blob ID decrypted.
func (c *StetClient) Decrypt(ctx context.Context, data *configpb.EncryptedData, config *configpb.DecryptConfig) (*DecryptedData, error) {
	// Find matching KeyConfig.
	var matchingKeyConfig *configpb.KeyConfig

	for _, keyCfg := range config.GetKeyConfigs() {
		if proto.Equal(keyCfg, data.Metadata.GetKeyConfig()) {
			matchingKeyConfig = keyCfg
			break
		}
	}

	if matchingKeyConfig == nil {
		return nil, fmt.Errorf("no known KeyConfig matches given data")
	}

	// Unwrap shares and validate.
	unwrappedShares, err := c.unwrapAndValidateShares(ctx, data.Metadata.GetShares(), matchingKeyConfig.GetKekInfos())
	if err != nil {
		return nil, fmt.Errorf("error unwrapping and validating shares: %v", err)
	}

	// Reconstitute DEK.
	var combinedShares []byte

	switch matchingKeyConfig.KeySplittingAlgorithm.(type) {
	// DEK wasn't split, so combined shares is just the sole share.
	case *configpb.KeyConfig_NoSplit:
		if len(unwrappedShares) != 1 {
			return nil, fmt.Errorf("number of unwrapped shares is %v but expected 1 for 'no split' option", len(unwrappedShares))
		}

		combinedShares = unwrappedShares[0]

	// Reverse Shamir's Secret Sharing to reconstitute the whole DEK.
	case *configpb.KeyConfig_Shamir:
		var err error
		combinedShares, err = CombineShares(unwrappedShares)
		if err != nil {
			return nil, fmt.Errorf("Error combining DEK shares: %v", err)
		}

	default:
		return nil, fmt.Errorf("Unknown key splitting algorithm")

	}

	if len(combinedShares) != int(DEKBytes) {
		return nil, fmt.Errorf("Reconstituted DEK has the wrong length")
	}

	var combinedDEK DEK
	copy(combinedDEK[:], combinedShares)

	// Generate AAD and decrypt ciphertext.
	aad, err := metadataToAAD(data.Metadata)
	if err != nil {
		return nil, fmt.Errorf("error serializing metadata: %v", err)
	}

	plaintext, err := aeadDecrypt(combinedDEK, data.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %v", err)
	}

	// Extract key URIs from KeyConfigs.
	var keyURIs []string
	for _, kcfg := range config.GetKeyConfigs() {
		for _, uri := range kcfg.GetKekInfos() {
			keyURIs = append(keyURIs, uri.GetKekUri())
		}
	}

	return &DecryptedData{
		Plaintext: plaintext,
		KeyUris:   keyURIs,
		BlobID:    data.Metadata.GetBlobId(),
	}, nil
}
