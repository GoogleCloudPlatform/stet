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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"hash/crc32"
	"io"
	"net/url"
	"path"
	"strings"

	"cloud.google.com/go/kms/apiv1"
	configpb "github.com/GoogleCloudPlatform/stet/proto/config_go_proto"
	glog "github.com/golang/glog"
	"github.com/google/uuid"
	"github.com/googleapis/gax-go"
	"google.golang.org/api/option"
	rpb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	spb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/protobuf/proto"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	// Identifier for GCP KMS used in KEK URIs, from https://developers.google.com/tink/get-key-uri
	gcpKeyPrefix = "gcp-kms://"
)

// StetMetadata represents metadata associated with data encrypted/decrypted by the client.
type StetMetadata struct {
	KeyUris []string
	BlobID  string
}

// unwrappedShare represents an unwrapped share and its associated external URI.
type unwrappedShare struct {
	share []byte
	uri   string
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
	// Client for performing Cloud KMS operations. Initialized via initializeKMSClient.
	kmsClient cloudKMSClient

	// Fake Cloud KMS Client for testing purposes.
	fakeKeyManagementClient cloudKMSClient

	// Fake Secure Session Client for testing purposes.
	fakeSecureSessionClient secureSessionClient

	// Whether to skip verification of the inner TLS session cert.
	InsecureSkipVerify bool

	// The version of STET, if set. This is used to construct user agent
	// strings for Cloud KMS requests.
	Version string
}

// initializeKMSClient initializes the StetClient's `kmsClient`.
// Performs a no-op if it has already been initialized.
func (c *StetClient) initializeKMSClient(ctx context.Context) error {
	// Don't double-initialize a real KMS client.
	if c.kmsClient != nil {
		return nil
	}

	// Use the fake key management client if one was configured, otherwise initialize a real one.
	if c.fakeKeyManagementClient != nil {
		c.kmsClient = c.fakeKeyManagementClient
	} else {
		var err error

		// Set user agent for Cloud KMS API calls.
		ua := "STET/"
		if c.Version != "" {
			ua += c.Version
		} else {
			ua += "dev"
		}

		c.kmsClient, err = kms.NewKeyManagementClient(ctx, option.WithUserAgent(ua))
		if err != nil {
			return fmt.Errorf("error creating KMS client: %v", err)
		}
	}

	return nil
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

	addr := fmt.Sprintf("%s://%s", u.Scheme, u.Hostname())
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

		ekmClient, err = EstablishSecureSession(ctx, md.uri, authToken, SkipTLSVerify(c.InsecureSkipVerify))
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

		ekmClient, err = EstablishSecureSession(ctx, md.uri, authToken, SkipTLSVerify(c.InsecureSkipVerify))
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

func crc32c(data []byte) uint32 {
	t := crc32.MakeTable(crc32.Castagnoli)
	return crc32.Checksum(data, t)
}

// wrapKMSShare uses a KMS client to wrap the given share using Cloud KMS.
func (c *StetClient) wrapKMSShare(ctx context.Context, share []byte, keyName string) ([]byte, error) {
	req := &spb.EncryptRequest{
		Name:            keyName,
		Plaintext:       share,
		PlaintextCrc32C: wrapperspb.Int64(int64(crc32c(share))),
	}

	result, err := c.kmsClient.Encrypt(ctx, req)
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
func (c *StetClient) protectionLevelsAndUris(ctx context.Context, kekInfos []*configpb.KekInfo) ([]kekMetadata, error) {
	var kekMetadatas []kekMetadata
	for _, kekInfo := range kekInfos {
		kmd := kekMetadata{}

		// Cloud KMS only needs to be queried if a KEK URI is specified (eg. not an RSA fingerprint).
		switch kekInfo.GetKekType().(type) {
		case *configpb.KekInfo_KekUri:
			uri := kekInfo.GetKekUri()
			// Verify that the URI indicates a GCP KMS key.
			if !strings.HasPrefix(uri, gcpKeyPrefix) {
				return nil, fmt.Errorf("%v does not have the expected URI prefix, want %v", uri, gcpKeyPrefix)
			}

			cryptoKey, err := c.kmsClient.GetCryptoKey(ctx, &spb.GetCryptoKeyRequest{Name: strings.TrimPrefix(uri, gcpKeyPrefix)})
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

			kmd.protectionLevel = cryptoKeyVer.GetProtectionLevel()

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
		}

		kekMetadatas = append(kekMetadatas, kmd)
	}

	return kekMetadatas, nil
}

// wrapShares encrypts the given shares using either the given key URIs or the
// asymmetric key provided in the corresponding KekInfo struct. It returns a
// list of wrapped shares, and a list of key URIs used for shares that were
// wrapped by communicating with an external KMS (these lists might not
// correspond one-to-one if some shares are wrapped via asymmetric key).
func (c *StetClient) wrapShares(ctx context.Context, unwrappedShares [][]byte, kekInfos []*configpb.KekInfo, keys *configpb.AsymmetricKeys) (wrappedShares []*configpb.WrappedShare, keyURIs []string, err error) {
	if len(unwrappedShares) != len(kekInfos) {
		return nil, nil, fmt.Errorf("number of shares to wrap (%d) does not match number of KEKs (%d)", len(unwrappedShares), len(kekInfos))
	}

	// Gets populated once the first non-local key is seen.
	var kekMetadatas []kekMetadata

	for i, share := range unwrappedShares {
		wrapped := &configpb.WrappedShare{
			Hash: HashShare(share),
		}

		kek := kekInfos[i]

		switch x := kek.KekType.(type) {
		case *configpb.KekInfo_RsaFingerprint:
			key, err := publicKeyForRSAFingerprint(kek, keys)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to find public key for RSA fingerprint: %w", err)
			}

			wrapped.Share, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, key, share, nil)
			if err != nil {
				return nil, nil, fmt.Errorf("error wrapping key share: %v", err)
			}

		case *configpb.KekInfo_KekUri:
			// Instantiate `kmsClient` and populate `kekMetadatas` if not already done.
			if err := c.initializeKMSClient(ctx); err != nil {
				return nil, nil, fmt.Errorf("error initializing KMS Client: %v", err)
			}
			defer c.kmsClient.Close()

			if kekMetadatas == nil {
				var err error
				kekMetadatas, err = c.protectionLevelsAndUris(ctx, kekInfos)
				if err != nil {
					return nil, nil, fmt.Errorf("Error retrieving KEK Metadata: %v", err)
				}
			}

			// Wrap share via KMS.
			switch pl := kekMetadatas[i].protectionLevel; pl {
			case rpb.ProtectionLevel_SOFTWARE, rpb.ProtectionLevel_HSM:
				var err error
				wrapped.Share, err = c.wrapKMSShare(ctx, share, kekMetadatas[i].resourceName)
				if err != nil {
					return nil, nil, fmt.Errorf("error wrapping key share: %v", err)
				}
			case rpb.ProtectionLevel_EXTERNAL:
				ekmWrappedShare, err := c.ekmSecureSessionWrap(ctx, share, kekMetadatas[i])
				if err != nil {
					return nil, nil, fmt.Errorf("error wrapping with secure session: %v", err)
				}

				wrapped.Share = ekmWrappedShare
			default:
				return nil, nil, fmt.Errorf("unsupported protection level %v", pl)
			}

			// Return the URI used: the Cloud KMS one in the case of a software
			// or HSM key, and the external key URI for an external key.
			keyURIs = append(keyURIs, kekMetadatas[i].uri)

		default:
			return nil, nil, fmt.Errorf("unsupported KekInfo type: %v", x)
		}

		wrappedShares = append(wrappedShares, wrapped)
	}

	return wrappedShares, keyURIs, nil
}

// unwrapKMSShare uses a KMS client to unwrap the given share using Cloud KMS.
func (c *StetClient) unwrapKMSShare(ctx context.Context, wrappedShare []byte, keyName string) ([]byte, error) {
	req := &spb.DecryptRequest{
		Name:             keyName,
		Ciphertext:       wrappedShare,
		CiphertextCrc32C: wrapperspb.Int64(int64(crc32c(wrappedShare))),
	}

	result, err := c.kmsClient.Decrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext: %v", err)
	}

	if int64(crc32c(result.Plaintext)) != result.PlaintextCrc32C.Value {
		return nil, fmt.Errorf("Decrypt: response corrupted in-transit")
	}
	return result.Plaintext, nil
}

// unwrapAndValidateShares decrypts the given wrapped share based on its URI.
func (c *StetClient) unwrapAndValidateShares(ctx context.Context, wrappedShares []*configpb.WrappedShare, kekInfos []*configpb.KekInfo, keys *configpb.AsymmetricKeys) ([]unwrappedShare, error) {
	if len(wrappedShares) != len(kekInfos) {
		return nil, fmt.Errorf("number of shares to unwrap (%d) does not match number of KEKs (%d)", len(wrappedShares), len(kekInfos))
	}

	// Gets populated once the first non-local key is seen.
	var kekMetadatas []kekMetadata

	// In order to support k-of-n decryption, don't exit early if share
	// share unwrapping fails. Attempt to unwrap all shares and just
	// return the subset of ones that succeeded, and let the Shamir's
	// implementation handle the subset of shares.
	var unwrappedShares []unwrappedShare
	for i, wrapped := range wrappedShares {
		glog.Infof("Attempting to unwrap share #%v", i+1)
		unwrapped := unwrappedShare{}
		kek := kekInfos[i]

		switch x := kek.KekType.(type) {
		case *configpb.KekInfo_RsaFingerprint:
			key, err := privateKeyForRSAFingerprint(kek, keys)
			if err != nil {
				glog.Warningf("Failed to find public key for RSA fingerprint: %v", err)
				continue
			}

			unwrapped.share, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, key, wrapped.GetShare(), nil)
			if err != nil {
				glog.Warningf("Error unwrapping key share: %v", err)
				continue
			}

		case *configpb.KekInfo_KekUri:
			// Instantiate `kmsClient` and populate `kekMetadatas` if not already done.
			if err := c.initializeKMSClient(ctx); err != nil {
				glog.Warningf("Error initializing Cloud KMS Client: %v", err)
				continue
			}
			defer c.kmsClient.Close()

			if kekMetadatas == nil {
				var err error
				kekMetadatas, err = c.protectionLevelsAndUris(ctx, kekInfos)
				if err != nil {
					glog.Warningf("Error retrieving KEK Metadata: %v", err)
					continue
				}
			}

			// Unwrap share via KMS.
			var err error
			switch pl := kekMetadatas[i].protectionLevel; pl {
			case rpb.ProtectionLevel_SOFTWARE, rpb.ProtectionLevel_HSM:
				unwrapped.share, err = c.unwrapKMSShare(ctx, wrapped.GetShare(), kekMetadatas[i].resourceName)
				if err != nil {
					glog.Warningf("Error unwrapping key share: %v", err)
					continue
				}
			case rpb.ProtectionLevel_EXTERNAL:
				unwrapped.share, err = c.ekmSecureSessionUnwrap(ctx, wrapped.GetShare(), kekMetadatas[i])
				if err != nil {
					glog.Warningf("Error unwrapping with external EKM for %v: %v", kekMetadatas[i].uri, err)
					continue
				}
			default:
				glog.Warningf("Unsupported protection level %v", pl)
				continue
			}

			// Return the URI used: the Cloud KMS one in the case of a software
			// or HSM key, and the external key URI for an external key.
			unwrapped.uri = kekMetadatas[i].uri

		default:
			glog.Warningf("Unsupported KekInfo type: %v", x)
			continue
		}

		if !ValidateShare(unwrapped.share, wrapped.GetHash()) {
			glog.Warningf("Unwrapped share %v does not have the expected hash", i)
			continue
		}

		glog.Infof("Successfully unwrapped share #%v", i+1)
		unwrappedShares = append(unwrappedShares, unwrapped)
	}

	return unwrappedShares, nil
}

// Encrypt generates a DEK and creates EncryptedData in accordance with the EKM encryption protocol.
func (c *StetClient) Encrypt(ctx context.Context, input io.Reader, output io.Writer, config *configpb.EncryptConfig, keys *configpb.AsymmetricKeys, blobID string) (*StetMetadata, error) {
	if config == nil {
		return nil, fmt.Errorf("nil EncryptConfig passed to Encrypt()")
	}

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
		return nil, fmt.Errorf("unknown key splitting algorithm")
	}

	metadata.KeyConfig = keyCfg

	var err error
	var keyURIs []string
	metadata.Shares, keyURIs, err = c.wrapShares(ctx, shares, keyCfg.GetKekInfos(), keys)
	if err != nil {
		return nil, fmt.Errorf("error wrapping shares: %v", err)
	}

	// Create AAD from metadata.
	aad, err := metadataToAAD(metadata)
	if err != nil {
		return nil, fmt.Errorf("error serializing metadata: %v", err)
	}

	// Marshal the metadata into serialized bytes.
	metadataBytes, err := proto.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize metadata: %v", err)
	}

	// Write the header and metadata to `output`.
	if err := writeHeader(output, len(metadataBytes)); err != nil {
		return nil, fmt.Errorf("failed to write encrypted file header: %v", err)
	}

	if _, err := output.Write(metadataBytes); err != nil {
		return nil, fmt.Errorf("failed to write metadata: %v", err)
	}

	// Pass `output` to the AEAD encryption function to write the ciphertext.
	if err := aeadEncrypt(dataEncryptionKey, input, output, aad); err != nil {
		return nil, fmt.Errorf("error encrypting data: %v", err)
	}

	return &StetMetadata{
		KeyUris: keyURIs,
		BlobID:  metadata.GetBlobId(),
	}, nil
}

// Decrypt writes the decrypted data to the `output` writer, and returns the
// key URIs used during decryption and the blob ID decrypted.
func (c *StetClient) Decrypt(ctx context.Context, input io.Reader, output io.Writer, config *configpb.DecryptConfig, keys *configpb.AsymmetricKeys) (*StetMetadata, error) {
	if config == nil {
		return nil, fmt.Errorf("nil DecryptConfig passed to Decrypt()")
	}

	// Read the STET header from the given `input`.
	header, err := readHeader(input)
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

	// Find matching KeyConfig.
	var matchingKeyConfig *configpb.KeyConfig

	for _, keyCfg := range config.GetKeyConfigs() {
		if proto.Equal(keyCfg, metadata.GetKeyConfig()) {
			matchingKeyConfig = keyCfg
			break
		}
	}

	if matchingKeyConfig == nil {
		return nil, fmt.Errorf("no known KeyConfig matches given data")
	}

	// Unwrap shares and validate.
	unwrappedShares, err := c.unwrapAndValidateShares(ctx, metadata.GetShares(), matchingKeyConfig.GetKekInfos(), keys)
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

		combinedShares = unwrappedShares[0].share

	// Reverse Shamir's Secret Sharing to reconstitute the whole DEK.
	case *configpb.KeyConfig_Shamir:
		if len(unwrappedShares) < int(matchingKeyConfig.GetShamir().GetThreshold()) {
			return nil, fmt.Errorf("only successfully unwrapped %v shares, which is fewer than threshold of %v", len(unwrappedShares), matchingKeyConfig.GetShamir().GetThreshold())
		}

		var shares [][]byte
		for _, share := range unwrappedShares {
			shares = append(shares, share.share)
		}

		var err error
		combinedShares, err = CombineShares(shares)
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
	aad, err := metadataToAAD(metadata)
	if err != nil {
		return nil, fmt.Errorf("error serializing metadata: %v", err)
	}

	// Now `input` is at the start of ciphertext to pass to Tink.
	if err := aeadDecrypt(combinedDEK, input, output, aad); err != nil {
		return nil, fmt.Errorf("error decrypting data: %v", err)
	}

	// Return URIs of keys used during decryption.
	var keyURIs []string
	for _, unwrapped := range unwrappedShares {
		if unwrapped.uri != "" {
			keyURIs = append(keyURIs, unwrapped.uri)
		}
	}

	return &StetMetadata{
		KeyUris: keyURIs,
		BlobID:  metadata.GetBlobId(),
	}, nil
}
