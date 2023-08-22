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
	"io"
	"net/url"
	"path"
	"strings"

	"github.com/GoogleCloudPlatform/stet/client/cloudkms"
	"github.com/GoogleCloudPlatform/stet/client/confidentialspace"
	"github.com/GoogleCloudPlatform/stet/client/jwt"
	"github.com/GoogleCloudPlatform/stet/client/securesession"
	"github.com/GoogleCloudPlatform/stet/client/shares"
	configpb "github.com/GoogleCloudPlatform/stet/proto/config_go_proto"
	glog "github.com/golang/glog"
	"github.com/google/uuid"
	rpb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	spb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/protobuf/proto"
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

type secureSessionClient interface {
	ConfidentialWrap(ctx context.Context, keyPath string, resourceName string, plaintext []byte) ([]byte, error)
	ConfidentialUnwrap(ctx context.Context, keyPath string, resourceName string, wrappedBlob []byte) ([]byte, error)
	EndSession(context.Context) error
}

// StetClient provides Encryption and Decryption services through the Split Trust Encryption Tool.
type StetClient struct {
	// Contains test KMS clients.
	testKMSClients *cloudkms.ClientFactory

	// Fake Secure Session Client for testing purposes.
	fakeSecureSessionClient secureSessionClient

	// Whether to skip verification of the inner TLS session cert.
	InsecureSkipVerify bool

	// The version of STET, if set. This is used to construct user agent
	// strings for Cloud KMS requests.
	Version string
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
		authToken, err := jwt.GenerateTokenWithAudience(ctx, addr)
		if err != nil {
			return nil, err
		}

		ekmClient, err = securesession.EstablishSecureSession(ctx, md.uri, authToken, securesession.SkipTLSVerify(c.InsecureSkipVerify))
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
		authToken, err := jwt.GenerateTokenWithAudience(ctx, addr)
		if err != nil {
			return nil, err
		}

		ekmClient, err = securesession.EstablishSecureSession(ctx, md.uri, authToken, securesession.SkipTLSVerify(c.InsecureSkipVerify))
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

type kekMetadata struct {
	protectionLevel rpb.ProtectionLevel
	uri             string
	resourceName    string
}

// Retrieves the metadata of a CloudKMS KEK URI.
func getKekURIMetadata(ctx context.Context, kmsClient cloudkms.Client, kekInfo *configpb.KekInfo) (*kekMetadata, error) {
	_, ok := kekInfo.GetKekType().(*configpb.KekInfo_KekUri)
	// No-op if this does not describe a KEK URI.
	if !ok {
		return nil, fmt.Errorf("cannot retrieve KEK Metadata for a non-KEK")
	}

	kmd := &kekMetadata{}

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

	return kmd, nil
}

// wrapShares encrypts the given shares using either the given key URIs or the
// asymmetric key provided in the corresponding KekInfo struct. It returns a
// list of wrapped shares, and a list of key URIs used for shares that were
// wrapped by communicating with an external KMS (these lists might not
// correspond one-to-one if some shares are wrapped via asymmetric key).
type sharesOpts struct {
	kekInfos        []*configpb.KekInfo
	asymmetricKeys  *configpb.AsymmetricKeys
	confSpaceConfig *confidentialspace.Config
}

func (c *StetClient) wrapShares(ctx context.Context, unwrappedShares [][]byte, opts sharesOpts) (wrappedShares []*configpb.WrappedShare, keyURIs []string, err error) {
	if len(unwrappedShares) != len(opts.kekInfos) {
		return nil, nil, fmt.Errorf("number of shares to wrap (%d) does not match number of KEKs (%d)", len(unwrappedShares), len(opts.kekInfos))
	}

	var kmsClients *cloudkms.ClientFactory
	if c.testKMSClients != nil {
		kmsClients = c.testKMSClients
	} else {
		kmsClients = cloudkms.NewClientFactory(c.Version)
	}
	defer kmsClients.Close()

	for i, share := range unwrappedShares {
		wrapped := &configpb.WrappedShare{
			Hash: shares.HashShare(share),
		}

		kek := opts.kekInfos[i]

		switch x := kek.KekType.(type) {
		case *configpb.KekInfo_RsaFingerprint:
			key, err := PublicKeyForRSAFingerprint(kek, opts.asymmetricKeys)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to find public key for RSA fingerprint: %w", err)
			}

			wrapped.Share, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, key, share, nil)
			if err != nil {
				return nil, nil, fmt.Errorf("error wrapping key share: %v", err)
			}

		case *configpb.KekInfo_KekUri:
			// Configure CloudKMS Client, with Confidential Space credentials if applicable.
			creds := ""
			if opts.confSpaceConfig != nil {
				creds = opts.confSpaceConfig.FindMatchingCredentials(kek.GetKekUri(), configpb.CredentialMode_ENCRYPT_ONLY_MODE)
			}

			kmsClient, err := kmsClients.Client(ctx, creds)
			if err != nil {
				return nil, nil, fmt.Errorf("error initializing Cloud KMS Client with credentials \"%v\": %v", creds, err)
			}

			kmd, err := getKekURIMetadata(ctx, kmsClient, kek)
			if err != nil {
				return nil, nil, fmt.Errorf("Error retrieving KEK Metadata: %v", err)
			}

			// Wrap share via KMS.
			switch pl := kmd.protectionLevel; pl {
			case rpb.ProtectionLevel_SOFTWARE, rpb.ProtectionLevel_HSM:
				var err error

				wrapOpts := cloudkms.WrapOpts{
					Share:   share,
					KeyName: kmd.resourceName,
				}
				wrapped.Share, err = cloudkms.WrapShare(ctx, kmsClient, wrapOpts)
				if err != nil {
					return nil, nil, fmt.Errorf("error wrapping key share: %v", err)
				}
			case rpb.ProtectionLevel_EXTERNAL:
				ekmWrappedShare, err := c.ekmSecureSessionWrap(ctx, share, *kmd)
				if err != nil {
					return nil, nil, fmt.Errorf("error wrapping with secure session: %v", err)
				}

				wrapped.Share = ekmWrappedShare
			default:
				return nil, nil, fmt.Errorf("unsupported protection level %v", pl)
			}

			// Return the URI used: the Cloud KMS one in the case of a software
			// or HSM key, and the external key URI for an external key.
			keyURIs = append(keyURIs, kmd.uri)

		default:
			return nil, nil, fmt.Errorf("unsupported KekInfo type: %v", x)
		}

		wrappedShares = append(wrappedShares, wrapped)
	}

	return wrappedShares, keyURIs, nil
}

// unwrapAndValidateShares decrypts the given wrapped share based on its URI.
func (c *StetClient) unwrapAndValidateShares(ctx context.Context, wrappedShares []*configpb.WrappedShare, opts sharesOpts) ([]shares.UnwrappedShare, error) {
	if len(wrappedShares) != len(opts.kekInfos) {
		return nil, fmt.Errorf("number of shares to unwrap (%d) does not match number of KEKs (%d)", len(wrappedShares), len(opts.kekInfos))
	}

	var kmsClients *cloudkms.ClientFactory
	if c.testKMSClients != nil {
		kmsClients = c.testKMSClients
	} else {
		kmsClients = cloudkms.NewClientFactory(c.Version)
	}
	defer kmsClients.Close()

	// In order to support k-of-n decryption, don't exit early if share
	// share unwrapping fails. Attempt to unwrap all shares and just
	// return the subset of ones that succeeded, and let the Shamir's
	// implementation handle the subset of shares.
	var unwrappedShares []shares.UnwrappedShare
	for i, wrapped := range wrappedShares {
		glog.Infof("Attempting to unwrap share #%v", i+1)
		unwrapped := shares.UnwrappedShare{}
		kek := opts.kekInfos[i]

		switch x := kek.KekType.(type) {
		case *configpb.KekInfo_RsaFingerprint:
			key, err := PrivateKeyForRSAFingerprint(kek, opts.asymmetricKeys)
			if err != nil {
				glog.Warningf("Failed to find public key for RSA fingerprint: %v", err)
				continue
			}

			unwrapped.Share, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, key, wrapped.GetShare(), nil)
			if err != nil {
				glog.Warningf("Error unwrapping key share: %v", err)
				continue
			}

		case *configpb.KekInfo_KekUri:
			// Configure CloudKMS Client, with Confidential Space credentials if applicable.
			creds := ""
			if opts.confSpaceConfig != nil {
				creds = opts.confSpaceConfig.FindMatchingCredentials(kek.GetKekUri(), configpb.CredentialMode_DECRYPT_ONLY_MODE)
			}

			kmsClient, err := kmsClients.Client(ctx, creds)
			if err != nil {
				return nil, fmt.Errorf("error initializing Cloud KMS Client with credentials \"%v\": %v", creds, err)
			}

			kmd, err := getKekURIMetadata(ctx, kmsClient, kek)
			if err != nil {
				return nil, fmt.Errorf("Error retrieving KEK Metadata: %v", err)
			}

			// Unwrap share via KMS.
			switch pl := kmd.protectionLevel; pl {
			case rpb.ProtectionLevel_SOFTWARE, rpb.ProtectionLevel_HSM:
				unwrapOpts := cloudkms.UnwrapOpts{
					Share:   wrapped.GetShare(),
					KeyName: kmd.resourceName,
				}
				unwrapped.Share, err = cloudkms.UnwrapShare(ctx, kmsClient, unwrapOpts)
				if err != nil {
					glog.Warningf("Error unwrapping key share: %v", err)
					continue
				}
			case rpb.ProtectionLevel_EXTERNAL:
				unwrapped.Share, err = c.ekmSecureSessionUnwrap(ctx, wrapped.GetShare(), *kmd)
				if err != nil {
					glog.Warningf("Error unwrapping with external EKM for %v: %v", kmd.uri, err)
					continue
				}
			default:
				glog.Warningf("Unsupported protection level %v", pl)
				continue
			}

			// Return the URI used: the Cloud KMS one in the case of a software
			// or HSM key, and the external key URI for an external key.
			unwrapped.URI = kmd.uri

		default:
			glog.Warningf("Unsupported KekInfo type: %v", x)
			continue
		}

		if !shares.ValidateShare(unwrapped.Share, wrapped.GetHash()) {
			glog.Warningf("Unwrapped share %v does not have the expected hash", i)
			continue
		}

		glog.Infof("Successfully unwrapped share #%v", i+1)
		unwrappedShares = append(unwrappedShares, unwrapped)
	}

	return unwrappedShares, nil
}

// Encrypt generates a DEK and creates EncryptedData in accordance with the EKM encryption protocol.
func (c *StetClient) Encrypt(ctx context.Context, input io.Reader, output io.Writer, stetConfig *configpb.StetConfig, blobID string) (*StetMetadata, error) {
	config := stetConfig.GetEncryptConfig()
	if config == nil {
		return nil, fmt.Errorf("nil EncryptConfig passed to Encrypt()")
	}

	keyCfg := config.GetKeyConfig()
	dataEncryptionKey := shares.NewDEK()
	shares, err := shares.CreateDEKShares(dataEncryptionKey, keyCfg)
	if err != nil {
		return nil, fmt.Errorf("error creating DEK shares: %v", err)
	}

	// Set blob ID if specified, otherwise generate UUID.
	if blobID == "" {
		blobID = uuid.NewString()
	}

	// Create metadata.
	metadata := &configpb.Metadata{BlobId: blobID, KeyConfig: keyCfg}

	var keyURIs []string
	opts := sharesOpts{
		kekInfos:       keyCfg.GetKekInfos(),
		asymmetricKeys: stetConfig.GetAsymmetricKeys(),
	}
	if csConfigs := stetConfig.GetConfidentialSpaceConfigs(); csConfigs != nil {
		opts.confSpaceConfig = confidentialspace.NewConfig(csConfigs)
	}

	metadata.Shares, keyURIs, err = c.wrapShares(ctx, shares, opts)
	if err != nil {
		return nil, fmt.Errorf("error wrapping shares: %v", err)
	}

	// Create AAD from metadata.
	aad, err := MetadataToAAD(metadata)
	if err != nil {
		return nil, fmt.Errorf("error serializing metadata: %v", err)
	}

	// Marshal the metadata into serialized bytes.
	metadataBytes, err := proto.Marshal(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize metadata: %v", err)
	}

	// Write the header and metadata to `output`.
	if err := WriteSTETHeader(output, len(metadataBytes)); err != nil {
		return nil, fmt.Errorf("failed to write encrypted file header: %v", err)
	}

	if _, err := output.Write(metadataBytes); err != nil {
		return nil, fmt.Errorf("failed to write metadata: %v", err)
	}

	// Pass `output` to the AEAD encryption function to write the ciphertext.
	if err := AeadEncrypt(dataEncryptionKey, input, output, aad); err != nil {
		return nil, fmt.Errorf("error encrypting data: %v", err)
	}

	return &StetMetadata{
		KeyUris: keyURIs,
		BlobID:  metadata.GetBlobId(),
	}, nil

}

// Decrypt writes the decrypted data to the `output` writer, and returns the
// key URIs used during decryption and the blob ID decrypted.
func (c *StetClient) Decrypt(ctx context.Context, input io.Reader, output io.Writer, stetConfig *configpb.StetConfig) (*StetMetadata, error) {
	config := stetConfig.GetDecryptConfig()
	if config == nil {
		return nil, fmt.Errorf("nil DecryptConfig passed to Decrypt()")
	}

	metadata, err := ReadMetadata(input)
	if err != nil {
		return nil, fmt.Errorf("error reading metadata: %v", err)
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
	opts := sharesOpts{
		kekInfos:       matchingKeyConfig.GetKekInfos(),
		asymmetricKeys: stetConfig.GetAsymmetricKeys(),
	}
	if csConfigs := stetConfig.GetConfidentialSpaceConfigs(); csConfigs != nil {
		opts.confSpaceConfig = confidentialspace.NewConfig(csConfigs)
	}

	unwrappedShares, err := c.unwrapAndValidateShares(ctx, metadata.GetShares(), opts)
	if err != nil {
		return nil, fmt.Errorf("error unwrapping and validating shares: %v", err)
	}

	combinedShares, err := shares.CombineUnwrappedShares(matchingKeyConfig, unwrappedShares)
	if err != nil {
		return nil, fmt.Errorf("error combining unwrapped shares: %v", err)
	}

	var combinedDEK shares.DEK
	copy(combinedDEK[:], combinedShares)

	// Generate AAD and decrypt ciphertext.
	aad, err := MetadataToAAD(metadata)
	if err != nil {
		return nil, fmt.Errorf("error serializing metadata: %v", err)
	}

	// Now `input` is at the start of ciphertext to pass to Tink.
	if err := AeadDecrypt(combinedDEK, input, output, aad); err != nil {
		return nil, fmt.Errorf("error decrypting data: %v", err)
	}

	// Return URIs of keys used during decryption.
	var keyURIs []string
	for _, unwrapped := range unwrappedShares {
		if unwrapped.URI != "" {
			keyURIs = append(keyURIs, unwrapped.URI)
		}
	}

	return &StetMetadata{
		KeyUris: keyURIs,
		BlobID:  metadata.GetBlobId(),
	}, nil
}
