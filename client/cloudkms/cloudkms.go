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

// Package cloudkms contains utilities for communicating with CloudKMS.
package cloudkms

import (
	"context"
	"fmt"
	"hash/crc32"

	"cloud.google.com/go/kms/apiv1"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/option"
	rpb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	spb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

// Client defines an interface compatible with Cloud KMS client.
type Client interface {
	GetCryptoKey(context.Context, *spb.GetCryptoKeyRequest, ...gax.CallOption) (*rpb.CryptoKey, error)
	Encrypt(context.Context, *spb.EncryptRequest, ...gax.CallOption) (*spb.EncryptResponse, error)
	Decrypt(context.Context, *spb.DecryptRequest, ...gax.CallOption) (*spb.DecryptResponse, error)
	Close() error
}

func crc32c(data []byte) uint32 {
	t := crc32.MakeTable(crc32.Castagnoli)
	return crc32.Checksum(data, t)
}

// WrapOpts does xyz.
type WrapOpts struct {
	Share   []byte
	KeyName string
	RPCOpts []gax.CallOption
}

// WrapShare uses a KMS client to wrap the given share using Cloud KMS.
func WrapShare(ctx context.Context, client Client, opts WrapOpts) ([]byte, error) {
	if client == nil {
		return nil, fmt.Errorf("nil client specified")
	}
	req := &spb.EncryptRequest{
		Name:            opts.KeyName,
		Plaintext:       opts.Share,
		PlaintextCrc32C: wrapperspb.Int64(int64(crc32c(opts.Share))),
	}

	result, err := client.Encrypt(ctx, req, opts.RPCOpts...)
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

// UnwrapOpts does xyz.
type UnwrapOpts struct {
	Share   []byte
	KeyName string
}

// UnwrapShare uses a KMS client to unwrap the given share using Cloud KMS.
func UnwrapShare(ctx context.Context, client Client, opts UnwrapOpts) ([]byte, error) {
	req := &spb.DecryptRequest{
		Name:             opts.KeyName,
		Ciphertext:       opts.Share,
		CiphertextCrc32C: wrapperspb.Int64(int64(crc32c(opts.Share))),
	}

	result, err := client.Decrypt(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext: %v", err)
	}

	if int64(crc32c(result.Plaintext)) != result.PlaintextCrc32C.Value {
		return nil, fmt.Errorf("Decrypt: response corrupted in-transit")
	}
	return result.Plaintext, nil
}

// ClientFactory manages singleton instances of KMS Clients mapped to JSON credentials.
type ClientFactory struct {
	CredsMap    map[string]Client
	StetVersion string

	newKMSClient func(context.Context, ...option.ClientOption) (*kms.KeyManagementClient, error)
}

// NewClientFactory initializes a ClientMap with the provided version.
func NewClientFactory(version string) *ClientFactory {
	return &ClientFactory{
		CredsMap:     make(map[string]Client),
		StetVersion:  version,
		newKMSClient: kms.NewKeyManagementClient,
	}
}

func (m *ClientFactory) createClient(ctx context.Context, credentials string) (Client, error) {
	// Set user agent for Cloud KMS API calls.
	ua := "STET/"
	if m.StetVersion != "" {
		ua += m.StetVersion
	} else {
		ua += "dev"
	}

	opts := []option.ClientOption{option.WithUserAgent(ua)}

	// If credentials were specified, include them in the options.
	if len(credentials) != 0 {
		opts = append(opts, option.WithCredentialsJSON([]byte(credentials)))
	}

	return m.newKMSClient(ctx, opts...)
}

// Client returns a KMS Client initialized with the provided credentials. If a client
// with these credentials already exists, it returns that.
func (m *ClientFactory) Client(ctx context.Context, credentials string) (Client, error) {
	client, ok := m.CredsMap[credentials]

	if !ok {
		var err error
		client, err = m.createClient(ctx, credentials)
		if err != nil {
			return nil, fmt.Errorf("error creating new KMS client: %v", err)
		}

		m.CredsMap[credentials] = client
	}

	return client, nil
}

// Close iterates through all the clients in the map and closes them.
func (m *ClientFactory) Close() error {
	for _, client := range m.CredsMap {
		if err := client.Close(); err != nil {
			return err
		}
	}
	return nil
}
