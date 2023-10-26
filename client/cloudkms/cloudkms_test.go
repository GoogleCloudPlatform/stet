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

package cloudkms

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"cloud.google.com/go/kms/apiv1"
	kmsspb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/GoogleCloudPlatform/stet/client/testutil"
	"github.com/google/go-cmp/cmp"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/option"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

func TestWrapKMSShareSucceeds(t *testing.T) {
	testShare := []byte("Food share")
	testCases := []struct {
		name         string
		kekName      string
		expectedWrap []byte
	}{
		{
			name:         "HSM",
			kekName:      testutil.TestHSMKEKName,
			expectedWrap: testutil.FakeKMSWrap(testShare, testutil.TestHSMKEKName),
		},
		{
			name:         "Software",
			kekName:      testutil.TestSoftwareKEKName,
			expectedWrap: testutil.FakeKMSWrap(testShare, testutil.TestSoftwareKEKName),
		},
	}

	ctx := context.Background()
	fakeKMSClient := &testutil.FakeKeyManagementClient{}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			opts := WrapOpts{Share: testShare, KeyName: testCase.kekName}
			wrappedShare, err := WrapShare(ctx, fakeKMSClient, opts)
			if err != nil {
				t.Fatalf("wrapKMSShare(%v, %v) = %v error, want nil error", testShare, testCase.kekName, err)
			}
			if !bytes.Equal(wrappedShare, testCase.expectedWrap) {
				t.Errorf("wrapKMSShare(%v, %v) = %v, want %v", testShare, testCase.kekName, wrappedShare, testCase.expectedWrap)
			}
		})
	}
}

func TestWrapKMSShareFails(t *testing.T) {
	plaintext := []byte("Plaintext")
	testCases := []struct {
		name            string
		encryptResponse *kmsspb.EncryptResponse
		encryptError    error
	}{
		{
			name: "Plaintext corrupted",
			encryptResponse: &kmsspb.EncryptResponse{
				Name:                    testutil.TestKEKName,
				Ciphertext:              []byte("Ciphertext"),
				CiphertextCrc32C:        wrapperspb.Int64(int64(crc32c([]byte("Ciphertext")))),
				VerifiedPlaintextCrc32C: false,
			},
			encryptError: nil,
		},
		{
			name: "Ciphertext corrupted",
			encryptResponse: &kmsspb.EncryptResponse{
				Name:                    testutil.TestKEKName,
				Ciphertext:              []byte("Ciphertext"),
				CiphertextCrc32C:        wrapperspb.Int64(10),
				VerifiedPlaintextCrc32C: true,
			},
			encryptError: nil,
		},
		{
			name:            "Error from encrypt",
			encryptResponse: nil,
			encryptError:    errors.New("Service unavailable"),
		},
	}

	ctx := context.Background()

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fakeKMSClient := &testutil.FakeKeyManagementClient{
				EncryptFunc: func(_ context.Context, _ *kmsspb.EncryptRequest, _ ...gax.CallOption) (*kmsspb.EncryptResponse, error) {
					return testCase.encryptResponse, testCase.encryptError
				},
			}

			opts := WrapOpts{Share: []byte(plaintext), KeyName: testutil.TestKEKName}
			_, err := WrapShare(ctx, fakeKMSClient, opts)

			if err == nil {
				t.Errorf("wrapKMSShare(%v, %v) = nil error, want error", plaintext, testutil.TestKEKName)
			}
		})
	}
}

func TestUnwrapKMSShareSucceeds(t *testing.T) {
	expectedShare := []byte("Google, let me into the office for fooooddd")
	testCases := []struct {
		name    string
		kekName string
	}{
		{"HSM", testutil.TestHSMKEKName},
		{"Software", testutil.TestSoftwareKEKName},
	}

	ctx := context.Background()
	fakeKMSClient := &testutil.FakeKeyManagementClient{}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			wrappedShare := testutil.FakeKMSWrap(expectedShare, testCase.kekName)

			opts := UnwrapOpts{Share: wrappedShare, KeyName: testCase.kekName}
			unwrappedShare, err := UnwrapShare(ctx, fakeKMSClient, opts)
			if err != nil {
				t.Fatalf("unwrapKMSShare(ctx, %v, %v) = %v error, want nil error", wrappedShare, testCase.kekName, err)
			}
			if !bytes.Equal(unwrappedShare, expectedShare) {
				t.Errorf("unwrapKMSShare(ctx, %v, %v) = %v, want %v", wrappedShare, testCase.kekName, unwrappedShare, expectedShare)
			}
		})
	}
}

func TestUnwrapKMSShareFails(t *testing.T) {
	plaintext := []byte("Plaintext")
	testCases := []struct {
		name            string
		decryptResponse *kmsspb.DecryptResponse
		decryptError    error
	}{
		{
			name: "Plaintext corrupted",
			decryptResponse: &kmsspb.DecryptResponse{
				Plaintext:       []byte("Plaintext"),
				PlaintextCrc32C: wrapperspb.Int64(10),
			},
			decryptError: nil,
		},
		{
			name:            "Error from decrypt",
			decryptResponse: nil,
			decryptError:    errors.New("Service unavailable"),
		},
	}

	ctx := context.Background()

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fakeKMSClient := &testutil.FakeKeyManagementClient{
				DecryptFunc: func(_ context.Context, _ *kmsspb.DecryptRequest, _ ...gax.CallOption) (*kmsspb.DecryptResponse, error) {
					return testCase.decryptResponse, testCase.decryptError
				},
			}

			opts := UnwrapOpts{Share: plaintext, KeyName: testutil.TestKEKName}
			_, err := UnwrapShare(ctx, fakeKMSClient, opts)

			if err == nil {
				t.Errorf("unwrapKMSShare(ctx, %v, %v) = nil error, want error", plaintext, testutil.TestKEKName)
			}
		})
	}
}

func TestCreateClient(t *testing.T) {
	version := "test"

	expectedOpts := []option.ClientOption{option.WithUserAgent("STET/" + version)}

	testNewKMSClient := func(ctx context.Context, opts ...option.ClientOption) (*kms.KeyManagementClient, error) {
		if len(opts) != len(expectedOpts) {
			t.Fatalf("len(opts) = %v, want %v", len(opts), len(expectedOpts))
		}

		// Check WithUserAgent option.
		if opts[0] != expectedOpts[0] {
			t.Fatalf("opts[0] = %v, want %v", opts[0], expectedOpts[0])
		}

		return &kms.KeyManagementClient{}, nil
	}

	factory := &ClientFactory{
		StetVersion:  version,
		newKMSClient: testNewKMSClient,
	}

	if _, err := factory.createClient(context.Background(), ""); err != nil {
		t.Errorf("createClient returned error: %v", err)
	}
}

func TestCreateClientWithCredentials(t *testing.T) {
	credentials := "credentials: test"
	version := "test"

	expectedOpts := []option.ClientOption{
		option.WithUserAgent("STET/" + version),
		option.WithCredentialsJSON([]byte(credentials)),
	}

	testNewKMSClient := func(ctx context.Context, opts ...option.ClientOption) (*kms.KeyManagementClient, error) {
		if len(opts) != len(expectedOpts) {
			t.Fatalf("len(opts) = %v, want %v", len(opts), len(expectedOpts))
		}

		// Check WithUserAgent option.
		if opts[0] != expectedOpts[0] {
			t.Errorf("opts[0] = %v, want %v", opts[0], expectedOpts[0])
		}

		// Check WithCredentialsJSON option.
		if !cmp.Equal(opts[1], expectedOpts[1]) {
			t.Errorf("opts[1] = %v, want %v", opts[1], expectedOpts[1])
		}

		return &kms.KeyManagementClient{}, nil
	}

	factory := &ClientFactory{
		StetVersion:  version,
		newKMSClient: testNewKMSClient,
	}

	if _, err := factory.createClient(context.Background(), credentials); err != nil {
		t.Errorf("createClient returned error: %v", err)
	}
}
