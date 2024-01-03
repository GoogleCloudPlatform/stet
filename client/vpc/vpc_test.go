// Copyright 2023 Google LLC
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

package vpc

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"

	ekmpb "cloud.google.com/go/kms/apiv1/kmspb"
	rpb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/GoogleCloudPlatform/stet/client/testutil"
	"github.com/GoogleCloudPlatform/stet/constants"
	"github.com/googleapis/gax-go/v2"
)

var (
	testHostname = "testhostname"
	testKeyPath  = "key/path"
	testVPCURI   = fmt.Sprintf("https://%s/%s", testHostname, testKeyPath)

	testEkmConnName = "projects/test/locations/test/ekmConnection/testConn"
)

func parsePEMCert(t *testing.T, pemCert string) *x509.Certificate {
	t.Helper()

	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		t.Fatal("Failed to decode PEM certificate.")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

func TestGetURIAndCerts(t *testing.T) {
	ctx := context.Background()

	// The specific cert doesn't matter, as long as it parses into an x509.Certificate.
	testCert := parsePEMCert(t, constants.SrvTestCrt)
	expectedCertPool := x509.NewCertPool()
	expectedCertPool.AddCert(testCert)

	getEkmConnectionFunc := func(ctx context.Context, req *ekmpb.GetEkmConnectionRequest, _ ...gax.CallOption) (*ekmpb.EkmConnection, error) {
		if req.GetName() != testEkmConnName {
			t.Errorf("Fake EKM service got EKM connection name %q, want %q", req.GetName(), testEkmConnName)
		}

		conn := &ekmpb.EkmConnection{
			ServiceResolvers: []*ekmpb.EkmConnection_ServiceResolver{
				{
					Hostname:           testHostname,
					ServerCertificates: []*ekmpb.Certificate{{RawDer: testCert.Raw}},
				},
			},
		}

		return conn, nil
	}

	cryptoKey := &rpb.CryptoKey{
		CryptoKeyBackend: testEkmConnName,
		Primary: &rpb.CryptoKeyVersion{
			ExternalProtectionLevelOptions: &rpb.ExternalProtectionLevelOptions{
				EkmConnectionKeyPath: testKeyPath,
			},
		},
	}

	client := &testutil.FakeCloudEKMClient{GetEkmConnectionFunc: getEkmConnectionFunc}

	uri, certPool, err := GetURIAndCerts(ctx, client, cryptoKey)
	if err != nil {
		t.Fatalf("GetURIAndCerts returned error: %v", err)
	}

	if uri != testVPCURI {
		t.Errorf("GetURIAndCerts did not return expected hostname: got %q, want %q", uri, testVPCURI)
	}

	if !certPool.Equal(expectedCertPool) {
		t.Errorf("GetURIAndCerts did not return expected cert pool: got %+v, want %+v", certPool, expectedCertPool)
	}
}

func TestGetURIAndCertsErrors(t *testing.T) {
	testCert := parsePEMCert(t, constants.SrvTestCrt)
	validEkmClient := &testutil.FakeCloudEKMClient{
		GetEkmConnectionFunc: func(ctx context.Context, req *ekmpb.GetEkmConnectionRequest, _ ...gax.CallOption) (*ekmpb.EkmConnection, error) {
			return &ekmpb.EkmConnection{
				ServiceResolvers: []*ekmpb.EkmConnection_ServiceResolver{
					{
						Hostname:           testHostname,
						ServerCertificates: []*ekmpb.Certificate{{RawDer: testCert.Raw}},
					},
				},
			}, nil
		},
	}

	testcases := []struct {
		name      string
		client    *testutil.FakeCloudEKMClient
		cryptoKey *rpb.CryptoKey
	}{
		{
			name:   "No EKM Connection Name",
			client: validEkmClient,
			cryptoKey: &rpb.CryptoKey{
				Primary: &rpb.CryptoKeyVersion{
					ExternalProtectionLevelOptions: &rpb.ExternalProtectionLevelOptions{
						EkmConnectionKeyPath: testKeyPath,
					},
				},
			},
		},
		{
			name: "GetEkmConnection error",
			client: &testutil.FakeCloudEKMClient{
				GetEkmConnectionFunc: func(ctx context.Context, req *ekmpb.GetEkmConnectionRequest, _ ...gax.CallOption) (*ekmpb.EkmConnection, error) {
					return nil, errors.New("getEkmConnection error")
				},
			},
		},
		{
			name: "No service resolver in EKM Connection",
			client: &testutil.FakeCloudEKMClient{
				GetEkmConnectionFunc: func(ctx context.Context, req *ekmpb.GetEkmConnectionRequest, _ ...gax.CallOption) (*ekmpb.EkmConnection, error) {
					return &ekmpb.EkmConnection{}, nil
				},
			},
			cryptoKey: &rpb.CryptoKey{
				CryptoKeyBackend: testEkmConnName,
				Primary: &rpb.CryptoKeyVersion{
					ExternalProtectionLevelOptions: &rpb.ExternalProtectionLevelOptions{
						EkmConnectionKeyPath: testKeyPath,
					},
				},
			},
		},
		{
			name:   "No CryptoKeyVersion",
			client: validEkmClient,
			cryptoKey: &rpb.CryptoKey{
				CryptoKeyBackend: testEkmConnName,
				Primary:          &rpb.CryptoKeyVersion{},
			},
		},
		{
			name:   "No external protection level options",
			client: validEkmClient,
			cryptoKey: &rpb.CryptoKey{
				CryptoKeyBackend: testEkmConnName,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			_, _, err := GetURIAndCerts(ctx, tc.client, tc.cryptoKey)
			if err == nil {
				t.Fatalf("GetURIAndCerts returned successfully, expected error.")
			}
		})
	}
}
