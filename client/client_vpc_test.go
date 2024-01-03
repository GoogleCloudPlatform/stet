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

package client

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

	ekmpb "cloud.google.com/go/kms/apiv1/kmspb"
	rpb "cloud.google.com/go/kms/apiv1/kmspb"
	spb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/GoogleCloudPlatform/stet/client/cloudkms"
	"github.com/GoogleCloudPlatform/stet/client/testutil"
	"github.com/GoogleCloudPlatform/stet/constants"
	"github.com/google/go-cmp/cmp"
	"github.com/googleapis/gax-go/v2"

	configpb "github.com/GoogleCloudPlatform/stet/proto/config_go_proto"
)

var (
	testHostname = "vpc-kms.io"
	testKeyPath  = "test/key"
	testVPCURI   = fmt.Sprintf("https://%s/%s", testHostname, testKeyPath)
)

func testCert(t *testing.T) *x509.Certificate {
	// Using constants.SrvTestCrt since it's available - exact contents don't matter here.
	block, _ := pem.Decode([]byte(constants.SrvTestCrt))
	if block == nil {
		t.Fatal("Failed to decode PEM certificate.")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert
}

func TestGetExternalVPCKeyInfo(t *testing.T) {
	cert := testCert(t)

	ekmClient := &testutil.FakeCloudEKMClient{
		GetEkmConnectionFunc: func(context.Context, *ekmpb.GetEkmConnectionRequest, ...gax.CallOption) (*ekmpb.EkmConnection, error) {
			return &ekmpb.EkmConnection{
				ServiceResolvers: []*ekmpb.EkmConnection_ServiceResolver{
					{
						Hostname:           testHostname,
						ServerCertificates: []*ekmpb.Certificate{{RawDer: cert.Raw}},
					},
				},
			}, nil
		},
	}

	cryptoKey := &rpb.CryptoKey{
		CryptoKeyBackend: "test/ekmconn/name",
		Primary: &rpb.CryptoKeyVersion{
			ExternalProtectionLevelOptions: &rpb.ExternalProtectionLevelOptions{
				EkmConnectionKeyPath: testKeyPath,
			},
		},
	}

	kek := &configpb.KekInfo{
		KekType: &configpb.KekInfo_KekUri{
			KekUri: testutil.VPCKEK.URI(),
		},
	}

	client := &StetClient{testCloudEKMClient: ekmClient}

	kmd, certs, err := client.getExternalVPCKeyInfo(context.Background(), kek, cryptoKey, "")
	if err != nil {
		t.Fatalf("getExternalVPCKeyInfo failed: %v", err)
	}

	expectedKMD := &kekMetadata{
		protectionLevel: kmd.protectionLevel,
		uri:             testVPCURI,
		resourceName:    testutil.VPCKEK.Name,
	}
	if !cmp.Equal(kmd, expectedKMD, cmp.AllowUnexported(kekMetadata{})) {
		t.Errorf("getExternalVPCKeyInfo = %v, want %v", kmd, expectedKMD)
	}

	expectedCerts := x509.NewCertPool()
	expectedCerts.AddCert(cert)
	if !certs.Equal(expectedCerts) {
		t.Errorf("getExternalVPCKeyInfo = %v, want %v", certs, expectedCerts)
	}
}

func TestVPCWrapAndUnwrap(t *testing.T) {
	kmsClient := &testutil.FakeKeyManagementClient{
		GetCryptoKeyFunc: func(_ context.Context, req *spb.GetCryptoKeyRequest, _ ...gax.CallOption) (*rpb.CryptoKey, error) {
			ck := testutil.CreateEnabledCryptoKey(rpb.ProtectionLevel_EXTERNAL_VPC, testutil.VPCKEK.Name)
			return ck, nil
		},
	}

	cert := testCert(t)
	ekmClient := &testutil.FakeCloudEKMClient{
		GetEkmConnectionFunc: func(context.Context, *ekmpb.GetEkmConnectionRequest, ...gax.CallOption) (*ekmpb.EkmConnection, error) {
			return &ekmpb.EkmConnection{
				ServiceResolvers: []*ekmpb.EkmConnection_ServiceResolver{
					{
						Hostname:           testHostname,
						ServerCertificates: []*ekmpb.Certificate{{RawDer: cert.Raw}},
					},
				},
			}, nil
		},
	}

	shares := [][]byte{[]byte("share")}
	kekInfo := &configpb.KekInfo{
		KekType: &configpb.KekInfo_KekUri{
			KekUri: testutil.VPCKEK.URI(),
		},
	}

	ctx := context.Background()

	stetClient := &StetClient{
		testKMSClients: &cloudkms.ClientFactory{
			CredsMap: map[string]cloudkms.Client{
				"": kmsClient,
			},
		},
		testCloudEKMClient:      ekmClient,
		testSecureSessionClient: &testutil.FakeSecureSessionClient{},
	}

	opts := sharesOpts{kekInfos: []*configpb.KekInfo{kekInfo}}
	wrapped, _, err := stetClient.wrapShares(ctx, shares, opts)
	if err != nil {
		t.Fatalf("wrapShares failed: %v", err)
	}

	unwrapped, err := stetClient.unwrapAndValidateShares(ctx, wrapped, opts)
	if err != nil {
		t.Fatalf("unwrapAndValidateShares failed: %v", err)
	}

	if len(wrapped) != len(unwrapped) {
		t.Fatalf("wrapShares returned %v shares, unwrapAndValidateShares returned %v shares. Expected equal numbers.", len(wrapped), len(unwrapped))
	}

	if !bytes.Equal(unwrapped[0].Share, shares[0]) {
		t.Errorf("unwrapAndValidateShares = %v, want %v", unwrapped[0], shares[0])
	}
}
