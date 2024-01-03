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

// Package vpc contains utilties for handling VPC-protected keys.
package vpc

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	ekmpb "cloud.google.com/go/kms/apiv1/kmspb"
	rpb "cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/googleapis/gax-go/v2"
)

// CloudEKMClient is an interface corresponding to CloudKMS' EKMClient.
type CloudEKMClient interface {
	GetEkmConnection(context.Context, *ekmpb.GetEkmConnectionRequest, ...gax.CallOption) (*ekmpb.EkmConnection, error)
	Close() error
}

// Converts a slice of KMS Certificates to x509 Certificates.
func toCertPool(kmsCerts []*ekmpb.Certificate) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	for _, kmsCert := range kmsCerts {
		cert, err := x509.ParseCertificate(kmsCert.GetRawDer())
		if err != nil {
			return nil, fmt.Errorf("error parsing KMS Connection cert: %w", err)
		}

		certPool.AddCert(cert)
	}

	return certPool, nil
}

// GetURIAndCerts uses the provided client to get the EKM URI and service resolver certificates
// for the given cryptoKey.
func GetURIAndCerts(ctx context.Context, client CloudEKMClient, cryptoKey *rpb.CryptoKey) (string, *x509.CertPool, error) {
	ekmConnName := cryptoKey.GetCryptoKeyBackend()
	if len(ekmConnName) == 0 {
		return "", nil, errors.New("No EKM Connection name specified")
	}

	ekmConn, err := client.GetEkmConnection(ctx, &ekmpb.GetEkmConnectionRequest{Name: ekmConnName})
	if err != nil {
		return "", nil, fmt.Errorf("error retrieving KMS EkmConnection: %w", err)
	}

	if len(ekmConn.GetServiceResolvers()) == 0 {
		return "", nil, fmt.Errorf("No service resolvers found for EkmConnection %v", ekmConnName)
	}
	sr := ekmConn.GetServiceResolvers()[0]
	leafCerts, err := toCertPool(sr.GetServerCertificates())
	if err != nil {
		return "", nil, err
	}

	// For EXTERNAL_VPC, construct the URI using the hostname from the EkmConnection and key
	// path from ExternalProtectionLevelOptions.
	cryptoKeyVer := cryptoKey.GetPrimary()
	if cryptoKeyVer == nil {
		return "", nil, errors.New("No CryptoKeyVersion found")
	}
	if cryptoKeyVer.ExternalProtectionLevelOptions == nil {
		return "", nil, errors.New("CryptoKeyVersion does not have external protection level options despite being EXTERNAL_VPC protection level")
	}
	keyPath := cryptoKeyVer.GetExternalProtectionLevelOptions().GetEkmConnectionKeyPath()

	return fmt.Sprintf("https://%s/%s", sr.Hostname, keyPath), leafCerts, nil
}
