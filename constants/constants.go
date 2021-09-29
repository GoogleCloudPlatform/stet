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

// Package constants contains shared constants between the client and the server.
package constants

import (
	"crypto/tls"
)

// AllowableCipherSuites is a set of TLS cipher suites to allow for the inner
// session on both the client and server when using TLS 1.2 rather than 1.3+.
// These are ciphers that are considered secure in TLS 1.3 as of 2021-09-23.
// (see: https://en.wikipedia.org/wiki/Transport_Layer_Security#Cipher)
var AllowableCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
}

// AttestationPrefix is the protocol-defined prefix for finalizing attestations.
const AttestationPrefix = "TLSAttestationV1"

// EndSessionString gets session-encrypted and sent in an EndSession request.
const EndSessionString = "TLS Tunneled EndSessionRequest V1"

// ExportLabel is the unique label for exporting key material from the TLS session.
const ExportLabel = "EXPERIMENTAL Google Confidential Computing Client Attestation 1.0"

// GrpcPort is the default gRPC server port.
const GrpcPort = 9754

// HTTPPort is the default listening port for the HTTP to gRPC proxy.
const HTTPPort = 9755

// SrvTestKey is a test ECDSA key generated with the secp256r1 curve.
// $ openssl ecparam -out ec_key.pem -name secp256r1 -genkey
const SrvTestKey = `-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIH0MZ+AM4ncRbe9j9jcrW2hcw9DvqEq0TCAhideeWAN8oAoGCCqGSM49
AwEHoUQDQgAE+db9MET1Z38XKeCWYfIWwv9dNA0Uu8ATY4DLaZEQwbLre3TPCg+Z
CaI2UB+DoXdipQFPMGxnm4m2KGrV3+/9qg==
-----END EC PRIVATE KEY-----`

// SrvTestCrt is a self-signed test cert generated using SrvTestKey.
// $ openssl req -new -key ec_key.pem -x509 -nodes -days 365 -out cert.pem
const SrvTestCrt = `-----BEGIN CERTIFICATE-----
MIIB6jCCAY+gAwIBAgIUGnNNkjxUtLQz1Lr66W7QTXPVOHMwCgYIKoZIzj0EAwIw
SjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xETAPBgNVBAcMCEtp
cmtsYW5kMRMwEQYDVQQKDApHb29nbGUgSW5jMB4XDTIxMDkyMzE2MzIxOFoXDTIy
MDYxNTE2MzIxOFowSjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24x
ETAPBgNVBAcMCEtpcmtsYW5kMRMwEQYDVQQKDApHb29nbGUgSW5jMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAE+db9MET1Z38XKeCWYfIWwv9dNA0Uu8ATY4DLaZEQ
wbLre3TPCg+ZCaI2UB+DoXdipQFPMGxnm4m2KGrV3+/9qqNTMFEwHQYDVR0OBBYE
FHyt8MO8SkRK1BfE8k73sFAwaq+kMB8GA1UdIwQYMBaAFHyt8MO8SkRK1BfE8k73
sFAwaq+kMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAOWLrdry
NSKBzdaStqPBsYF2BNMMdSqeexdrjzRb2d6TAiEA8OgSkxS9A6owfXH0sMjlkzah
M5NZTkkZj5jgDUgzKTk=
-----END CERTIFICATE-----`
