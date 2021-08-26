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

// This file contains test asymmetric keys for use in client_test.go.
// They are declared in a separate file so that automated tooling does
// not trigger warnings about touching a file with keys in them every time
// a developer tries to modify client_test.go.

package client

const (
	// This is a 1024-bit RSA key generated explicitly for testing.
	testPrivatePEM = `-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDUzk2aLRRBhg4Kj596qJ+7zCGO784A5HQMbCRn3eYd1ZCR+pnk
PDs1m1QM+3twHDYuo9EpGjSVduTC0PGzwrc3KLmX9oYmC36/l5Jj/fKGRaeOfwm1
S6Ai3uhXagl5tneuoRKKomviHYLRV7eEzJYbavpUcc0G2yLntdS66ogLSQIDAQAB
AoGBAJT7DTcHoiuxJvlbzSF5FcLKyR+hYM4dIeVkfCQ/JA/06K5aDAzN4gHIiZJB
KQy2o3QJea/VycRtpP+CegQIKGzsmbS9SA3VubcJBdKgK5stKCJtZVGdaKTp69bc
cDnI/VBfoUJRyFeBc//6Q5mz4PElNq8K10wKyNP9AjrRrtwBAkEA+5tLBacDoPNE
QLJsoeouunD/Nf0AdNX+TJfnc9pprtoKIYzEDxFS0KFfkFFcI3+lnIoJkWlU0uVA
3rMk4YWzgQJBANiFkRz4AJaGs4zb2bWS07WIdczUzcaoS332BTL0+LvG0BNVzVfu
rmFPfVDvKthVJyvngvAcaoGVDXqdIEhfm8kCQFVr0bqniznXnXKBoRQPl7HAr0S7
Eq6YAHAsmm3g10R/zjS5v86FySH/x5wNo0SCD83np3vw0NWQ88cn9vuCEwECQC3b
W/h+reEzdiOHDHzgM+ZmmExhZZOFYTe0OzWnnGZonPj7WxoceuIxK6FQhgp7PmiW
B61C12vKXahyTrwFQ8ECQQCPl6Jlp0Bwe4lWUtZLDU3jaBlIxiKHEJv9FT3buiHx
ZtniOrKhivHxz/eWzqQ8CAhIqshMVQ5OpqgZB/Oxt/ei
-----END RSA PRIVATE KEY-----`

	// This public key corresponds to the above private key.
	testPublicPEM = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDUzk2aLRRBhg4Kj596qJ+7zCGO
784A5HQMbCRn3eYd1ZCR+pnkPDs1m1QM+3twHDYuo9EpGjSVduTC0PGzwrc3KLmX
9oYmC36/l5Jj/fKGRaeOfwm1S6Ai3uhXagl5tneuoRKKomviHYLRV7eEzJYbavpU
cc0G2yLntdS66ogLSQIDAQAB
-----END PUBLIC KEY-----`

	testPublicFingerprint = "geOLcfo619JGjvwYKXfwiQVZAK1ZyFwjUpmoVWyJD9s="

	// This public key is different from the above private key.
	testPublicPEM2 = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC1XeUPybTSQE6OfXQ77RdA8uAW
soh7x5Jxdhw6wEtzxycIm7pbXQB0LqnCsOzRETkESbJ9K+SiggnBt7aPZs6T34DT
IKM76bmQu0sgv3xgFlRrXpk372IBjYLtBT7XiOMddS5cHiy31kcqGQb5WwpVcIeQ
JuDmwlL9LWE3SrmGawIDAQAB
-----END PUBLIC KEY-----`
)
