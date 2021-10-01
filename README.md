# STET (Split-Trust Encryption Tool)

The Split-Trust Encryption Tool (STET) allows users to encrypt and decrypt data
while splitting trust between multiple Key Management Systems and providing
environment attestations to aid in key release policy decisions.

## Building STET

STET can be built manually using *either* Go's native toolchain (e.g. `go get`
and `go build` commands), or via [Bazel](https://bazel.build/).

### Using Go's Native Toolchain

1.  Install `make` and `curl` via `apt-get install build-essential curl`.
2.  [Install Go 1.16+](https://golang.org/doc/install).
3.  [Install `protoc` version 3](https://grpc.io/docs/protoc-installation/).
4.  [Install Go plugins for the protocol compiler](https://grpc.io/docs/languages/go/quickstart/#prerequisites).
    *   Specifically, run `go install
        google.golang.org/protobuf/cmd/protoc-gen-go@v1.26` and `go install
        google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1`, then add `$(go env
        GOPATH)/bin` to your `PATH`.
5.  From the root of this source repository, run `make all` to vendor `.proto`
    files and compile `pb.go` sources.
6.  Build STET via `go build github.com/GoogleCloudPlatform/stet/cmd/stet`.
7.  Copy the resulting binary to an executable location, granting it `suid`
    permissions (root permissions are required to generate attestations in a
    Confidential VM):

    ```bash
    $ sudo mv stet /usr/local/bin
    $ sudo chown root /usr/local/bin/stet
    $ sudo chmod u+sx,a+rs /usr/local/bin/stet
    ```

### Using Bazel

1.  [Install Bazel](https://docs.bazel.build/versions/main/install.html)
2.  From the root of this source repository, run `bazel build cmd/stet:main`
    *   This will download all necessary dependencies
    *   The resulting binary will be found at `bazel-bin/cmd/stet/main_/main`
3.  Copy the resulting binary to an executable location, granting it `suid`
    permissions (root permissions are required to generate attestations in a
    Confidential VM):

    ```bash
    $ sudo mv bazel-bin/cmd/stet/main_/main /usr/local/bin
    $ sudo chown root /usr/local/bin/stet
    $ sudo chmod u+sx,a+rx /usr/local/bin/stet
    ```

## Using STET

### Create configuration

STET configurations are written in YAML.

A `key_config` provides information about the encryption and decryption process.
It includes the fields listed below.

#### KEK Information

One or more `kek_infos` fields must be defined, indicating all the KEKs to use
in encryption and decryption for that configuration. Each `kek_info` contains
the Google Cloud KMS URI of a KEK.

The number of `kek_infos` in a configuration must match the number of shares the
DEK will be split into, as indicated by the Key Splitting Algorithm (see below).

#### DEK Algorithm

The DEK Algorithm indicates the algorithm used to generate the DEK.

Currently, only AES256-GCM is supported.

#### Key Splitting Algorithm

This indicates the number of shares the split the DEK into - if at all. It
requires **exactly one** of the following fields to be defined:

*   `no_split: true` indicates the DEK will not be split into any shares.
    *   The `key_config` should contain a single `kek_infos` indicating the KEK
        to encrypt/decrypt the entire DEK with
*   `shamir` indicates the DEK will be split into multiple shares using Shamir's
    Secret Sharing. Each share will be encrypted/decrypted with a separate KEK.
    This configuration requires two fields to be defined:
    *   `shares` defines the total number of shares to split the DEK into.
    *   `threshold` defines the minimum number of shares needed to reconstitute
        the DEK during decryption.
    *   The `key_config` should contain a number of `kek_infos` equal to the
        values of `shares`

#### Examples

`key_config` using a single KMS (no split):

```yaml
key_config:
  kek_infos:
  - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-key-ring/cryptoKeys/my-key"
  dek_algorithm: AES256_GCM
  no_split: true
```

`key_config` using Shamir's Secret Sharing:

```yaml
key_config:
  kek_infos:
  - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-key-ring/cryptoKeys/my-key-1"
  - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-key-ring/cryptoKeys/my-key-2"
  dek_algorithm: AES256_GCM
  shamir:
    shares: 2
    threshold: 2
```

#### Creating a Configuration File

A configuration file for STET consists of two configurations: one for encryption
and one for decryption.

An `encrypt_config` contains a single `key_config` with information about the
key and scheme to encrypt with.

A `decrypt_config` contains all the `key_configs` known to the client, one of
which should match the `key_config` the ciphertext was encrypted with. During
decryption, the STET will search through the provided `key_configs` to find the
matching one.

Note that the encryption and decryption configurations could be identical if the
`key_config` used in encryption is the only known to the client. However, they
must still be defined separately in the configuration file.

Example of a STET configuration file:

```yaml
encrypt_config:
  key_config:
    kek_infos:
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-key-ring/cryptoKeys/my-key-1"
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-key-ring/cryptoKeys/my-key-2"
    dek_algorithm: AES256_GCM
    shamir:
      shares: 2
      threshold: 2

decrypt_config:
  key_configs:
  - kek_infos:  # Note the extra hyphen here, because key_configs is a repeated field.
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-key-ring/cryptoKeys/my-key0"
    dek_algorithm: AES256_GCM
    no_split: true
  key_configs:
  - kek_infos:  # Note the extra hyphen here, because key_configs is a repeated field.
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-key-ring/cryptoKeys/my-key-1"
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-key-ring/cryptoKeys/my-key-2"
    dek_algorithm: AES256_GCM
    shamir:
      shares: 2
      threshold: 2
```

#### Generating asymmetric keypairs for offline encryption

Another method of wrapping shares is to generate an asymmetric keypair locally.
In your STET configuration file, you can specify the fingerprint of the keypair
rather than the URI of a KMS-stored key and add another stanza describing the
path to the public/private keys on disk.

Generate a private, 2048-bit RSA key:

```
$ openssl genrsa -out my_key.pem 2048
```

Create a public key file from that private key:

```
$ openssl rsa -in my_key.pem -pubout -out my_key.pub
```

Compute the fingerprint of the keypair:

```
$ openssl rsa -in stet.pem -pubout -outform DER | openssl sha256 -binary | openssl base64
```

Here is an example config file that encrypts data using a single RSA key:

```yaml
encrypt_config:
  key_config:
    kek_infos:
    - rsa_fingerprint: "0FkfGnh4KEUBJGLoLUEcIIFTdlcx61ec1M/H2Gdh7tY="
    dek_algorithm: AES256_GCM
    no_split: true

decrypt_config:
  key_configs:
  - kek_infos:
    - rsa_fingerprint: "0FkfGnh4KEUBJGLoLUEcIIFTdlcx61ec1M/H2Gdh7tY="
    dek_algorithm: AES256_GCM
    no_split: true

asymmetric_keys:
  public_key_files:
  - "/home/me/stet.pub"
  private_key_files:
  - "/home/me/stet.pem"
```

### Execute STET

Example invocations:

```bash
$ stet encrypt --config-file=~/stet.cfg ./plaintext.txt ./ciphertext.dat
$ stet decrypt --config-file=~/stet.cfg ./ciphertext.dat ./plaintext2.txt
```

#### Using stdin and stdout

In place of providing input and output files, stdin and stdout can be used for
input and output respectively by using `-` in place of the corresponding file in
the command.

When stdout is used as the output destination, logging from STET is written to
stderr to avoid interference with the outputted plaintext or ciphertext.

Using stdin as input:

```bash
$ some-process | stet encrypt - ./ciphertext.dat
$ some-process | stet decrypt - ./plaintext.txt
```

Using stdout as output:

```bash
$ stet encrypt ./plaintext.txt - | some-process
$ stet decrypt ./ciphertext.dat - | some-process
```

Using both stdin as input and stdout as output:

```bash
$ some-process | stet encrypt - - | some-other-process
$ some-process | stet decrypt - - | some-other-process
```

### Validating blob IDs and key URIs

When encrypting and decrypting data using STET, it is important to validate the
blob ID and key URIs used. STET will output the blob ID stored in the metadata
of the encrypted file, as well as the key URI of the key actually used (e.g. the
specific external key URI when using an external key management system):

```
Blob ID of decrypted data: fa0fc0a8-b7b3-4ae2-bcc8-0aa862d1ff61
Used these key URIs: [https://my-ekm.io/keys/12345]
```

Checking the key URI used during encryption prevents accidental or malicious
misconfiguration resulting in the incorrect (with a potentially less restrictive
decryption policy) encryption key.

If the blob ID was set to a known value (e.g. the location of the file when
uploaded to a bucket), ensuring a match at decryption time confirms that the
data was not swapped out with another piece of data unknowingly.

## License

STET is not an officially supported Google product.

STET is released under the [Apache 2.0 license](/LICENSE).

```
Copyright 2021 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
