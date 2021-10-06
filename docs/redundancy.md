# Redundancy

In addition to the typical workflows described in other documents, STET includes
more advanced features that enable extra redundancy of encrypted data.

## k-of-n Share Splitting

Because STET uses
[Shamir's Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing),
to split up data encryption keys, there is the capability to set the "threshold"
for shares needed to unwrap (`k`) lower than the total number of shares that
were created (`n`). We refer to this as "k-of-n share splitting", where k < n.

Consider the following configuration file:

```yaml
encrypt_config:
  key_config:
    kek_infos:
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/ekm-1-key"
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/ekm-2-key"
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/ekm-3-key"
    dek_algorithm: AES256_GCM
    shamir:
      shares: 3
      threshold: 2

decrypt_config:
  key_configs:
  - kek_infos:
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/ekm-1-key"
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/ekm-2-key"
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/ekm-3-key"
    dek_algorithm: AES256_GCM
    shamir:
      shares: 3
      threshold: 2
```

Supposing each key is stored in a different key management system, STET will
split the data encryption key at decryption time, wrapping it to all three KMSs.
However, at decryption time, only 2 of the 3 KMSs need to be contactable. STET
will automatically try to unwrap the share via all three, and the decryption
will only fail if two or more KMSs are offline.

## Asymmetric Keypairs

Rather than having a key manager be responsible for storing and wrapping a key
share, STET also supports using asymmetric keypairs.

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

When STET sees the `rsa_fingerprint` field under `kek_infos`, it will iterate
through either the list of `public_key_files` or `private_key_files` (depending
on whether data is being enrypted or decrypted, respectively), until it finds a
key that matches the given fingerprint. It then uses that key file to encrypt or
decrypt the share.

Note that the private key here should **only** be included where decryption is
being performed; the presence of both the public and private key filepaths in
this example is only to demonstrate the format of the configuration.

## Offline Backup using k-of-n with Asymmetric Keys

Using asymmetric keys in conjunction with Shamir Secret Sharing's ability to
split shares in a "k-of-n" setup allows you to encrypt your data and still be
able to access it, even if one or more KMS providers are unable to be contacted.

This is enabled because the private component of the asymmetric keypair can be
kept in a protected location controlled directly by the user, and brought out
only in scenarios such as a KMS going down.

Consider the following configuration file:

```yaml
encrypt_config:
  key_config:
    kek_infos:
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/ekm-key"
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/gcp-key"
    - rsa_fingerprint: "0FkfGnh4KEUBJGLoLUEcIIFTdlcx61ec1M/H2Gdh7tY="
    dek_algorithm: AES256_GCM
    shamir:
      shares: 3
      threshold: 2

decrypt_config:
  key_configs:
  - kek_infos:
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/ekm-key"
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/gcp-key"
    - rsa_fingerprint: "0FkfGnh4KEUBJGLoLUEcIIFTdlcx61ec1M/H2Gdh7tY="
    dek_algorithm: AES256_GCM
    shamir:
      shares: 3
      threshold: 2

asymmetric_keys:
  public_key_files:
  - "/home/me/stet.pub"
  private_key_files:
  - "/home/me/stet.pem"
```

Note that the arguments to `shamir` are a threshold of 2 and a share count of 3.
What this means is that, while all three of `ekm-key`, `gcp-key`, and the
asymmetric keypair are used to encrypt the data, *only* two of those three are
required to decrypt.

If the asymmetric keypair was generated and the private key was stored in a
safe, then this configuration file could be used under normal circumstances as
if it were simply a 2-of-2 setup with `ekm-key` and `gcp-key`. However, if one
of these two services were unreachable, the private key could be retrieved and
used as the 2nd share instead.

This pattern can be extended to create a backup that is not dependent on *any*
KMS providers being accessible. This can be done by taking advantage of the
property that the same `kek_info` field can be repeated. Consider the following
key config:

```yaml
key_configs:
- kek_infos:
  - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/ekm-key"
  - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/gcp-key"
  - rsa_fingerprint: "0FkfGnh4KEUBJGLoLUEcIIFTdlcx61ec1M/H2Gdh7tY="
  - rsa_fingerprint: "0FkfGnh4KEUBJGLoLUEcIIFTdlcx61ec1M/H2Gdh7tY="
  dek_algorithm: AES256_GCM
  shamir:
    shares: 4
    threshold: 2
```

This is similar to the above example, but with the RSA key duplicated. Because
the threshold is still set to 2, the data can be decrypted utilizing both EKMs,
one EKM and the offline keypair, or the keypair by itself.
