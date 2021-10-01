# Advanced STET Configuration

Check out our [quickstart guide](quickstart_guide.md) for a basic overview of
STET execution.

## Configuration Files

STET is configured with a configuration file that contains the needed
information for STET to encrypt and decrypt files. There are two primary
sections in a STET configuration file: an `encrypt_config` and a
`decrypt_config`. An `encrypt_config` is only required if this installation of
STET will be performing encrypt operations, and a `decrypt_config` is only
required if it will be performing decrypt operations.

The encrypt_config contains only one set of instructions (called a `key_config`,
described below), while a decrypt_config can contain multiple sets. This is
because when performing an encrypt operation, STET needs a specific set of
instructions for encrypting the data. In constrast, when performing a decrypt
operation, STET can decrypt data as long as it was encrypted with any one of the
provided instructions.

When invoking STET, you can specify which configuration file to use. Otherwise,
it will default to `stet.yaml` in your user configuration directory
(~/.config/stet.yaml on Linux).

### Key Configs

The primary information in a STET configuration file is known as a `key_config`,
which describes how to encrypt or decrypt data.

There are 3 components to a `key_config`:

1.  A series of `kek_info` objects, each describing a unique Key Encryption Key
    used to encrypt or decrypt the data. Each `kek_info` includes the URI of its
    respective key.
1.  The `dek_algorithm` used to encrypt or decrypt the data. The only currently
    supported algorithm is AES-256-GCM.
1.  The "key-splitting algorithm" and details of the key splitting. This is
    where the amount of "split trust" can be configured.

### Split Trust

If you would like to configure STET to use "split trust" and encrypt/decrypt
with multiple KMS systems, a key-splitting algorithm and an appropriate number
of `kek_info` objects for that algorithm must be provided.

The following key-splitting algorithms are currently supported:

*   `no_split`: This algorithm does not split the trust. The key encryption key
    used is wholly known by the single KMS being used.
*   `shamir`: This algorithm splits the trust between a number of KMS systems
    (specified by `shares`) during encryption. Decryption requires a minimum
    number of those shares (specified by `threshold`) to be present. Currently,
    the only supported value for `shares` and `threshold` is 2 for both fields.

### Example

The following configuration would tell STET to encrypt any new data (any
`encrypt` operation) with the single provided KMS key. However, it would support
decrypting data that was encrypted with any of the three provided
configurations: using that same key, using a separate key (such as a key that
was previously, but no longer, used for encryption), or using a pair of keys
used for split trust.

In order to illustrate the extensibility of STET, this example configuration
file is more complicated than what is typically needed. More details on the
common workflows can be found [here](workflows.md)

```yaml
# ~/.config/stet.yaml
encrypt_config:
  key_config:
    kek_infos:
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/my-key"
    dek_algorithm: AES256_GCM
    no_split: true

decrypt_config:
  key_configs:
  - kek_infos:
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/my-key"
    dek_algorithm: AES256_GCM
    no_split: true
 - kek_infos:
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/old-key"
    dek_algorithm: AES256_GCM
    no_split: true
 - kek_infos:
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/ekm-key"
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/gcp-key"
    dek_algorithm: AES256_GCM
    shamir:
      shares: 2
      threshold: 2
```

## Service Account Configuration

### On-Premises

When operating STET on-premises, a service account must be used in order to
access the KMS keys. This can be done by
[creating a service account key](https://cloud.google.com/iam/docs/creating-managing-service-account-keys#iam-service-account-keys-create-gcloud)
for the service account, and then setting the `GOOGLE_APPLICATION_CREDENTIALS`
[environment variable](https://cloud.google.com/docs/authentication/production#passing_variable)
to point to the service account key file. STET and other Google client libraries
will automatically use this environment variable and use these credentials.

A different service account can be used for on-premises, or the same service
account in the Confidential VM can be used. If a different service account is
used, ensure that you have
[configured your IAM permissions and key policy](quickstart_guide.md#creating-an-ekm-key-and-linking-to-cloud-kms)
for this new service account.

### Confidential VM

When [creating a Confidential VM](quickstart_guide.md#create-a-confidential-vm),
a specific service account is associated with the VM, but a different service
account (such as the one used on-premises above) can also be used if desired.
This can be accomplished by selecting that service account when creating the VM
from the **VM instance details** page on the Google Cloud Console, or by
performing the same credentials downloading step described above.

If a different service account is used, ensure that you have
[configured your IAM permissions and Thales key policy](quickstart_guide.md#creating-an-ekm-key-and-linking-to-cloud-kms)
for this new service account.
