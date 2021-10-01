# Workflows

STET can be used in many different ways to solve various problems. This guide
walks through many common scenarios and how to use STET to protect your data.

## Cloud Data Ingress

A common use of STET is to ingest data from on-premises to a Confidential VM.
With this, one can be sure the data they are encrypting in their trusted
on-premises environment can only be decrypted in a Confidential Computing
environment, giving more confidence that it will not be compromised.

When configuring keys for this workflow, you need to configure restrictions such
that Confidential VM attestations are required in to decrypt but not to encrypt.
With this configuration, your on-premises environment will be allowed to encrypt
data unrestricted, but no environment other than a Confidential VM can decrypt
that data.

### Example STET Configuration

#### Configuration On-Premises

The following STET configuration indicates that a single KMS key should be used
to encrypt data.

```yaml
encrypt_config:
  key_config:
    kek_infos:
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/my-key"
    dek_algorithm: AES256_GCM
    no_split: true
```

#### Configuration in Confidential VM

The following STET configuration indicates that a single KMS key should be used
to decrypt data. Notice that it is similar to the on-premises configuration, but
with a couple key differences:

*   `decrypt_config` instead of `encrypt_config`.
*   `key_config` becomes `key_configs` and there is an additional `-` before
    `kek_infos`
    *   This is because STET can be configured to decrypt data that was
        encrypted by one of multiple different encryption configurations.

```yaml
decrypt_config:
  key_configs:
  - kek_infos:
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/my-key"
    dek_algorithm: AES256_GCM
    no_split: true
```

### Example Commands

The following are examples of commands that would be typically run when using
STET for a Cloud Data Ingress workflow.

#### Commands run on-premises

```bash
# Encrypt the data
$ stet encrypt plaintext.txt encrypted.dat
# Upload the data to a GCS bucket
$ gsutil cp encrypted.dat gs://my-bucket/
```

#### Commands run in Confidential VM

```bash
# Download the data
$ gsutil cp gs://my-bucket/encrypted.dat .
# Decrypt the data
$ stet decrypt encrypted.dat plaintext.txt
```

The contents of `plaintext.txt` on the Confidential VM should now be identical
to the original `plaintext.txt` provided on-premises. This was done in a way so
that no other entities have access to the unencrypted file contents, and no key
had to be manually transferred to the Confidential VM. Only confidential
computing workloads could accomplish this workflow.

## Cloud Data Egress

Another use for STET is to egress data from a Confidential VM to an on-premises
system. With this, one can be sure that the data received on-premises could only
have been produced/encrypted by a Confidential VM. This can give more confidence
in the origination of the data.

When configuring keys for this workflow, you need to configure restrictions such
that Confidential VM attestations are required to encrypt but not to decrypt.
With this configuration, your on-premises environment will still be allowed to
decrypt data, but no environment other than a Confidential VM can encrypt that
data.

### Example STET Configuration

#### Configuration in Confidential VM

The following STET configuration indicates that a single KMS key should be used
to encrypt data.

```yaml
encrypt_config:
  key_config:
    kek_infos:
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/my-key"
    dek_algorithm: AES256_GCM
    no_split: true
```

#### Configuration On-Premises

The following STET configuration indicates that a single KMS key should be used
to decrypt data. Notice that it is similar to the on-premises configuration, but
with a couple key differences:

*   `decrypt_config` instead of `encrypt_config`.
*   `key_config` becomes `key_configs` and there is an additional `-` before
    `kek_infos`
    *   This is because STET can be configured to decrypt data that was
        encrypted by one of multiple different encryption configurations.

```yaml
decrypt_config:
  key_configs:
  - kek_infos:
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/my-key"
    dek_algorithm: AES256_GCM
    no_split: true
```

Note that these configurations are identical to those in the **Cloud Data
Ingress** workflow, only reversed on where they are configured. The
configuration of confidential restrictions on the keys themselves are the
essential difference in how the different workflows operate.

### Example Commands

The following are examples of the types of commands that would be typical in
using STET for a Cloud Data Egress workflow.

#### Commands run in Confidental VM

```bash
# Encrypt the data
$ stet encrypt plaintext.txt encrypted.dat
# Upload the data to a GCS bucket
$ gsutil cp encrypted.dat gs://my-bucket/
```

#### Commands run on-premises

```bash
# Download the data
$ gsutil cp gs://my-bucket/encrypted.dat .
# Decrypt the data
$ stet decrypt encrypted.dat plaintext.txt
```

The contents of `plaintext.txt` on-premises should now be identical to the
original `plaintext.txt` provided in the Confidential VM. This was done in a way
so that no other entities have access to the unencrypted file contents, and no
key had to be manually transferred to the Confidential VM. Only confidential
computing workloads could accomplish this workflow.

Note that the commands are identical to those in the **Cloud Data Ingress**
workflow, only reversed on where they are configured. The configuration of
confidential restrictions on the keys themselves are the essential difference in
how the different workflows operate.

## Intra-Cloud Data

STET can also be used to ensure data is only ever found within Confidential VMs,
preventing it from being brought into a non-confidential VM or on-premises.
Examples include storing data for later use by the same Confidential VM or
sharing data between Confidential VMs. This can give more confidence that the
data is not compromised or used in unintended systems.

When configuring keys for this workflow, you need to configure restrictions such
that Confidential VM attestations are required to encrypt and decrypt. With this
configuration, only Confidential VMs can encrypt and decrypt the data.

### Example STET Configuration

#### Configuration in Confidential VMs

The following STET configuration indicates that a single KMS key should be used
to encrypt data.

```yaml
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
```

Note that the configurations are identical to those in the **Cloud Data
Ingress** and **Cloud Data Egress** workflows, only combined into a single
configuration file. The configuration of confidential restrictions on the keys
themselves are the essential difference in how the different workflows operate.

### Example Commands

The following are examples of the types of commands that would be typical in
using STET for Intra-Cloud Data.

#### Commands run in encrypting Confidential VM

```bash
# Encrypt the data
$ stet encrypt plaintext.txt encrypted.dat
# Upload the data to a GCS bucket
$ gsutil cp encrypted.dat gs://my-bucket/
```

#### Commands run in decrypting Confidential VM

```bash
# Download the data
$ gsutil cp gs://my-bucket/encrypted.dat .
# Decrypt the data
$ stet decrypt encrypted.dat plaintext.txt
```

The contents of `plaintext.txt` in the decrypting Confidential VM should now be
identical to the original `plaintext.txt` provided in the encrypting
Confidential VM. This was done in a way so that no other entities have access to
the unencrypted file contents, and no key had to be manually transferred to the
Confidential VMs. Only confidential computing workloads could accomplish this
workflow.

Note that the configurations are identical to those in the **Cloud Data
Ingress** and **Cloud Data Egress** workflows, only all commands are executed in
Confidential VMs. The configuration of confidential restrictions on the keys
themselves are the essential difference in how the different workflows operate.

## Split Trust

If you would like to configure STET to use
["split trust"](https://cloud.google.com/compute/confidential-vm/docs/ubiquitous-data-encryption#split-trust)
and encrypt/decrypt with multiple different KMS systems, any of the previous
workflows can be modified by changing their configuration file to use the
[shamir key splitting algorithm](advanced_cofiguration.md#split-trust) to use
two different KMS keys. This is most effective when using keys from two
different KMS systems, so that no single KMS system has enough information to
reconstruct your data encryption keys.

### Creating a Cloud KMS Native Key

If you want to split trust between Thales and Google, you can also generate a
native Cloud KMS key (managed and generated by Google) and specify it as part of
your configuration.

1.  Navigate to the
    [Key Management section](https://console.cloud.google.com/security/kms/keyrings)
    of the Google Cloud Console.
1.  Create a new key ring if necessary
1.  Create a new key associated with the key ring
    *   *Protection Level:* Software
    *   *Purpose:* Symmetric encrypt/decrypt
1.  Click the `...` next to the key and choose **Copy Resource Name**. This is
    the **KEK URI** which will need to be referenced when creating your
    configuration files.
    *   The KEK URI must be prefixed with `gcp-kms://`.
    *   If the resource name is a
        [key version](https://cloud.google.com/kms/docs/resource-hierarchy#retrieve_resource_id),
        remove the cryptoKeyVersions/foo suffix at the end to turn it into a key
        object.

### Split Trust Cloud Data Ingress Example

After creating the above key, you can modify the configuration files in the
[Cloud Data Ingress](#cloud-data-ingress) example to split the trust between
Thales's KMS and Google's KMS. This can also be similarly done for examples from
the other workflows.

#### On-Premises Configuration File

The following configuration file adds a second `kek_uri` and uses the shamir
key-splitting algorithm. Do not forget to update the key URIs referenced.

```yaml
encrypt_config:
  key_config:
    kek_infos:
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/ekm-key"
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/gcp-key"
    dek_algorithm: AES256_GCM
    shamir:
      shares: 2
      threshold: 2
```

#### Confidential VM Configuration File

The following configuration file adds a second `kek_uri` and uses the shamir
key-splitting algorithm. Do not forget to update the key URIs referenced.

```bash
decrypt_config:
  key_configs:
  - kek_infos:
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/ekm-key"
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/gcp-key"
    dek_algorithm: AES256_GCM
    shamir:
      shares: 2
      threshold: 2
```

#### Commands

Since this workflow is still data ingress, the commands used after configuration
are identical to those in the [Cloud Data Ingress](#cloud-data-ingress) example
above.
