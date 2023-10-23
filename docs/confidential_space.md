# Confidential Space

Integration with Confidential Space enables added security and convenience for
both products. This doc covers the features enabled by this combination.

## CloudKMS Attestation

With Confidential Space, STET can use the Attestation Token as attestation
evidence when accessing a CloudKMS KEK.

By default, STET uses Application Default Credentials when performing CloudKMS
operations. This feature allows STET to determine whether it needs to configure
a different set of credentials (through Workload Identity Federation) to use a
particular KEK.

### Setup

You can find additional information and examples on how to use Confidential
Space
[here](https://cloud.google.com/confidential-computing/confidential-vm/docs/analyze-with-confidential-space).

To enable STET to provide Confidential Space attestation to Cloud KMS, (aside
from existing setup) you will need to (A) write STET configs containing your KEK
and credential information, and (B)
[install and run STET](../README.md#prebuilt-binaries) in your workload.

To use CloudKMS Attestation in STET, add a `confidential_space_configs` section
to your STET config file. This contains one or more `kek_credentials`, each of
which contains information about credentials needed to access a Confidential
Space WIP-protected KEK: * `kek_uri_pattern` is a regex pattern indicating the
URIs of KEKs that should be this set of credentials. * `wip_name` is the
identifier of the WIP, which should be of the format
`projects/*/locations/*/workloadIdentityPools/*/providers/*`. *
`service_account` is the trusted service account that will be used to access the
KEK. * `mode` refers to whether these credentials are used for encrypt and/or
decrypt. Defaults to `DEFAULT_ENCRYPT_AND_DECRYPT_MODE`.

#### Example

```yaml#
encrypt_config:
  key_config:
    kek_infos:
    - kek_uri: "gcp-kms://projects/foo-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/my-key"
    dek_algorithm: AES256_GCM0
    no_split: true

decrypt_config:
  key_configs:
  - kek_infos:
    - kek_uri: "gcp-kms://projects/foo-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/my-key"
    dek_algorithm: AES256_GCM
    no_split: true

confidential_space_configs:
  kek_credentials:
    # These credentials will be used in both `encrypt` and `decrypt`.
    - kek_uri_pattern: "gcp-kms://projects/foo-project/.*"
      wip_name: "projects/1234/locations/global/workloadIdentityPools/foo-wip/providers/foo-provider"
      service_account: "foo@my-project.iam.gserviceaccount.com"
    # These credentials will only be used in `encrypt`.
    - kek_uri_pattern: "gcp-kms://projects/bar-project/.*"
      wip_name: "projects/5678/locations/global/workloadIdentityPools/bar-wip/providers/bar-provider"
      service_account: "bar-encrypter@my-project.iam.gserviceaccount.com"
      mode: ENCRYPT_ONLY
    # These credentials will only be used in `decrypt`.
    - kek_uri_pattern: "gcp-kms://projects/bar-project/.*"
      wip_name: "projects/5678/locations/global/workloadIdentityPools/bar-wip/providers/bar-provider"
      service_account: "bar-decrypter@my-project.iam.gserviceaccount.com"
      mode: DECRYPT_ONLY
```

When a STET is run from a workload in a Confidential Space VM, it will
automatically detect that it is in Confidential Space and look for corresponding
credentials to use when contacting CloudKMS.

*   If STET detects it is in Confidential Space and `confidential_space_configs`
    is provided, it will search `kek_credentials` for the first one where
    `kek_uri_pattern` and `mode` match the current KEK URI and STET command,
    respectively.
    *   If a match is found, `wip_name` and `service_account` will be used to
        configure credentials for CloudKMS.
    *   If a match is not found, Application Default Credentials will be used.
*   Defining `confidential_space_configs` is **optional**. If not provided, STET
    will default to Application Default Credentials for CloudKMS Operations.

### Usage

Once you have configured Confidential Space and your STET configs accordingly,
you can execute `stet encrypt` or `decrypt` like normal.

### Additional Considerations

#### Grant CloudKMS Viewer Permissions

If STET detects a KEK has Confidential Space credentials, it will also use those
credentials to retrieve its `CryptoKey` metadata.

**What does this mean?** Ensure that any service accounts used to encrypt or
decrypt with a KEK also have the `CloudKMS Viewer` role on that KEK.

#### First Match Only

STET will only try the first set of credentials that matches the KEK URI and
encrypt/decrypt command.

**What does this mean?** To avoid confusion, ensure only one `kek_uri_pattern`
matches the KEK you want to use, or pay careful attention to the ordering of
`kek_credentials`.

In the below config, STET will use the credentials with the `foo@` service
account, despite the `kek_uri_pattern` for `bar@` matching more specifically.

```yaml#
encrypt_config:
  key_config:
    kek_infos:
    - kek_uri: "gcp-kms://projects/foo-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/my-key"
    dek_algorithm: AES256_GCM
    no_split: true

confidential_space_configs:
  kek_credentials:
    - kek_uri_pattern: "gcp-kms://.*"
      wip_name: "projects/1234/locations/global/workloadIdentityPools/foo-wip/providers/foo-provider"
      service_account: "foo@my-project.iam.gserviceaccount.com"
    - kek_uri_pattern: "gcp-kms://projects/foo-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/my-key"
      wip_name: "projects/5678/locations/global/workloadIdentityPools/bar-wip/providers/bar-provider"
      service_account: "bar@my-project.iam.gserviceaccount.com"
```

#### Only Include Required Credentials

If STET finds a set of credentials that matches the KEK and command, it assumes
that KEK/command can only be accessed in Confidential Space by that set of
credentials. If that fails, STET will not (A) try another set of credentials, or
(B) try Application Default Credentials.

**What does this mean?** Ensure you only include credentials that are necessary
to access the KEKs.
