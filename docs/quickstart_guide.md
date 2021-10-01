# STET Quickstart Guide

For an introduction on how ubiquitous data encryptiona and split-trust work,
read our
[concept overview](https://cloud.google.com/compute/confidential-vm/docs/ubiquitous-data-encryption).

## Create and Configure a Service Account

You will need a
[Google Cloud service account](https://cloud.google.com/iam/docs/creating-managing-service-accounts#creating)
to authenticate with both the CipherTrust Cloud Key Manager (CCKM) and Google
Cloud KMS/EKM.

1.  Enable the
    [IAM Service Account Credentials API](https://console.cloud.google.com/apis/api/iamcredentials.googleapis.com/overview)
    for your project if not already enabled.
2.  Create a service account in the
    [IAM console](https://console.cloud.google.com/iam-admin/serviceaccounts).
    In the *"Grant this service account access to project"* step of service
    account creation, add the following roles:
    *   **Service Account Token Creator**
        *   This is needed so that the service account can generate OIDC tokens
            required to authenticate with CCKM.
    *   **Cloud KMS Admin**
        *   This is needed to query Cloud KMS for
            [key metadata](https://cloud.google.com/kms/docs/reference/permissions-and-roles")
            which applies to both keys stored in Cloud KMS and also external
            keys.
            *   Note: The Cloud KMS Admin role is used to grant the
                [cloudkms.cryptoKeys.get permission](https://cloud.google.com/kms/docs/reference/permissions-and-roles#predefined).
    *   **Cloud KMS CryptoKey Encrypter/Decrypter**
        *   This is needed so that the service account can use keys stored in
            Cloud KMS to
            [encrypt/decrypt data](https://cloud.google.com/kms/docs/reference/permissions-and-roles)
            *   Note: this is not necessary if shares are not going to be
                wrapped using Cloud KMS keys.
3.  Note down the member name of the service account that you created (**you
    will need this later**).

## Create a Confidential VM

In this guide, you will be running the STET utility in a Confidential VM. We
will now create that VM.

1.  Enable the
    [Compute Engine API](https://console.cloud.google.com/apis/api/compute.googleapis.com/overview)
    for your project if not already enabled.
1.  Go to the [Google Compute Engine](http://console.cloud.google.com/compute)
    console
1.  Click "Create Instance" to create a new VM and give the VM a name.
1.  Select the "Enable the Confidential Computing service on this VM instance."
    checkbox to make this VM a Confidential VM.
1.  Under "Identity and API access", select the service account you created
    above.
1.  Click "Create" to complete the VM creation process. It will take a few
    minutes for the VM to be provisioned and finish booting. You can continue
    with the guide while that is done.
1.  For the remainder of this guide, commands can be executed in this
    Confidential VM through an
    [SSH connection](https://cloud.google.com/compute/docs/instances/connecting-to-instance).

*Note: The Confidential VM will need to be able to make connections to services
outside of Google communicate with external key managers. Please ensure that
your network configuration allows such connections (firewalls, network address
translation, Virtual Private Cloud, etc).*

## Create Keys

### Creating an EKM Key and Linking to Cloud KMS

To use a key managed by an External Key Manager (EKM), you will have to inform
Cloud KMS of the location of this key.

1.  Navigate to the
    [Key Management section](https://console.cloud.google.com/security/kms/keyrings)
    of the Google Cloud Console.
1.  Create a new key ring if necessary.
    *   Note that this key ring cannot be in the *global* location, since
        external keys must be region-specific. The location should ideally be
        one that is geographically close to the location of the Confidential VM
        and the EKM.
1.  Start to create a new key associated with that key ring, choosing the
    **Externally managed key** type.
    *   **You will need get the key URI from step 4 before finishing the key
        creation.**
    *   Take note of the service account that needs to be authorized in the EKM.
    *   See the
        [Cloud EKM documentation](https://cloud.google.com/kms/docs/managing-external-keys)
        for more information.
1.  Create a key in the EKM. Please refer to the user guide provided by the EKM.
    *   If using Thales' CipherTrust Cloud Key Manager, note the following
        considerations:
        *   Your GCP project ID will need to be added to the CCKM in order to
            wrap and unwrap keys properly. This can be done via **Containers >
            Google** in the CipherTrust sidebar, navigating to the **Projects**
            tab, and clicking **Add Existing Project**
            *   Use the *Manually Enter Project ID* option and type in the
                "Project ID" corresponding to your GCP project.
        *   When creating a new endpoint, there will be a textbox for the **Key
            URI Hostname**. This should be the fully-qualified domain name
            (FQDN) of your CipherTrust Manager instance.
            *   For example, if you are at *https://ciphertrust.thalescpl.io*,
                the Key URI Hostname should be *ciphertrust.thalescpl.io*
        *   When creating the endpoint, you will have to choose which
            confidential computing restrictions to enable:
            *   **For generating data on-premises and consuming it in a
                Confidential VM:** Select only "Confidential Computing required
                for decryption". This is the most common configuration.
            *   **For generating data in a Confidential VM and consuming it
                on-premises:** Select only "Confidential Computing required for
                encryption".
            *   **For generating data in a Confidential VM and consuming it in a
                Confidential VM (either at a later time or in another
                instance):** select both of the above options.
        *   The key's policy should be configured with a couple of service
            accounts. In the CCKM Endpoint UI, the accounts are to be added to
            the *input.clients* list in the *Policies* textbox that appears when
            expanding the arrow next to the created endpoint. Add the following
            service accounts:
            *   The KMS service account listed in the GCP Key Management UI from
                step 3 (just above the box for the key URI)
            *   Any service account that will be used to access the key
                (including the one created earlier in the
                [Create and Configure a Service Account](#create-and-configure-a-service-account)
                section)
1.  Return to Google Cloud Console and paste the key URI from your EKM,
    completing the key setup flow started in step 3.

## Install STET

You can opt to use the pre-built binaries directly or build from source yourself
(see the `README.md` file in the STET source code for instructions). The stet
binary should be placed in an executable location (e.g., `~/bin` or
`/usr/local/bin`).

In order to generate attestations in a Confidential VM, STET needs to run with
root permissions. These permissions are only used when gathering attestations;
STET automatically reverts to non-privileged permissions otherwise. You can make
it automatically run in this way by installing it with `suid` permissions.

```
$ sudo mv stet /usr/local/bin/
$ sudo chown root /usr/local/bin/stet
$ sudo chmod u+sx,a+rx /usr/local/bin/stet
```

## STET Execution

### Install Configuration Files

As described in further detail in the
[*Advanced Configuration* guide](advanced_configuration.md), STET is configured
using YAML configuration files. Placing the following example configuration file
at `~/.config/stet.yaml` in your Confidential VM will allow you to encrypt and
decrypt using the key you created earlier in this guide (don't forget to replace
the key URI with the one from the key you created).

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
  - kek_infos:  # Note the extra hyphen here, because key_configs is a repeated field.
    - kek_uri: "gcp-kms://projects/my-project/locations/us-east1/keyRings/my-keyring/cryptoKeys/my-key"
    dek_algorithm: AES256_GCM
    no_split: true
```

### Executing STET from the command line

```bash
# Encrypt a file (using ~/.config/stet.yaml as the config file).
$ stet encrypt ~/plaintext.txt /tmp/encrypted.data
Wrote encrypted data to /tmp/encrypted.data

# Decrypt the ciphertext we just encrypted.
$ stet decrypt /tmp/encrypted.data /tmp/plaintext.txt
Wrote plaintext to /tmp/plaintext.txt
Blob ID of decrypted data: 1a4e5421-7cb4-45b3-a21c-6d1803872a50
Used these key URIs: [https://my-ekm.io/keys/123]

# Same decryption command as above with additional debugging info.
$ stet -logtostderr decrypt /tmp/encrypted.data /tmp/plaintext.txt
```
