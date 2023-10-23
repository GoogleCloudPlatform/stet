This document briefly describes how to use the example code in this directory,
consisting of the following files: * `config.yaml` is an example STET config
that uses Confidential Space. It is configured to use Confidential Space in the
decrypt workflow. * `simple_workload.sh` is a basic workload meant to be used in
a Confidential Space VM. It downloads data from GCS and executes `stet decrypt`
on it with `config.yaml`. * `Dockerfile` is an example dockerfile to build an
image with `simple_workload`.

## Encrypt Workflow

For this example, Confidential Space is not needed for the encryption workflow.
Execute `stet encrypt` and upload the ciphertext to your GCS bucket as you
normally would for
[Cloud Data Ingress](https://github.com/GoogleCloudPlatform/stet/blob/main/docs/workflows.md#cloud-data-ingress).

## Decrypt Workflow

For this example, the decryption workflow requires setting up a Confidential
Space VM. Follow the instructions
[here](https://codelabs.developers.google.com/codelabs/confidential-space#0) for
a codelab on how to set up Confidential Space - including building and uploading
the workload as a Docker image.

To use the provided example `config.yaml`: * Replace the `kek_uri` and
`kek_uri_pattern` fields with your KEK URI * Replace `wip_name` with the name of
your WIP * Replace `service_account` with the trusted service account attached
to your WIP * This is the same service account that should have `decrypt`
permissions on your KEK

When you create your Confidential VM instance, make sure to include the
following metadata values: * `tee-env-CIPHERTEXT_OBJECT=$CIPHER_URI`, where
`$CIPHER_URI` is the gsutil URI where your ciphertext was uploaded to. *
`tee-env-PLAINTEXT_OBJECT=$PLAIN_URI`, where `$PLAIN_URI` is the gsutil URI for
the workload to upload the deciphered data to.

Once the VM is created and started, it will automatically run the workload and
upload the decrypted data to the URI you specified. You can also inspect the VM
logs to see the exit code of the workload to confirm it ran correctly.
