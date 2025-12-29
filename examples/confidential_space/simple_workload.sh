#!/bin/bash

# This is a simple Confidential Space workload that downloads an object from
# GCS, decrypts it with STET, and uploads the result to GCS.

gcloud storage cp $CIPHERTEXT_OBJECT /test/ciphertext

# Decrypt with STET.
stet decrypt --config-file=config.yaml /test/ciphertext /test/plaintext

# Print decrypted data.
gcloud storage cp /test/plaintext $PLAINTEXT_OBJECT
