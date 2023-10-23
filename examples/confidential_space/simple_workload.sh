#!/bin/bash

# This is a simple Confidential Space workload that downloads an object from
# GCS, decrypts it with STET, and uploads the result to GCS.

gsutil cp $CIPHERTEXT_OBJECT /test/ciphertext

# Decrypt with STET.
stet decrypt --config-file=config.yaml /test/ciphertext /test/plaintext

# Print decrypted data.
gsutil cp /test/plaintext $PLAINTEXT_OBJECT
