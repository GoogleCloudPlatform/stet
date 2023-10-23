FROM google/cloud-sdk:latest

WORKDIR /test

LABEL "tee.launch_policy.allow_env_override"="CIPHERTEXT_OBJECT,PLAINTEXT_OBJECT"

# Assuming stet binary is built/present in the current directory.
ADD stet /usr/local/bin
RUN chown root /usr/local/bin/stet
RUN chmod u+sx,a+rx /usr/local/bin/stet

COPY config.yaml .

COPY --chown=1001 simple_workload.sh ./
RUN chmod +x ./simple_workload.sh
CMD ["./simple_workload.sh"]
