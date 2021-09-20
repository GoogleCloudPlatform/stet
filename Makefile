# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# All proto files should generate a .pb.go file
PROTO_FILES = $(wildcard proto/*.proto)
PROTO_GEN = $(foreach proto,$(patsubst proto/%.proto,%,$(PROTO_FILES)),proto/$(proto)_go_proto/$(proto).pb.go)

# These protobufs need to be downloaded from other repositories
PROTO_DEPS = \
  proto/vendor/go-tpm-tools/proto/attest.proto \
  proto/vendor/go-tpm-tools/proto/tpm.proto \
  proto/vendor/googleapis/google/api/annotations.proto \
  proto/vendor/googleapis/google/api/http.proto
GO_TPM_TOOLS_VER=4ceb8e7
GOOGLEAPIS_VER=1872f45

# Default target should generate all .pb.go files
all: $(PROTO_GEN)

$(PROTO_GEN): $(PROTO_FILES) $(PROTO_DEPS)
	protoc \
		-I ./proto \
		-I ./proto/vendor/go-tpm-tools \
		-I ./proto/vendor/googleapis \
		--go_opt=module=github.com/GoogleCloudPlatform/stet \
		--go_out=. \
		--go-grpc_opt=module=github.com/GoogleCloudPlatform/stet \
		--go-grpc_out=. \
		$(PROTO_FILES)

proto/vendor/go-tpm-tools/%:
	curl --create-dirs -sfLo $@ https://github.com/google/go-tpm-tools/raw/$(GO_TPM_TOOLS_VER)/$*

proto/vendor/googleapis/%:
	curl --create-dirs -sfLo $@ https://github.com/googleapis/googleapis/raw/$(GOOGLEAPIS_VER)/$*

clean:
	rm -rf proto/vendor proto/*_go_proto

.PHONY: all