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

all: protoc-vendor protoc

protoc:
	@protoc \
		-I ./proto \
		-I ./proto/vendor/go-tpm-tools \
		-I ./proto/vendor/googleapis \
		--go_out=. \
		--go_opt=module=github.com/GoogleCloudPlatform/stet \
		--go-grpc_out=. --go-grpc_opt=module=github.com/GoogleCloudPlatform/stet proto/*.proto


protoc-vendor:
	@rm -rf ./proto/vendor
	@curl --create-dirs -sfLo ./proto/vendor/go-tpm-tools/proto/attest.proto https://github.com/google/go-tpm-tools/raw/master/proto/attest.proto
	@curl --create-dirs -sfLo ./proto/vendor/go-tpm-tools/proto/tpm.proto https://github.com/google/go-tpm-tools/raw/master/proto/tpm.proto
	@curl --create-dirs -sfLo ./proto/vendor/googleapis/google/api/annotations.proto https://github.com/googleapis/googleapis/raw/master/google/api/annotations.proto
	@curl --create-dirs -sfLo ./proto/vendor/googleapis/google/api/http.proto https://github.com/googleapis/googleapis/raw/master/google/api/http.proto

.PHONY: all protoc protoc-vendor