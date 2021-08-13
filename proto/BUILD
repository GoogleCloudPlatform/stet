# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Protos that are shared between the client and server.

load("@rules_proto//proto:defs.bzl", "proto_library")
load("@io_bazel_rules_go//proto:def.bzl", "go_proto_library")

licenses(["notice"])

package(default_visibility = ["//visibility:private"])

proto_library(
    name = "attestation_evidence_proto",
    srcs = ["attestation_evidence.proto"],
    deps = ["@com_github_google_go_tpm_tools//proto:attest_proto"],
)

go_proto_library(
    name = "attestation_evidence_go_proto",
    importpath = "github.com/GoogleCloudPlatform/stet/proto/attestation_evidence_go_proto",
    proto = ":attestation_evidence_proto",
    visibility = ["//:__subpackages__"],
    deps = ["@com_github_google_go_tpm_tools//proto/attest"],
)

proto_library(
    name = "confidential_wrap_proto",
    srcs = ["confidential_wrap.proto"],
    deps = [
        "@com_google_protobuf//:duration_proto",
        "@go_googleapis//google/api:annotations_proto",
    ],
)

go_proto_library(
    name = "confidential_wrap_go_proto",
    compilers = ["@io_bazel_rules_go//proto:go_grpc"],
    importpath = "github.com/GoogleCloudPlatform/stet/proto/confidential_wrap_go_proto",
    proto = ":confidential_wrap_proto",
    visibility = ["//:__subpackages__"],
    deps = ["@go_googleapis//google/api:annotations_go_proto"],
)

proto_library(
    name = "config_proto",
    srcs = ["config.proto"],
)

go_proto_library(
    name = "config_go_proto",
    importpath = "github.com/GoogleCloudPlatform/stet/proto/config_go_proto",
    proto = ":config_proto",
    visibility = ["//:__subpackages__"],
)

proto_library(
    name = "secure_session_proto",
    srcs = ["secure_session.proto"],
    deps = ["@go_googleapis//google/api:annotations_proto"],
)

go_proto_library(
    name = "secure_session_go_proto",
    compilers = ["@io_bazel_rules_go//proto:go_grpc"],
    importpath = "github.com/GoogleCloudPlatform/stet/proto/secure_session_go_proto",
    proto = ":secure_session_proto",
    visibility = ["//:__subpackages__"],
    deps = ["@go_googleapis//google/api:annotations_go_proto"],
)
