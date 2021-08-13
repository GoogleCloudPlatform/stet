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

load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

licenses(["notice"])

package(default_visibility = ["//visibility:private"])

go_library(
    name = "client",
    srcs = [
        "aead.go",
        "client.go",
        "dek.go",
        "jwt.go",
        "metadata.go",
        "securesession.go",
        "shamir.go",
        "shares.go",
    ],
    importpath = "github.com/GoogleCloudPlatform/stet/client",
    visibility = ["//:__subpackages__"],
    deps = [
        "//constants",
        "//proto:attestation_evidence_go_proto",
        "//proto:confidential_wrap_go_proto",
        "//proto:config_go_proto",
        "//proto:secure_session_go_proto",
        "//transportshim",
        "@com_github_golang_glog//:glog",
        "@com_github_google_go_tpm//tpm2:go_default_library",
        "@com_github_google_go_tpm_tools//client:go_default_library",
        "@com_github_google_go_tpm_tools//proto/attest:go_default_library",
        "@com_github_google_tink_go//streamingaead/subtle:go_default_library",
        "@com_github_google_tink_go//subtle/random:go_default_library",
        "@com_github_google_uuid//:uuid",
        "@com_github_googleapis_gax_go_v2//:go_default_library",
        "@com_github_hashicorp_vault//:shamir",
        "@com_google_cloud_go//compute/metadata",
        "@com_google_cloud_go//iam/credentials/apiv1:go_default_library",
        "@com_google_cloud_go//kms/apiv1:go_default_library",
        "@go_googleapis//google/cloud/kms/v1:kms_go_proto",
        "@go_googleapis//google/iam/credentials/v1:credentials_go_proto",
        "@org_golang_google_grpc//:grpc",
        "@org_golang_google_protobuf//proto",
        "@org_golang_google_protobuf//types/known/wrapperspb",
        "@org_golang_x_oauth2//google:go_default_library",
    ],
)

go_test(
    name = "client_test",
    size = "small",
    srcs = [
        "aead_test.go",
        "client_test.go",
        "dek_test.go",
        "metadata_test.go",
        "shamir_test.go",
        "shares_test.go",
    ],
    embed = [":client"],
    deps = [
        "//proto:config_go_proto",
        "@com_github_google_tink_go//subtle/random:go_default_library",
        "@com_github_googleapis_gax_go_v2//:go_default_library",
        "@com_google_cloud_go//kms/apiv1:go_default_library",
        "@go_googleapis//google/cloud/kms/v1:kms_go_proto",
        "@org_golang_google_protobuf//types/known/wrapperspb",
    ],
)
