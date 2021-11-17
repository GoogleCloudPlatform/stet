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
    name = "server",
    srcs = [
        "httpproxy.go",
        "server.go",
    ],
    importpath = "github.com/GoogleCloudPlatform/stet/server",
    visibility = ["//:__subpackages__"],
    deps = [
        "//constants",
        "//proto:attestation_evidence_go_proto",
        "//proto:confidential_wrap_go_proto",
        "//proto:secure_session_go_proto",
        "//transportshim",
        "@com_github_golang_glog//:glog",
        "@com_github_google_go_tpm_tools//proto/attest:go_default_library",
        "@com_github_google_go_tpm_tools//server:go_default_library",
        "@com_github_google_uuid//:uuid",
        "@org_golang_google_api//compute/v1:go_default_library",
        "@org_golang_google_grpc//:grpc",
        "@org_golang_google_protobuf//encoding/protojson",
        "@org_golang_google_protobuf//proto",
    ],
)

go_test(
    name = "server_test",
    size = "small",
    srcs = [
        "server_test.go",
    ],
    embed = [":server"],
    deps = [
        "//proto:secure_session_go_proto",
    ],
)
