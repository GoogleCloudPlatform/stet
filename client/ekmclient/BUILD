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
load("//tools/build_defs/go:go_library.bzl", "go_library")
load("//tools/build_defs/go:go_test.bzl", "go_test")

package(
    default_visibility = ["//:__subpackages__"],
)

go_library(
    name = "ekmclient",
    srcs = ["confidentialekmclient.go"],
    importpath = "github.com/GoogleCloudPlatform/stet/client/ekmclient",
    deps = [
        "//proto:confidential_wrap_go_proto",
        "//proto:secure_session_go_proto",
        "@org_golang_google_protobuf//encoding/protojson",
        "@org_golang_google_protobuf//proto",
    ],
)

go_test(
    name = "ekmclient_test",
    srcs = ["confidentialekmclient_test.go"],
    embed = [":ekmclient"],
    deps = [
        "//proto:confidential_wrap_go_proto",
        "//proto:secure_session_go_proto",
        "@org_golang_google_protobuf//encoding/protojson",
        "@org_golang_google_protobuf//proto",
    ],
)
