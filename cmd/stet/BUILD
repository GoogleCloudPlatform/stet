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

load("@io_bazel_rules_go//go:def.bzl", "go_binary")
load("//tools/build_defs/go:go_binary.bzl", "go_binary")

licenses(["notice"])

package(default_visibility = ["//visibility:private"])

go_binary(
    name = "main",
    srcs = ["main.go"],
    embedsrcs = [
        "notices/THIRD_PARTY_NOTICES",  # keep
    ],
    deps = [
        "//client",
        "//proto:config_go_proto",
        "@com_github_golang_glog//:glog",
        "@com_github_google_subcommands//:go_default_library",
        "@com_github_kubernetes_sigs_yaml//:go_default_library",
        "@org_golang_google_protobuf//encoding/protojson",
    ],
)
