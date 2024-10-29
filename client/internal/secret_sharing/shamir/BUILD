# Copyright 2024 Google LLC
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

package(
    default_visibility = [
        "//client/internal/secret_sharing:__subpackages__",
    ],
)

licenses(["notice"])

go_library(
    name = "shamir",
    srcs = ["shamir.go"],
    importpath = "github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/shamir",
    visibility = [
        "//client/shares:__subpackages__",
    ],
    deps = [
        "//client/internal/secret_sharing/finitefield",
        "//client/internal/secret_sharing/internal/field",
        "//client/internal/secret_sharing/internal/field/gf32",
        "//client/internal/secret_sharing/internal/field/gf8",
        "//client/internal/secret_sharing/internal/shamirgeneric",
        "//client/internal/secret_sharing/secrets",
    ],
)

go_test(
    name = "shamir_test",
    size = "small",
    srcs = ["shamir_test.go"],
    deps = [
        ":shamir",
        "//client/internal/secret_sharing/finitefield",
        "//client/internal/secret_sharing/secrets",
    ],
)
