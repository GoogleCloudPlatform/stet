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

package(
    default_visibility = ["//:__subpackages__"],
)

go_library(
    name = "cloudkms",
    srcs = ["cloudkms.go"],
    importpath = "github.com/GoogleCloudPlatform/stet/client/cloudkms",
    deps = [
        "@com_github_googleapis_gax_go_v2//:go_default_library",
        "@com_google_cloud_go//kms/apiv1:go_default_library",
        "@go_googleapis//google/cloud/kms/v1:kms_go_proto",
        "@org_golang_google_api//option:go_default_library",
        "@org_golang_google_protobuf//types/known/wrapperspb",
    ],
)

go_test(
    name = "cloudkms_test",
    srcs = ["cloudkms_test.go"],
    embed = [":cloudkms"],
    deps = [
        "//client/testutil",
        "@com_github_google_go_cmp//cmp:go_default_library",
        "@com_github_googleapis_gax_go_v2//:go_default_library",
        "@com_google_cloud_go//kms/apiv1:go_default_library",
        "@go_googleapis//google/cloud/kms/v1:kms_go_proto",
        "@org_golang_google_api//option:go_default_library",
        "@org_golang_google_protobuf//types/known/wrapperspb",
    ],
)
