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
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//:__subpackages__"],
)

licenses(["notice"])

go_library(
    name = "client",
    srcs = [
        "client.go",
        "clientutil.go",
    ],
    importpath = "github.com/GoogleCloudPlatform/stet/client",
    deps = [
        "//client/jwt",
        "//client/securesession",
        "//client/shares",
        "//proto:config_go_proto",
        "@com_github_golang_glog//:glog",
        "@com_github_google_tink_go//streamingaead/subtle:go_default_library",
        "@com_github_google_uuid//:uuid",
        "@com_github_googleapis_gax_go_v2//:go_default_library",
        "@com_google_cloud_go//kms/apiv1:go_default_library",
        "@go_googleapis//google/cloud/kms/v1:kms_go_proto",
        "@org_golang_google_api//option:go_default_library",
        "@org_golang_google_protobuf//proto",
        "@org_golang_google_protobuf//types/known/wrapperspb",
    ],
)

go_test(
    name = "client_test",
    size = "small",
    srcs = [
        "client_keys_test.go",
        "client_test.go",
        "clientutil_test.go",
    ],
    embed = [":client"],
    deps = [
        "//client/securesession",
        "//client/shares",
        "//proto:config_go_proto",
        "@com_github_google_tink_go//subtle/random:go_default_library",
        "@com_github_googleapis_gax_go_v2//:go_default_library",
        "@com_google_cloud_go//kms/apiv1:go_default_library",
        "@go_googleapis//google/cloud/kms/v1:kms_go_proto",
        "@org_golang_google_protobuf//proto",
        "@org_golang_google_protobuf//types/known/wrapperspb",
    ],
)
