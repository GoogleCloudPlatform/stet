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

load("@io_bazel_rules_go//go:def.bzl", "go_library")

package(
    default_visibility = ["//:__subpackages__"],
)

go_library(
    name = "jwt",
    srcs = ["jwt.go"],
    importpath = "github.com/GoogleCloudPlatform/stet/client/jwt",
    deps = [
        "@com_google_cloud_go_compute_metadata//:go_default_library",
        "@com_google_cloud_go_iam//credentials/apiv1",
        "@com_google_cloud_go_iam//credentials/apiv1/credentialspb:go_default_library",
        "@org_golang_x_oauth2//google:go_default_library",
    ],
)
