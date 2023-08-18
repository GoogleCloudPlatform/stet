load("@io_bazel_rules_go//go:def.bzl", "go_library")

package(
    default_visibility = ["//:__subpackages__"],
)

go_library(
    name = "testutil",
    srcs = ["testutil.go"],
    importpath = "github.com/GoogleCloudPlatform/stet/client/testutil",
    deps = [
        "@com_github_googleapis_gax_go_v2//:go_default_library",
        "@com_google_cloud_go//kms/apiv1:go_default_library",
        "@go_googleapis//google/cloud/kms/v1:kms_go_proto",
        "@org_golang_google_protobuf//types/known/wrapperspb",
    ],
)
