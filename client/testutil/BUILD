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
        "@com_google_cloud_go_kms//apiv1",
        "@com_google_cloud_go_kms//apiv1/kmspb:go_default_library",
        "@org_golang_google_protobuf//types/known/wrapperspb",
    ],
)
