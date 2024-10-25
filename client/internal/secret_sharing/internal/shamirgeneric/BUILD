load("@io_bazel_rules_go//go:def.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//client:__subpackages__"],
)

go_library(
    name = "shamirgeneric",
    srcs = ["shamir_generic.go"],
    importpath = "github.com/GoogleCloudPlatform/stet/client/internal/secret_sharing/internal/shamirgeneric",
    deps = [
        "//client/internal/secret_sharing/internal/field",
        "//client/internal/secret_sharing/secrets",
    ],
)

go_test(
    name = "shamirgeneric_test",
    srcs = ["shamir_generic_test.go"],
    deps = [
        ":shamirgeneric",
        "//client/internal/secret_sharing/finitefield",
        "//client/internal/secret_sharing/internal/field/gf32",
        "//client/internal/secret_sharing/secrets",
    ],
)
