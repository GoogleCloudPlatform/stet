load("@io_bazel_rules_go//go:def.bzl", "go_binary")
load("//tools/build_defs/go:go_binary.bzl", "go_binary")

go_binary(
    name = "main",
    srcs = ["main.go"],
    deps = [
        "//client/ekmclient",
        "//client/jwt",
        "//client/securesession",
        "//client/vpc",
        "//constants",
        "//proto:attestation_evidence_go_proto",
        "//proto:confidential_wrap_go_proto",
        "//proto:secure_session_go_proto",
        "//server",
        "//transportshim",
        "@com_github_alecthomas_colour//:go_default_library",
        "@com_github_golang_glog//:glog",
        "@com_github_google_go_tpm//legacy/tpm2:go_default_library",
        "@com_github_google_go_tpm_tools//proto/attest:go_default_library",
        "@com_google_cloud_go_kms//apiv1",
        "@com_google_cloud_go_kms//apiv1/kmspb:go_default_library",
        "@org_golang_google_protobuf//proto",
    ],
)
