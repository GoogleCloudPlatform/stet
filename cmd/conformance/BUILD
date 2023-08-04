load("@io_bazel_rules_go//go:def.bzl", "go_binary")

go_binary(
    name = "main",
    srcs = ["main.go"],
    deps = [
        "//client/ekmclient",
        "//client/jwt",
        "//client/securesession",
        "//constants",
        "//proto:attestation_evidence_go_proto",
        "//proto:confidential_wrap_go_proto",
        "//proto:secure_session_go_proto",
        "//server",
        "//transportshim",
        "@com_github_alecthomas_colour//:go_default_library",
        "@com_github_golang_glog//:glog",
        "@com_github_google_go_tpm//tpm2:go_default_library",
        "@com_github_google_go_tpm_tools//proto/attest:go_default_library",
        "@com_google_cloud_go//kms/apiv1:go_default_library",
        "@go_googleapis//google/cloud/kms/v1:kms_go_proto",
        "@org_golang_google_protobuf//proto",
    ],
)
