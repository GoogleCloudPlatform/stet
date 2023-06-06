load("@io_bazel_rules_go//go:def.bzl", "go_binary")

go_binary(
    name = "main",
    srcs = ["main.go"],
    deps = [
        "//client/ekmclient",
        "//client/securesession",
        "//constants",
        "//proto:attestation_evidence_go_proto",
        "//proto:confidential_wrap_go_proto",
        "//proto:secure_session_go_proto",
        "//server",
        "//transportshim",
        "@com_github_alecthomas_colour//:go_default_library",
        "@com_github_google_go_tpm//tpm2:go_default_library",
        "@com_github_google_go_tpm_tools//proto/attest:go_default_library",
        "@org_golang_google_protobuf//proto",
    ],
)
