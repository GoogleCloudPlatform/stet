load("@io_bazel_rules_go//go:def.bzl", "go_binary")

go_binary(
    name = "main",
    srcs = ["main.go"],
    deps = [
        "//client",
        "//constants",
        "//proto:secure_session_go_proto",
        "//server",
        "//transportshim",
        "@com_github_alecthomas_colour//:go_default_library",
    ],
)
