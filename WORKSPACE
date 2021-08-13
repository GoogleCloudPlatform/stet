workspace(name = "com_google_stet")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Go Bazel Rules
http_archive(
    name = "io_bazel_rules_go",
    sha256 = "69de5c704a05ff37862f7e0f5534d4f479418afc21806c887db544a316f3cb6b",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.27.0/rules_go-v0.27.0.tar.gz",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.27.0/rules_go-v0.27.0.tar.gz",
    ],
)

# Protocol Buffers
http_archive(
    name = "com_google_protobuf",
    strip_prefix = "protobuf-3.14.0",
    urls = ["https://github.com/google/protobuf/archive/v3.14.0.tar.gz"],
    sha256 = "d0f5f605d0d656007ce6c8b5a82df3037e1d8fe8b121ed42e536f569dec16113",
)

# Required by protobuf
http_archive(
    name = "rules_python",
    urls = ["https://github.com/bazelbuild/rules_python/archive/aa27a3fe7e1a6c73028effe1c78e87d2e7fab641.tar.gz"],
    sha256 = "9533911df1086debd5686ae4cfe3be6171faf65dfdb2e431619342689c3b9ed1",
    strip_prefix = "rules_python-aa27a3fe7e1a6c73028effe1c78e87d2e7fab641",
)

# Required by protobuf
http_archive(
    name = "zlib",
    build_file = "@com_google_protobuf//:third_party/zlib.BUILD",
    sha256 = "629380c90a77b964d896ed37163f5c3a34f6e6d897311f1df2a7016355c45eff",
    strip_prefix = "zlib-1.2.11",
    urls = ["https://github.com/madler/zlib/archive/v1.2.11.tar.gz"],
)

# Needed to manage go dependencies
http_archive(
    name = "bazel_gazelle",
    sha256 = "62ca106be173579c0a167deb23358fdfe71ffa1e4cfdddf5582af26520f1c66f",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.23.0/bazel-gazelle-v0.23.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.23.0/bazel-gazelle-v0.23.0.tar.gz",
    ],
)

# Used only for Shamir's Secret Sharing implementation.
# NOTE: Not imported as go_repository to avoid pulling in all of vault's deps.
http_archive(
    name = "com_github_hashicorp_vault",
    build_file_content = """
load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "shamir",
    srcs = [
        "shamir/shamir.go",
        "shamir/tables.go",
    ],
    importpath = "github.com/hashicorp/vault/shamir",
    visibility = ["//visibility:public"],
    deps = ["@com_github_hashicorp_errwrap//:errwrap"],
)
""",
    sha256 = "5d9beff14b24825642a46dc322a814e82eb618cebd412a0d2ac652039be59d70",
    strip_prefix = "vault-1.7.3",
    urls = ["https://github.com/hashicorp/vault/archive/refs/tags/v1.7.3.tar.gz"],
)

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")

# RPC library
go_repository(
    name = "org_golang_google_grpc",
    importpath = "google.golang.org/grpc",
    sum = "h1:uSZWeQJX5j11bIQ4AJoj+McDBo29cY1MCoC1wO3ts+c=",
    version = "v1.37.0",
)

# Cloud KMS client library
go_repository(
    name = "com_google_cloud_go",
    importpath = "cloud.google.com/go",
    sum = "h1:NLQf5e1OMspfNT1RAHOB3ublr1TW3YTXO8OiWwVjK2U=",
    version = "v0.61.0",
)

# Needed for com_google_cloud_go.
go_repository(
    name = "com_github_googleapis_gax_go_v2",
    importpath = "github.com/googleapis/gax-go/v2",
    sum = "h1:sjZBwGj9Jlw33ImPtvFviGYvseOtDM7hkSKB7+Tv3SM=",
    version = "v2.0.5",
)

# Needed for com_google_cloud_go.
go_repository(
    name = "org_golang_google_api",
    importpath = "google.golang.org/api",
    sum = "h1:BaiDisFir8O4IJxvAabCGGkQ6yCJegNQqSVoYUNAnbk=",
    version = "v0.29.0",
)

# Needed for com_google_cloud_go.
go_repository(
    name = "org_golang_x_oauth2",
    importpath = "golang.org/x/oauth2",
    sum = "h1:TzXSXBo42m9gQenoE3b9BGiEpg5IG2JkU5FkPIawgtw=",
    version = "v0.0.0-20200107190931-bf48bf16ab8d",
)

# Needed for com_google_cloud_go.
go_repository(
    name = "io_opencensus_go",
    importpath = "go.opencensus.io",
    sum = "h1:LYy1Hy3MJdrCdMwwzxA/dRok4ejH+RwNGbuoD9fCjto=",
    version = "v0.22.4",
)

# Needed for com_google_cloud_go.
go_repository(
    name = "com_github_golang_groupcache",
    importpath = "github.com/golang/groupcache",
    sum = "h1:1r7pUrabqp18hOBcwBwiTsbnFeTZHV9eER/QT5JVZxY=",
    version = "v0.0.0-20200121045136-8c9f03a8e57e",
)

# Required for Shamir's implementation
go_repository(
    name = "com_github_hashicorp_errwrap",
    importpath = "github.com/hashicorp/errwrap",
    sum = "h1:OxrOeh75EUXMY8TBjag2fzXGZ40LB6IKw45YeGUDY2I=",
    version = "v1.1.0",
)

# Used for crypto APIs
go_repository(
    name = "com_github_google_tink_go",
    importpath = "github.com/google/tink/go",
    sum = "h1:iC+PQlQsR8oVxJnrSDS8u9GFXsPy8f56LFmEaGZDhD4=",
    version = "v1.5.0",
)

# Used for logging
go_repository(
    name = "com_github_golang_glog",
    commit = "424d2337a5299a465c8a8228fc3ba4b1c28337a2",
    importpath = "github.com/golang/glog",
)

# Used for proto encoding.
go_repository(
    name = "com_github_tdewolff_minify_v2",
    importpath = "github.com/tdewolff/minify/v2",
    sum = "h1:2Pv8pFRX/ZfjTRYX2xzcuNrkEJqU5TfriNJJYOeN3rI=",
    version = "v2.9.16",
)

# Needed for tdewolff/minify.
go_repository(
    name = "com_github_tdewolff_parse_v2",
    importpath = "github.com/tdewolff/parse/v2",
    sum = "h1:ADVB3h2AR2jkLhY1LttDqRj3FFPDgSa0RZUBq5+q/t8=",
    version = "v2.5.16",
)

# Used to stabilize proto encoding.
go_repository(
    name = "org_golang_google_protobuf",
    importpath = "google.golang.org/protobuf",
    sum = "h1:Ejskq+SyPohKW+1uil0JJMtmHCgJPJ/qWTxr8qp+R4c=",
    version = "v1.25.0",
)

# Used to create connection ID for secure session.
go_repository(
    name = "com_github_google_uuid",
    importpath = "github.com/google/uuid",
    sum = "h1:qJYtXnJRWmpe7m/3XlyhrsLrEURqHRM2kxzoxXqyUDs=",
    version = "v1.2.0",
)

# Used to build the STET CLI.
go_repository(
    name = "com_github_google_subcommands",
    importpath = "github.com/google/subcommands",
    sum = "h1:vWQspBTo2nEqTUFita5/KeEWlUL8kQObDFbub/EN9oE=",
    version = "v1.2.0",
)

# Used for vTPM functionality.
go_repository(
    name = "com_github_google_go_tpm_tools",
    importpath = "github.com/google/go-tpm-tools",
    commit = "0e0a98fb328ee3449247002a09e46249d38c65af",
    patches = ["patches/go-tpm-tools/BUILD.patch"],
)

# Needed for com_github_google_go_tpm_tools.
go_repository(
    name = "com_github_google_go_tpm",
    importpath = "github.com/google/go-tpm",
    sum = "h1:3iQQ2dlEf+1no7CLlfLPYzxhQy7j2G/emBqU5okydaw=",
    version = "v0.3.2",
)

# Used to convert YAML to JSON for config files.
go_repository(
    name = "com_github_kubernetes_sigs_yaml",
    importpath = "sigs.k8s.io/yaml",
    commit = "11e43d4a8b9271a822a950dbf9b6ff15fe00fafc",
)

# General go toolchain dependencies
load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")
go_rules_dependencies()
go_register_toolchains(version = "1.16")

# Required for go_repository imports.
gazelle_dependencies()
