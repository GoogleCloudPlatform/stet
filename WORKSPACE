workspace(name = "com_google_stet")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "rules_license",
    sha256 = "6157e1e68378532d0241ecd15d3c45f6e5cfd98fc10846045509fb2a7cc9e381",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_license/releases/download/0.0.4/rules_license-0.0.4.tar.gz",
        "https://github.com/bazelbuild/rules_license/releases/download/0.0.4/rules_license-0.0.4.tar.gz",
    ],
)

http_archive(
    name = "io_bazel_rules_go",
    sha256 = "51dc53293afe317d2696d4d6433a4c33feedb7748a9e352072e2ec3c0dafd2c6",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.40.1/rules_go-v0.40.1.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.40.1/rules_go-v0.40.1.zip",
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
    sha256 = "b8b6d75de6e4bf7c41b7737b183523085f56283f6db929b86c5e7e1f09cf59c9",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.31.1/bazel-gazelle-v0.31.1.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.31.1/bazel-gazelle-v0.31.1.tar.gz",
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
    ],
    importpath = "github.com/hashicorp/vault/shamir",
    visibility = ["//visibility:public"],
)
""",
    sha256 = "240d9b6fd17d5c8bc544695cae0a3529f45b5ed0c0ccece3e791ffe5eef7520a",
    strip_prefix = "vault-1.14.5",
    urls = ["https://github.com/hashicorp/vault/archive/refs/tags/v1.14.5.tar.gz"],
)

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")

# RPC library
go_repository(
    name = "org_golang_google_grpc",
    importpath = "google.golang.org/grpc",
    sum = "h1:Z5Iec2pjwb+LEOqzpB2MR12/eKFhDPhuqW91O+4bwUk=",
    version = "v1.59.0",
)

# Cloud KMS client library
go_repository(
    name = "com_google_cloud_go_kms",
    importpath = "cloud.google.com/go/kms",
    sum = "h1:RYsbxTRmk91ydKCzekI2YjryO4c5Y2M80Zwcs9/D/cI=",
    version = "v1.15.3",
)

# Cloud IAM client library
go_repository(
    name = "com_google_cloud_go_iam",
    importpath = "cloud.google.com/go/iam",
    sum = "h1:18tKG7DzydKWUnLjonWcJO6wjSCAtzh4GcRKlH/Hrzc=",
    version = "v1.1.3",
)

# Cloud Compute client library
go_repository(
    name = "com_google_cloud_go_compute_metadata",
    importpath = "cloud.google.com/go/compute/metadata",
    sum = "h1:mg4jlk7mCAj6xXp9UJ4fjI9VUI5rubuGBW5aJ7UnBMY=",
    version = "v0.2.3",
)

# Needed for com_google_cloud_go.
go_repository(
    name = "com_github_googleapis_gax_go_v2",
    importpath = "github.com/googleapis/gax-go/v2",
    sum = "h1:A+gCJKdRfqXkr+BIRGtZLibNXf0m1f9E4HG56etFpas=",
    version = "v2.12.0",
)

# Needed for com_google_cloud_go.
go_repository(
    name = "org_golang_google_api",
    importpath = "google.golang.org/api",
    sum = "h1:HBq4TZlN4/1pNcu0geJZ/Q50vIwIXT532UIMYoo0vOs=",
    version = "v0.148.0",
)

# Needed for com_google_cloud_go.
go_repository(
    name = "org_golang_x_oauth2",
    importpath = "golang.org/x/oauth2",
    sum = "h1:jDDenyj+WgFtmV3zYVoi8aE2BwtXFLWOA67ZfNWftiY=",
    version = "v0.13.0",
)

# Used for crypto APIs
go_repository(
    name = "com_github_google_tink_go",
    importpath = "github.com/google/tink/go",
    sum = "h1:6Eox8zONGebBFcCBqkVmt60LaWZa6xg1cl/DwAh/J1w=",
    version = "v1.7.0",
)

# Used for logging
go_repository(
    name = "com_github_golang_glog",
    importpath = "github.com/golang/glog",
    sum = "h1:DVjP2PbBOzHyzA+dn3WhHIq4NdVu3Q+pvivFICf/7fo=",
    version = "v1.1.2",
)

# Used to stabilize proto encoding.
go_repository(
    name = "org_golang_google_protobuf",
    importpath = "google.golang.org/protobuf",
    sum = "h1:g0LDEJHgrBl9N9r17Ru3sqWhkIx2NB67okBHPwC7hs8=",
    version = "v1.31.0",
)

# Used to create connection ID for secure session.
go_repository(
    name = "com_github_google_uuid",
    importpath = "github.com/google/uuid",
    sum = "h1:KjJaJ9iWZ3jOFZIf1Lqf4laDRCasjl0BCmnEGxkdLb4=",
    version = "v1.3.1",
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
    sum = "h1:gYU6iwRo0tY3V6NDnS6m+XYog+b3g6YFhHQl3sYaUL4=",
    version = "v0.4.1",
    patches = [
        "patches/go-tpm-tools/BUILD.patch",
        "patches/go-tpm-tools/attest.proto.patch",
    ],
)

# Needed for conformance test.
go_repository(
    name = "com_github_google_go_tpm",
    importpath = "github.com/google/go-tpm",
    sum = "h1:sQF6YqWMi+SCXpsmS3fd21oPy/vSddwZry4JnmltHVk=",
    version = "v0.9.0",
)

# Used to convert YAML to JSON for config files.
go_repository(
    name = "com_github_kubernetes_sigs_yaml",
    importpath = "sigs.k8s.io/yaml",
    commit = "11e43d4a8b9271a822a950dbf9b6ff15fe00fafc",
)

# Used to colourize terminal output.
go_repository(
    name = "com_github_alecthomas_colour",
    importpath = "github.com/alecthomas/colour",
    sum = "h1:nOE9rJm6dsZ66RGWYSFrXw461ZIt9A6+nHgL7FRrDUk=",
    version = "v0.1.0"
)

go_repository(
    name = "com_github_google_go_cmp",
    importpath = "github.com/google/go-cmp",
    sum = "h1:ofyhxvXcZhMsU5ulbFiLKl/XBFqE1GSq7atu8tAmTRI=",
    version = "v0.6.0",
)

# Indirect dependencies.

# Needed for com_google_cloud_go.
go_repository(
    name = "com_github_golang_groupcache",
    importpath = "github.com/golang/groupcache",
    sum = "h1:oI5xCqsCo564l8iNU+DwB5epxmsaqB+rhGL0m5jtYqE=",
    version = "v0.0.0-20210331224755-41bb18bfe9da",
)

# Needed for com_google_cloud_go.
go_repository(
    name = "io_opencensus_go",
    importpath = "go.opencensus.io",
    sum = "h1:y73uSU6J157QMP2kn2r30vwW1A2W2WFwSCGnAVxeaD0=",
    version = "v0.24.0",
)

# Needed for go_tpm_tools.
go_repository(
  name = "com_github_google_go_sev_guest",
  importpath = "github.com/google/go-sev-guest",
  sum = "h1:DBCABhTo7WicP27ZH/hwcCdjcmxFkxxMOQXm5hFcfp4=",
  version = "v0.7.0",
  patches = [
    "patches/go-sev-guest/BUILD.patch",
  ],
)

# Needed for go_tpm_tools.
go_repository(
  name = "com_github_google_go_tdx_guest",
  importpath = "github.com/google/go-tdx-guest",
  sum = "h1:XqVJa7fVU8b+Hlhcvw49qfg0+LYcRI+V+jYUrSek848=",
  version = "v0.2.1-0.20230907045450-944015509c84",
  patches = [
    "patches/go-tdx-guest/BUILD.patch",
  ],
)

# Needed for com_github_google_go_tpm_tools.
go_repository(
    name = "com_github_google_go_attestation",
    importpath = "github.com/google/go-attestation",
    sum = "h1:jXtAWT2sw2Yu8mYU0BC7FDidR+ngxFPSE+pl6IUu3/0=",
    version = "v0.5.0",
)

# Needed for com_github_google_go_attestation.
go_repository(
    name = "com_github_google_go_tspi",
    importpath = "github.com/google/go-tspi",
    sum = "h1:ADtq8RKfP+jrTyIWIZDIYcKOMecRqNJFOew2IT0Inus=",
    version = "v0.3.0",
)

# Needed for com_github_google_go_attestation.
go_repository(
    name = "com_github_google_certificate_transparency_go",
    importpath = "github.com/google/certificate-transparency-go",
    sum = "h1:4hE0GEId6NAW28dFpC+LrRGwQX5dtmXQGDbg8+/MZOM=",
    version = "v1.1.2",
)

# Needed for com_github_alecthomas_colour.
go_repository(
    name = "com_github_mattn_go_isatty",
    importpath = "github.com/mattn/go-isatty",
    sum = "h1:JITubQf0MOLdlGRuRq+jtsDlekdYPia9ZFsB8h/APPA=",
    version = "v0.0.19"
)

go_repository(
    name = "com_github_pkg_errors",
    importpath = "github.com/pkg/errors",
    sum = "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=",
    version = "v0.9.1"
)

go_repository(
    name = "com_github_pborman_uuid",
    importpath = "github.com/pborman/uuid",
    sum = "h1:J7Q5mO4ysT1dv8hyrUGHb9+ooztCXu1D8MY8DZYsu3g=",
    version = "v1.2.0"
)

go_repository(
  name = "com_github_google_logger",
  importpath = "github.com/google/logger",
  sum = "h1:+6Z2geNxc9G+4D4oDO9njjjn2d0wN5d7uOo0vOIW1NQ=",
  version = "v1.1.1",
)

go_repository(
  name = "com_github_google_s2a_go",
  importpath = "github.com/google/s2a-go",
  sum = "h1:60BLSyTrOV4/haCDW4zb1guZItoSq8foHCXrAnjBo/o=",
  version = "v0.1.7",
)

go_repository(
  name = "com_github_googleapis_enterprise_certificate_proxy",
  importpath = "github.com/googleapis/enterprise-certificate-proxy",
  sum = "h1:SBWmZhjUDRorQxrN0nwzf+AHBxnbFjViHQS4P0yVpmQ=",
  version = "v0.3.1",
)

go_repository(
    name = "org_golang_google_appengine",
    importpath = "google.golang.org/appengine",
    sum = "h1:FZR1q0exgwxzPzp/aF+VccGrSfxfPpkBqjIIEq3ru6c=",
    version = "v1.6.7",
)

go_repository(
    name = "org_golang_google_genproto_googleapis_rpc",
    importpath = "google.golang.org/genproto/googleapis/rpc",
    sum = "h1:a2MQQVoTo96JC9PMGtGBymLp7+/RzpFc2yX/9WfFg1c=",
    version = "v0.0.0-20231012201019-e917dd12ba7a",
)

go_repository(
    name = "org_uber_go_multierr",
    importpath = "go.uber.org/multierr",
    sum = "h1:blXXJkSxSSfBVBlC76pxqeO+LN3aDfLQo+309xJstO0=",
    version = "v1.11.0",
)

go_repository(
    name = "org_golang_x_crypto",
    importpath = "golang.org/x/crypto",
    sum = "h1:wBqGXzWJW6m1XrIKlAH0Hs1JJ7+9KBwnIO8v66Q9cHc=",
    version = "v0.14.0",
)

go_repository(
    name = "org_golang_x_net",
    importpath = "golang.org/x/net",
    sum = "h1:pVaXccu2ozPjCXewfr1S7xza/zcXTity9cCdXQYSjIM=",
    version = "v0.17.0",
)

go_repository(
    name = "org_golang_x_sync",
    importpath = "golang.org/x/sync",
    sum = "h1:zxkM55ReGkDlKSM+Fu41A+zmbZuaPVbGMzvvdUPznYQ=",
    version = "v0.4.0",
)

go_repository(
    name = "org_golang_x_sys",
    importpath = "golang.org/x/sys",
    sum = "h1:Af8nKPmuFypiUBjVoU9V20FiaFXOcuZI21p0ycVYYGE=",
    version = "v0.13.0",
)

go_repository(
    name = "org_golang_x_text",
    importpath = "golang.org/x/text",
    sum = "h1:ablQoSUd0tRdKxZewP80B+BaqeKJuVhuRxj/dkrun3k=",
    version = "v0.13.0",
)

# General go toolchain dependencies
load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")
go_rules_dependencies()
go_register_toolchains(version = "1.20.5")

# Required for go_repository imports.
gazelle_dependencies()
