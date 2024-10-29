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
    sha256 = "80a98277ad1311dacd837f9b16db62887702e9f1d1c4c9f796d0121a46c8e184",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.46.0/rules_go-v0.46.0.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.46.0/rules_go-v0.46.0.zip",
    ],
)

# See https://github.com/bazelbuild/rules_go/releases/tag/v0.41.0.
http_archive(
    name = "googleapis",
    sha256 = "9d1a930e767c93c825398b8f8692eca3fe353b9aaadedfbcf1fca2282c85df88",
    strip_prefix = "googleapis-64926d52febbf298cb82a8f472ade4a3969ba922",
    urls = [
        "https://github.com/googleapis/googleapis/archive/64926d52febbf298cb82a8f472ade4a3969ba922.zip",
    ],
)

load("@googleapis//:repository_rules.bzl", "switched_rules_by_language")

switched_rules_by_language(
    name = "com_google_googleapis_imports",
)

http_archive(
    name = "com_google_googleapis",
    sha256 = "38701e513aff81c89f0f727e925bf04ac4883913d03a60cdebb2c2a5f10beb40",
    strip_prefix = "googleapis-86fa44cc5ee2136e87c312f153113d4dd8e9c4de",
    urls = [
        "https://github.com/googleapis/googleapis/archive/86fa44cc5ee2136e87c312f153113d4dd8e9c4de.tar.gz",
    ],
)

# Protocol Buffers
http_archive(
    name = "com_google_protobuf",
    sha256 = "d0f5f605d0d656007ce6c8b5a82df3037e1d8fe8b121ed42e536f569dec16113",
    strip_prefix = "protobuf-3.14.0",
    urls = ["https://github.com/google/protobuf/archive/v3.14.0.tar.gz"],
)

# Required by protobuf
http_archive(
    name = "rules_python",
    sha256 = "9533911df1086debd5686ae4cfe3be6171faf65dfdb2e431619342689c3b9ed1",
    strip_prefix = "rules_python-aa27a3fe7e1a6c73028effe1c78e87d2e7fab641",
    urls = ["https://github.com/bazelbuild/rules_python/archive/aa27a3fe7e1a6c73028effe1c78e87d2e7fab641.tar.gz"],
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
    sha256 = "8ad77552825b078a10ad960bec6ef77d2ff8ec70faef2fd038db713f410f5d87",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.38.0/bazel-gazelle-v0.38.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.38.0/bazel-gazelle-v0.38.0.tar.gz",
    ],
)

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")

# RPC library
go_repository(
    name = "org_golang_google_grpc",
    importpath = "google.golang.org/grpc",
    sum = "h1:DibZuoBznOxbDQxRINckZcUvnCEvrW9pcWIE2yF9r1c=",
    version = "v1.66.0",
)

# Cloud KMS client library
go_repository(
    name = "com_google_cloud_go_kms",
    build_directives = [
        # https://github.com/bazelbuild/rules_go/issues/1877#issuecomment-1874616324
        "gazelle:resolve go google.golang.org/genproto/googleapis/api/annotations @org_golang_google_genproto//googleapis/api/annotations",  # keep
        "gazelle:resolve go google.golang.org/genproto/googleapis/api @org_golang_google_genproto//googleapis/api",  # keep
    ],
    importpath = "cloud.google.com/go/kms",
    sum = "h1:x0OVJDl6UH1BSX4THKlMfdcFWoE4ruh90ZHuilZekrU=",
    version = "v1.19.0",
)

# Cloud IAM client library
go_repository(
    name = "com_google_cloud_go_iam",
    build_directives = [
        "gazelle:resolve go google.golang.org/genproto/googleapis/api/annotations @org_golang_google_genproto//googleapis/api/annotations",  # keep
        "gazelle:resolve go google.golang.org/genproto/googleapis/api @org_golang_google_genproto//googleapis/api",  # keep
    ],
    importpath = "cloud.google.com/go/iam",
    sum = "h1:kZKMKVNk/IsSSc/udOb83K0hL/Yh/Gcqpz+oAkoIFN8=",
    version = "v1.2.0",
)

# Cloud Compute client library
go_repository(
    name = "com_google_cloud_go_compute_metadata",
    importpath = "cloud.google.com/go/compute/metadata",
    sum = "h1:Zr0eK8JbFv6+Wi4ilXAR8FJ3wyNdpxHKJNPos6LTZOY=",
    version = "v0.5.0",
)

# Needed for com_google_cloud_go.
go_repository(
    name = "com_github_googleapis_gax_go_v2",
    build_directives = [
        # https://github.com/bazelbuild/rules_go/issues/3625#issuecomment-1643804054
        "gazelle:resolve proto go google/rpc/code.proto @org_golang_google_genproto_googleapis_rpc//code",  # keep
        "gazelle:resolve proto proto google/rpc/code.proto @googleapis//google/rpc:code_proto",  # keep
    ],
    importpath = "github.com/googleapis/gax-go/v2",
    sum = "h1:yitjD5f7jQHhyDsnhKEBU52NdvvdSeGzlAnDPT0hH1s=",
    version = "v2.13.0",
)

# Needed for com_google_cloud_go.
go_repository(
    name = "org_golang_google_api",
    build_directives = [
        "gazelle:resolve go google.golang.org/genproto/googleapis/api/annotations @org_golang_google_genproto//googleapis/api/annotations",  # keep
        "gazelle:resolve go google.golang.org/genproto/googleapis/api @org_golang_google_genproto//googleapis/api",  # keep
    ],
    importpath = "google.golang.org/api",
    sum = "h1:k/RafYqebaIJBO3+SMnfEGtFVlvp5vSgqTUF54UN/zg=",
    version = "v0.196.0",
)

# Needed for com_google_cloud_go.
go_repository(
    name = "org_golang_x_oauth2",
    importpath = "golang.org/x/oauth2",
    sum = "h1:PbgcYx2W7i4LvjJWEbf0ngHV6qJYr86PkAV3bXdLEbs=",
    version = "v0.23.0",
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
    sum = "h1:1+mZ9upx1Dh6FmUTFR1naJ77miKiXgALjWOZ3NVFPmY=",
    version = "v1.2.2",
)

# Used to stabilize proto encoding.
go_repository(
    name = "org_golang_google_protobuf",
    build_directives = [
        "gazelle:proto disable",  # https://github.com/bazelbuild/rules_go/issues/3906
    ],
    importpath = "google.golang.org/protobuf",
    sum = "h1:6xV6lTsCfpGD21XK49h7MhtcApnLqkfYgPcdHftf6hg=",
    version = "v1.34.2",
)

# Used to create connection ID for secure session.
go_repository(
    name = "com_github_google_uuid",
    importpath = "github.com/google/uuid",
    sum = "h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=",
    version = "v1.6.0",
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
    patches = [
        "patches/go-tpm-tools/BUILD.patch",
        "patches/go-tpm-tools/attest.proto.patch",
    ],
    sum = "h1:oiQfAIkc6xTy9Fl5NKTeTJkBTlXdHsxAofmQyxBKY98=",
    version = "v0.4.4",
)

# Needed for conformance test.
go_repository(
    name = "com_github_google_go_tpm",
    importpath = "github.com/google/go-tpm",
    sum = "h1:0pGc4X//bAlmZzMKf8iz6IsDo1nYTbYJ6FZN/rg4zdM=",
    version = "v0.9.1",
)

# Used to convert YAML to JSON for config files.
go_repository(
    name = "com_github_kubernetes_sigs_yaml",
    importpath = "sigs.k8s.io/yaml",
    sum = "h1:Mk1wCc2gy/F0THH0TAp1QYyJNzRm2KCLy3o5ASXVI5E=",
    version = "v1.4.0",
)

# Used to colourize terminal output.
go_repository(
    name = "com_github_alecthomas_colour",
    importpath = "github.com/alecthomas/colour",
    sum = "h1:nOE9rJm6dsZ66RGWYSFrXw461ZIt9A6+nHgL7FRrDUk=",
    version = "v0.1.0",
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
    patches = [
        "patches/go-sev-guest/BUILD.patch",
    ],
    sum = "h1:gnww4U8fHV5DCPz4gykr1s8SEX1fFNcxCBy+vvXN24k=",
    version = "v0.11.1",
)

# Needed for go_tpm_tools.
go_repository(
    name = "com_github_google_go_tdx_guest",
    importpath = "github.com/google/go-tdx-guest",
    patches = [
        "patches/go-tdx-guest/BUILD.patch",
    ],
    sum = "h1:gl0KvjdsD4RrJzyLefDOvFOUH3NAJri/3qvaL5m83Iw=",
    version = "v0.3.1",
)

# Needed for com_github_google_go_tpm_tools.
go_repository(
    name = "com_github_google_go_attestation",
    importpath = "github.com/google/go-attestation",
    sum = "h1:jqtOrLk5MNdliTKjPbIPrAaRKJaKW+0LIU2n/brJYms=",
    version = "v0.5.1",
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
    sum = "h1:4iW/NwzqOqYEEoCBEFP+jPbBXbLqMpq3CifMyOnDUME=",
    version = "v1.2.1",
)

# Needed for com_github_alecthomas_colour.
go_repository(
    name = "com_github_mattn_go_isatty",
    importpath = "github.com/mattn/go-isatty",
    sum = "h1:xfD0iDuEKnDkl03q4limB+vH+GxLEtL/jb4xVJSWWEY=",
    version = "v0.0.20",
)

go_repository(
    name = "com_github_pkg_errors",
    importpath = "github.com/pkg/errors",
    sum = "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=",
    version = "v0.9.1",
)

go_repository(
    name = "com_github_pborman_uuid",
    importpath = "github.com/pborman/uuid",
    sum = "h1:+ZZIw58t/ozdjRaXh/3awHfmWRbzYxJoAdNJxe/3pvw=",
    version = "v1.2.1",
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
    sum = "h1:zZDs9gcbt9ZPLV0ndSyQk6Kacx2g/X+SKYovpnz3SMM=",
    version = "v0.1.8",
)

go_repository(
    name = "com_github_googleapis_enterprise_certificate_proxy",
    importpath = "github.com/googleapis/enterprise-certificate-proxy",
    sum = "h1:QRje2j5GZimBzlbhGA2V2QlGNgL8G6e+wGo/+/2bWI0=",
    version = "v0.3.3",
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
    sum = "h1:pPJltXNxVzT4pK9yD8vR9X75DaWYYmLGMsEvBfFQZzQ=",
    version = "v0.0.0-20240903143218-8af14fe29dc1",
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
    sum = "h1:RrRspgV4mU+YwB4FYnuBoKsUapNIL5cohGAmSH3azsw=",
    version = "v0.26.0",
)

go_repository(
    name = "org_golang_x_net",
    importpath = "golang.org/x/net",
    sum = "h1:a9JDOJc5GMUJ0+UDqmLT86WiEy7iWyIhz8gz8E4e5hE=",
    version = "v0.28.0",
)

go_repository(
    name = "org_golang_x_sync",
    importpath = "golang.org/x/sync",
    sum = "h1:3NFvSEYkUoMifnESzZl15y791HH1qU2xm6eCJU5ZPXQ=",
    version = "v0.8.0",
)

go_repository(
    name = "org_golang_x_sys",
    importpath = "golang.org/x/sys",
    sum = "h1:r+8e+loiHxRqhXVl6ML1nO3l1+oFoWbnlu2Ehimmi34=",
    version = "v0.25.0",
)

go_repository(
    name = "org_golang_x_text",
    importpath = "golang.org/x/text",
    sum = "h1:XvMDiNzPAl0jr17s6W9lcaIhGUfUORdGCNsuLmPG224=",
    version = "v0.18.0",
)

go_repository(
    name = "org_golang_x_time",
    importpath = "golang.org/x/time",
    sum = "h1:eTDhh4ZXt5Qf0augr54TN6suAUudPcawVZeIAPU7D4U=",
    version = "v0.6.0",
)

go_repository(
    name = "com_google_cloud_go_longrunning",
    build_directives = [
        "gazelle:resolve proto google/longrunning/operations.proto @googleapis//google/longrunning:operations_proto",
        "gazelle:resolve proto go google/longrunning/operations.proto @org_golang_google_genproto//googleapis/longrunning",
        "gazelle:resolve go google.golang.org/genproto/googleapis/api/annotations @org_golang_google_genproto//googleapis/api/annotations",  # keep
        "gazelle:resolve go google.golang.org/genproto/googleapis/api @org_golang_google_genproto//googleapis/api",  # keep
    ],
    importpath = "cloud.google.com/go/longrunning",
    sum = "h1:mM1ZmaNsQsnb+5n1DNPeL0KwQd9jQRqSqSDEkBZr+aI=",
    version = "v0.6.0",
)

go_repository(
    name = "com_github_google_go_configfs_tsm",
    importpath = "github.com/google/go-configfs-tsm",
    sum = "h1:ZYmHkdQavfsvVGDtX7RRda0gamelUNUhu0A9fbiuLmE=",
    version = "v0.3.2",
)

go_repository(
    name = "com_google_cloud_go_auth_oauth2adapt",
    importpath = "cloud.google.com/go/auth/oauth2adapt",
    sum = "h1:0GWE/FUsXhf6C+jAkWgYm7X9tK8cuEIfy19DBn6B6bY=",
    version = "v0.2.4",
)

go_repository(
    name = "io_opentelemetry_go_contrib_instrumentation_net_http_otelhttp",
    build_directives = [
        "gazelle:resolve go google.golang.org/genproto/googleapis/api/annotations @org_golang_google_genproto//googleapis/api/annotations",  # keep
        "gazelle:resolve go google.golang.org/genproto/googleapis/api @org_golang_google_genproto//googleapis/api",  # keep
    ],
    importpath = "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp",
    sum = "h1:TT4fX+nBOA/+LUkobKGW1ydGcn+G3vRw9+g5HwCphpk=",
    version = "v0.54.0",
)

go_repository(
    name = "io_opentelemetry_go_contrib_instrumentation_google_golang_org_grpc_otelgrpc",
    build_directives = [
        "gazelle:resolve go google.golang.org/genproto/googleapis/api/annotations @org_golang_google_genproto//googleapis/api/annotations",  # keep
        "gazelle:resolve go google.golang.org/genproto/googleapis/api @org_golang_google_genproto//googleapis/api",  # keep
    ],
    importpath = "go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc",
    sum = "h1:r6I7RJCN86bpD/FQwedZ0vSixDpwuWREjW9oRMsmqDc=",
    version = "v0.54.0",
)

go_repository(
    name = "com_google_cloud_go_auth",
    importpath = "cloud.google.com/go/auth",
    sum = "h1:VOEUIAADkkLtyfr3BLa3R8Ed/j6w1jTBmARx+wb5w5U=",
    version = "v0.9.3",
)

go_repository(
    name = "io_opentelemetry_go_otel",
    importpath = "go.opentelemetry.io/otel",
    sum = "h1:PdomN/Al4q/lN6iBJEN3AwPvUiHPMlt93c8bqTG5Llw=",
    version = "v1.29.0",
)

go_repository(
    name = "io_opentelemetry_go_otel_metric",
    importpath = "go.opentelemetry.io/otel/metric",
    sum = "h1:vPf/HFWTNkPu1aYeIsc98l4ktOQaL6LeSoeV2g+8YLc=",
    version = "v1.29.0",
)

go_repository(
    name = "io_opentelemetry_go_otel_trace",
    importpath = "go.opentelemetry.io/otel/trace",
    sum = "h1:J/8ZNK4XgR7a21DZUAsbF8pZ5Jcw1VhACmnYt39JTi4=",
    version = "v1.29.0",
)

go_repository(
    name = "com_github_felixge_httpsnoop",
    importpath = "github.com/felixge/httpsnoop",
    sum = "h1:NFTV2Zj1bL4mc9sqWACXbQFVBBg2W3GPvqp8/ESS2Wg=",
    version = "v1.0.4",
)

go_repository(
    name = "com_github_go_logr_logr",
    importpath = "github.com/go-logr/logr",
    sum = "h1:6pFjapn8bFcIbiKo3XT4j/BhANplGihG6tvd+8rYgrY=",
    version = "v1.4.2",
)

go_repository(
    name = "com_github_go_logr_stdr",
    importpath = "github.com/go-logr/stdr",
    sum = "h1:hSWxHoqTgW2S2qGc0LTAI563KZ5YKYRhT3MFKZMbjag=",
    version = "v1.2.2",
)

# General go toolchain dependencies
load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

go_rules_dependencies()

go_register_toolchains(version = "1.22.0")

# Required for go_repository imports.
gazelle_dependencies()
