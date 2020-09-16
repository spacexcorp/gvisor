load("//tools:defs.bzl", "go_library")

package(licenses = ["notice"])

go_library(
    name = "faketime",
    srcs = ["faketime.go"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/tcpip",
        "@com_github_dpjacques_clockwork//:go_default_library",
    ],
)
