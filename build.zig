const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("websocket", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });

    const mod_tests = b.addTest(.{ .root_module = mod });
    const run_mod_tests = b.addRunArtifact(mod_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_mod_tests.step);

    const echo_server = b.addExecutable(.{
        .name = "echo-server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/echo_server.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "websocket", .module = mod },
            },
        }),
    });
    echo_server.root_module.linkSystemLibrary("zlib", .{ .use_pkg_config = .force });

    b.installArtifact(echo_server);

    const echo_run = b.addRunArtifact(echo_server);
    if (b.args) |args| {
        echo_run.addArgs(args);
    }

    const echo_step = b.step("echo-server", "Run the Autobahn echo server");
    echo_step.dependOn(&echo_run.step);

    const examples_step = b.step("examples", "Build all examples");

    const blocking_echo = b.addExecutable(.{
        .name = "blocking-echo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/blocking-echo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "websocket", .module = mod },
            },
        }),
    });
    b.installArtifact(blocking_echo);
    examples_step.dependOn(&blocking_echo.step);

    const http_upgrade = b.addExecutable(.{
        .name = "http-upgrade",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/http-upgrade.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "websocket", .module = mod },
            },
        }),
    });
    b.installArtifact(http_upgrade);
    examples_step.dependOn(&http_upgrade.step);

    const run_autobahn = b.path("scripts/run-autobahn.nu").getPath(b);

    const conformance_script = b.addSystemCommand(&.{
        "nu",
        run_autobahn,
        b.getInstallPath(.bin, "echo-server"),
        "9002",
        "echo-server",
        "fast",
    });
    conformance_script.step.dependOn(&b.addInstallArtifact(echo_server, .{}).step);

    const conformance_step = b.step("conformance", "Run the fast Autobahn conformance suite");
    conformance_step.dependOn(&conformance_script.step);

    const conformance_full_script = b.addSystemCommand(&.{
        "nu",
        run_autobahn,
        b.getInstallPath(.bin, "echo-server"),
        "9002",
        "echo-server",
        "full",
    });
    conformance_full_script.step.dependOn(&b.addInstallArtifact(echo_server, .{}).step);

    const conformance_full_step = b.step(
        "conformance-full",
        "Run the full Autobahn conformance test suite",
    );
    conformance_full_step.dependOn(&conformance_full_script.step);

    if (b.lazyDependency("libxev", .{})) |xev_dep| {
        const xev_echo = b.addExecutable(.{
            .name = "xev-echo",
            .root_module = b.createModule(.{
                .root_source_file = b.path("examples/xev-echo.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "websocket", .module = mod },
                    .{ .name = "xev", .module = xev_dep.module("xev") },
                },
            }),
        });
        const xev_install = b.addInstallArtifact(xev_echo, .{});
        examples_step.dependOn(&xev_install.step);

        const xev_conformance = b.addSystemCommand(&.{
            "nu",
            run_autobahn,
            b.getInstallPath(.bin, "xev-echo"),
            "9003",
            "xev-echo",
            "fast",
        });
        xev_conformance.step.dependOn(&xev_install.step);

        const xev_conf_step = b.step(
            "conformance-xev",
            "Run Autobahn against xev echo server",
        );
        xev_conf_step.dependOn(&xev_conformance.step);
    }
}
