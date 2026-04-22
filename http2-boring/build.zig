const std = @import("std");

const default_http2_root = "../../http2.zig";

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const evented = b.option(
        bool,
        "evented",
        "Enable the experimental std.Io.Evented backend in http2.zig.",
    ) orelse false;
    const http2_root = b.option(
        []const u8,
        "http2-root",
        "Path to an http2.zig checkout.",
    ) orelse default_http2_root;

    const boring_dependency = b.dependency("boring", .{
        .target = target,
        .optimize = optimize,
    });
    const boring_module = boring_dependency.module("boring");
    const http2_module = add_http2_module(b, target, optimize, evented, http2_root);

    const module = b.addModule("http2-boring", .{
        .root_source_file = b.path("src/http2_boring.zig"),
        .target = target,
        .optimize = optimize,
    });
    module.addImport("boring", boring_module);
    module.addImport("http2", http2_module);

    add_tests(b, target, optimize, module);
    add_format_steps(b);
}

fn add_http2_module(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    evented: bool,
    http2_root: []const u8,
) *std.Build.Module {
    const build_options = b.addOptions();
    build_options.addOption(bool, "use_evented_backend", evented);

    const root_source_file = b.pathJoin(&.{ http2_root, "src/http2.zig" });
    const module = b.createModule(.{
        .root_source_file = .{ .cwd_relative = root_source_file },
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    module.addOptions("build_options", build_options);

    return module;
}

fn add_tests(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    module: *std.Build.Module,
) void {
    const test_module = b.createModule(.{
        .root_source_file = b.path("test/http2_boring.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_module.addImport("http2-boring", module);

    const tests = b.addTest(.{ .root_module = test_module });
    const run_tests = b.addRunArtifact(tests);

    const check_step = b.step("check", "Compile http2-boring tests");
    check_step.dependOn(&tests.step);
    b.default_step.dependOn(check_step);

    const test_step = b.step("test", "Run http2-boring tests");
    test_step.dependOn(&run_tests.step);
}

fn add_format_steps(b: *std.Build) void {
    const paths = &[_][]const u8{
        "build.zig",
        "src",
        "test",
    };

    const fmt_check = b.addFmt(.{
        .paths = paths,
        .check = true,
    });
    const fmt_check_step = b.step("fmt-check", "Check Zig formatting");
    fmt_check_step.dependOn(&fmt_check.step);

    const fmt = b.addFmt(.{
        .paths = paths,
        .check = false,
    });
    const fmt_step = b.step("fmt", "Format Zig files");
    fmt_step.dependOn(&fmt.step);
}

comptime {
    std.debug.assert(default_http2_root.len > 0);
}
