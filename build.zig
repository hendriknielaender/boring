const std = @import("std");

const Build = std.Build;
const LazyPath = Build.LazyPath;
const Module = Build.Module;
const OptimizeMode = std.builtin.OptimizeMode;
const ResolvedTarget = Build.ResolvedTarget;

const boring_ssl_revision = "7a6e828dc53ba9a56bd49915f2a0780d63af97d2";
const git_revision_length = 40;

const BuildOptions = struct {
    source_path: ?[]const u8,
    include_path: ?[]const u8,
    lib_path: ?[]const u8,
    cmake_build_type: []const u8,
    fips: bool,
    mlkem_patch: bool,
    rpk_patch: bool,
    underscore_wildcards_patch: bool,

    fn init(b: *Build, optimize: OptimizeMode) BuildOptions {
        const source_path = b.option(
            []const u8,
            "boringssl-source-path",
            "Path to a BoringSSL source checkout.",
        );
        const include_path = b.option(
            []const u8,
            "boringssl-include-path",
            "Path to BoringSSL headers. Defaults to <source>/include.",
        );
        const lib_path = b.option(
            []const u8,
            "boringssl-lib-path",
            "Path to a BoringSSL CMake build root.",
        );
        const cmake_build_type = b.option(
            []const u8,
            "boringssl-cmake-build-type",
            "CMake build type for BoringSSL.",
        ) orelse default_cmake_build_type(optimize);
        const fips = b.option(
            bool,
            "boringssl-fips",
            "Build BoringSSL with the FIPS CMake flag.",
        ) orelse false;
        const mlkem_patch = b.option(
            bool,
            "boringssl-mlkem-patch",
            "Enable wrappers that require a BoringSSL source with mlkem.h.",
        ) orelse false;
        const rpk_patch = b.option(
            bool,
            "boringssl-rpk-patch",
            "Enable wrappers that require raw public key TLS credentials.",
        ) orelse false;
        const underscore_wildcards_patch = b.option(
            bool,
            "boringssl-underscore-wildcards-patch",
            "Enable wrappers that require underscore wildcard host matching.",
        ) orelse false;

        return .{
            .source_path = source_path,
            .include_path = include_path,
            .lib_path = lib_path,
            .cmake_build_type = cmake_build_type,
            .fips = fips,
            .mlkem_patch = mlkem_patch,
            .rpk_patch = rpk_patch,
            .underscore_wildcards_patch = underscore_wildcards_patch,
        };
    }

    fn any_patch(self: BuildOptions) bool {
        if (self.mlkem_patch) return true;
        if (self.rpk_patch) return true;
        if (self.underscore_wildcards_patch) return true;

        return false;
    }
};

const Libraries = struct {
    ssl: LazyPath,
    crypto: LazyPath,
};

pub fn build(b: *Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const options = BuildOptions.init(b, optimize);

    verify_default_boringssl_revision(b, options);
    validate_patch_options(options);
    validate_patch_headers(b, options);

    if (options.fips and
        options.lib_path == null and
        target.result.os.tag != .linux)
    {
        std.process.fatal(
            "-Dboringssl-fips=true is supported only for Linux source builds; " ++
                "use -Dboringssl-lib-path for prebuilt FIPS libraries.",
            .{},
        );
    }

    const source_dir = option_path(options.source_path) orelse b.path("deps/boringssl");
    const include_dir = resolve_include_path(b, source_dir, options.include_path);
    const libraries = resolve_libraries(b, source_dir, options);
    const boringssl_module = add_boringssl_module(
        b,
        target,
        optimize,
        include_dir,
        options,
    );
    link_boringssl(boringssl_module, target, include_dir, libraries);

    const build_options = add_build_options(b, options);
    const fixed_bytes_module = add_fixed_bytes_module(b, target, optimize);
    const mlkem_module = add_mlkem_module(
        b,
        target,
        optimize,
        boringssl_module,
        fixed_bytes_module,
        options,
    );

    const boring_module = b.addModule("boring", .{
        .root_source_file = b.path("src/boring.zig"),
        .target = target,
        .optimize = optimize,
    });
    boring_module.addOptions("build_options", build_options);
    boring_module.addImport("boringssl", boringssl_module);
    boring_module.addImport("fixed_bytes", fixed_bytes_module);
    boring_module.addImport("mlkem_impl", mlkem_module);

    add_tests(
        b,
        target,
        optimize,
        boringssl_module,
        boring_module,
        fixed_bytes_module,
        options.fips,
    );
    add_format_steps(b);
}

fn add_boringssl_module(
    b: *Build,
    target: ResolvedTarget,
    optimize: OptimizeMode,
    include_dir: LazyPath,
    options: BuildOptions,
) *Module {
    const translate = b.addTranslateC(.{
        .root_source_file = b.path("include/boringssl.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    translate.addIncludePath(b.path("include"));
    translate.addIncludePath(include_dir);
    if (options.mlkem_patch) {
        translate.defineCMacro("BORINGSSL_ZIG_PATCH_MLKEM", "1");
    }

    return translate.addModule("boringssl");
}

fn add_build_options(b: *Build, options: BuildOptions) *Build.Step.Options {
    const build_options = b.addOptions();
    build_options.addOption(bool, "boringssl_mlkem_patch", options.mlkem_patch);
    build_options.addOption(bool, "boringssl_rpk_patch", options.rpk_patch);
    build_options.addOption(
        bool,
        "boringssl_underscore_wildcards_patch",
        options.underscore_wildcards_patch,
    );

    return build_options;
}

fn add_fixed_bytes_module(
    b: *Build,
    target: ResolvedTarget,
    optimize: OptimizeMode,
) *Module {
    return b.createModule(.{
        .root_source_file = b.path("src/fixed_bytes.zig"),
        .target = target,
        .optimize = optimize,
    });
}

fn add_mlkem_module(
    b: *Build,
    target: ResolvedTarget,
    optimize: OptimizeMode,
    boringssl_module: *Module,
    fixed_bytes_module: *Module,
    options: BuildOptions,
) *Module {
    const root_source_file = if (options.mlkem_patch)
        b.path("src/mlkem_patched.zig")
    else
        b.path("src/mlkem.zig");
    const module = b.createModule(.{
        .root_source_file = root_source_file,
        .target = target,
        .optimize = optimize,
    });
    module.addImport("boringssl", boringssl_module);
    module.addImport("fixed_bytes", fixed_bytes_module);

    return module;
}

fn link_boringssl(
    module: *Module,
    target: ResolvedTarget,
    include_dir: LazyPath,
    libraries: Libraries,
) void {
    module.addIncludePath(include_dir);
    module.addObjectFile(libraries.ssl);
    module.addObjectFile(libraries.crypto);
    module.link_libc = true;
    module.link_libcpp = true;

    if (target.result.os.tag == .windows) {
        module.linkSystemLibrary("advapi32", .{});
    }
}

fn resolve_include_path(
    b: *Build,
    source_dir: LazyPath,
    include_path: ?[]const u8,
) LazyPath {
    if (option_path(include_path)) |path| {
        return path;
    }

    return source_dir.path(b, "include");
}

fn resolve_libraries(
    b: *Build,
    source_dir: LazyPath,
    options: BuildOptions,
) Libraries {
    if (option_path(options.lib_path)) |lib_dir| {
        return .{
            .ssl = lib_dir.path(b, "ssl/libssl.a"),
            .crypto = lib_dir.path(b, "crypto/libcrypto.a"),
        };
    }

    const build_dir = add_boringssl_build(
        b,
        source_dir,
        options.cmake_build_type,
        options.fips,
    );

    return .{
        .ssl = build_dir.path(b, "ssl/libssl.a"),
        .crypto = build_dir.path(b, "crypto/libcrypto.a"),
    };
}

fn add_boringssl_build(
    b: *Build,
    source_dir: LazyPath,
    cmake_build_type: []const u8,
    fips: bool,
) LazyPath {
    const run = b.addSystemCommand(&.{"sh"});
    run.setName("build boringssl");
    run.addFileArg(b.path("tools/build-boringssl.sh"));
    run.addDirectoryArg(source_dir);
    const build_dir = run.addOutputDirectoryArg("boringssl-build");
    run.addArg(cmake_build_type);
    run.addArg(if (fips) "true" else "false");

    return build_dir;
}

fn add_tests(
    b: *Build,
    target: ResolvedTarget,
    optimize: OptimizeMode,
    boringssl_module: *Module,
    boring_module: *Module,
    fixed_bytes_module: *Module,
    fips: bool,
) void {
    const use_lld: ?bool = if (fips and target.result.os.tag == .linux) true else null;
    const fixed_bytes_tests = b.addTest(.{ .root_module = fixed_bytes_module });

    const sys_test_module = b.createModule(.{
        .root_source_file = b.path("test/boringssl.zig"),
        .target = target,
        .optimize = optimize,
    });
    sys_test_module.addImport("boringssl", boringssl_module);

    const boring_test_module = b.createModule(.{
        .root_source_file = b.path("test/boring.zig"),
        .target = target,
        .optimize = optimize,
    });
    boring_test_module.addImport("boring", boring_module);

    const sys_tests = b.addTest(.{
        .root_module = sys_test_module,
        .use_lld = use_lld,
    });
    const boring_tests = b.addTest(.{
        .root_module = boring_test_module,
        .use_lld = use_lld,
    });
    const run_fixed_bytes_tests = b.addRunArtifact(fixed_bytes_tests);
    const run_sys_tests = b.addRunArtifact(sys_tests);
    const run_boring_tests = b.addRunArtifact(boring_tests);

    const check_step = b.step("check", "Compile BoringSSL binding smoke tests");
    check_step.dependOn(&fixed_bytes_tests.step);
    check_step.dependOn(&sys_tests.step);
    check_step.dependOn(&boring_tests.step);
    b.default_step.dependOn(check_step);

    const test_step = b.step("test", "Run BoringSSL binding smoke tests");
    test_step.dependOn(&run_fixed_bytes_tests.step);
    test_step.dependOn(&run_sys_tests.step);
    test_step.dependOn(&run_boring_tests.step);
}

fn add_format_steps(b: *Build) void {
    const paths = &[_][]const u8{
        "build.zig",
        "http2-boring/build.zig",
        "http2-boring/src",
        "http2-boring/test",
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

fn option_path(path: ?[]const u8) ?LazyPath {
    if (path) |value| {
        return .{ .cwd_relative = value };
    }

    return null;
}

fn default_cmake_build_type(optimize: OptimizeMode) []const u8 {
    return switch (optimize) {
        .Debug => "Debug",
        .ReleaseSafe => "Release",
        .ReleaseFast => "Release",
        .ReleaseSmall => "Release",
    };
}

fn verify_default_boringssl_revision(b: *Build, options: BuildOptions) void {
    if (options.source_path != null) return;

    if (options.lib_path != null) {
        if (options.include_path != null) return;
    }

    const revision = read_default_boringssl_revision(b) catch |err| {
        std.process.fatal(
            "deps/boringssl must be initialized at {s}: {s}",
            .{ boring_ssl_revision, @errorName(err) },
        );
    };

    if (std.mem.eql(u8, revision, boring_ssl_revision)) return;

    std.process.fatal(
        "deps/boringssl is at {s}, expected {s}; run " ++
            "`git submodule update --init --recursive`.",
        .{ revision, boring_ssl_revision },
    );
}

fn validate_patch_options(options: BuildOptions) void {
    if (!options.any_patch()) return;
    if (options.source_path != null) return;

    if (options.lib_path != null) {
        if (options.include_path != null) return;
    }

    std.process.fatal(
        "patch feature options require -Dboringssl-source-path, or both " ++
            "-Dboringssl-include-path and -Dboringssl-lib-path.",
        .{},
    );
}

fn validate_patch_headers(b: *Build, options: BuildOptions) void {
    if (!options.any_patch()) return;

    const include_path = patch_include_path(b, options) orelse return;
    inline for (patch_header_requirements) |requirement| {
        if (requirement.enabled(options)) {
            requirement.validate(b, include_path);
        }
    }
}

const PatchHeaderRequirement = struct {
    option_name: []const u8,
    header: []const u8,
    symbol: ?[]const u8,
    enabled: *const fn (BuildOptions) bool,

    fn validate(
        requirement: PatchHeaderRequirement,
        b: *Build,
        include_path: []const u8,
    ) void {
        if (requirement.symbol) |symbol| {
            validate_header_contains(
                b,
                include_path,
                requirement.header,
                symbol,
                requirement.option_name,
            );
        } else {
            validate_header_exists(b, include_path, requirement.header);
        }
    }
};

const patch_header_requirements = [_]PatchHeaderRequirement{
    .{
        .option_name = "-Dboringssl-mlkem-patch=true",
        .header = "openssl/mlkem.h",
        .symbol = null,
        .enabled = patch_enabled_mlkem,
    },
    .{
        .option_name = "-Dboringssl-rpk-patch=true",
        .header = "openssl/ssl.h",
        .symbol = "SSL_CREDENTIAL_new_raw_public_key",
        .enabled = patch_enabled_rpk,
    },
    .{
        .option_name = "-Dboringssl-rpk-patch=true",
        .header = "openssl/ssl.h",
        .symbol = "SSL_CREDENTIAL_set1_spki",
        .enabled = patch_enabled_rpk,
    },
    .{
        .option_name = "-Dboringssl-underscore-wildcards-patch=true",
        .header = "openssl/x509.h",
        .symbol = "X509_CHECK_FLAG_UNDERSCORE_WILDCARDS",
        .enabled = patch_enabled_underscore_wildcards,
    },
};

fn patch_enabled_mlkem(options: BuildOptions) bool {
    return options.mlkem_patch;
}

fn patch_enabled_rpk(options: BuildOptions) bool {
    return options.rpk_patch;
}

fn patch_enabled_underscore_wildcards(options: BuildOptions) bool {
    return options.underscore_wildcards_patch;
}

fn patch_include_path(b: *Build, options: BuildOptions) ?[]const u8 {
    if (options.include_path) |include_path| return include_path;
    if (options.source_path) |source_path| return b.pathJoin(&.{ source_path, "include" });

    return null;
}

fn validate_header_exists(b: *Build, include_path: []const u8, header: []const u8) void {
    const path = b.pathJoin(&.{ include_path, header });
    _ = read_file_alloc(b, path, 1) catch |err| {
        std.process.fatal(
            "patch feature requires {s}: {s}",
            .{ path, @errorName(err) },
        );
    };
}

fn validate_header_contains(
    b: *Build,
    include_path: []const u8,
    header: []const u8,
    symbol: []const u8,
    option_name: []const u8,
) void {
    const path = b.pathJoin(&.{ include_path, header });
    const contents = read_file_alloc(b, path, 2 * 1024 * 1024) catch |err| {
        std.process.fatal(
            "{s} requires {s}: {s}",
            .{ option_name, path, @errorName(err) },
        );
    };
    if (std.mem.indexOf(u8, contents, symbol) != null) return;

    std.process.fatal("{s} requires {s} to define {s}.", .{ option_name, path, symbol });
}

fn read_default_boringssl_revision(b: *Build) ![]const u8 {
    const git_dir = try read_git_dir(b, "deps/boringssl");
    const head_path = try std.fs.path.join(b.allocator, &.{ git_dir, "HEAD" });
    const head_file = try read_file_alloc(b, head_path, 256);
    const head = std.mem.trim(u8, head_file, &std.ascii.whitespace);

    if (std.mem.startsWith(u8, head, "ref: ")) {
        const ref_name = std.mem.trim(u8, head["ref: ".len..], &std.ascii.whitespace);
        return read_git_ref(b, git_dir, ref_name);
    }

    if (!is_git_revision(head)) return error.InvalidGitHead;
    return head;
}

fn read_git_dir(b: *Build, source_path: []const u8) ![]const u8 {
    const dot_git = try std.fs.path.join(b.allocator, &.{ source_path, ".git" });
    const git_file = read_file_alloc(b, dot_git, 4096) catch |err| {
        switch (err) {
            error.IsDir => return dot_git,
            else => return err,
        }
    };
    const git_file_trimmed = std.mem.trim(u8, git_file, &std.ascii.whitespace);

    if (!std.mem.startsWith(u8, git_file_trimmed, "gitdir: ")) {
        return error.InvalidGitFile;
    }

    const git_dir = std.mem.trim(
        u8,
        git_file_trimmed["gitdir: ".len..],
        &std.ascii.whitespace,
    );
    if (std.fs.path.isAbsolute(git_dir)) return git_dir;

    return std.fs.path.join(b.allocator, &.{ source_path, git_dir });
}

fn read_git_ref(b: *Build, git_dir: []const u8, ref_name: []const u8) ![]const u8 {
    if (!std.mem.startsWith(u8, ref_name, "refs/")) return error.InvalidGitRef;

    const ref_path = try std.fs.path.join(b.allocator, &.{ git_dir, ref_name });
    const ref_file = read_file_alloc(b, ref_path, 256) catch |err| {
        switch (err) {
            error.FileNotFound => return read_packed_git_ref(b, git_dir, ref_name),
            else => return err,
        }
    };
    const revision = std.mem.trim(u8, ref_file, &std.ascii.whitespace);

    if (!is_git_revision(revision)) return error.InvalidGitRef;
    return revision;
}

fn read_packed_git_ref(b: *Build, git_dir: []const u8, ref_name: []const u8) ![]const u8 {
    const packed_refs_path = try std.fs.path.join(b.allocator, &.{ git_dir, "packed-refs" });
    const packed_refs = try read_file_alloc(b, packed_refs_path, 1024 * 1024);
    var lines = std.mem.splitScalar(u8, packed_refs, '\n');

    while (lines.next()) |line_raw| {
        const line = std.mem.trim(u8, line_raw, &std.ascii.whitespace);
        if (line.len == 0) continue;
        if (line[0] == '#') continue;
        if (line[0] == '^') continue;
        if (line.len <= git_revision_length) continue;

        const revision = line[0..git_revision_length];
        const name = std.mem.trim(u8, line[git_revision_length..], &std.ascii.whitespace);
        if (!std.mem.eql(u8, name, ref_name)) continue;
        if (!is_git_revision(revision)) return error.InvalidGitRef;
        return revision;
    }

    return error.GitRefNotFound;
}

fn read_file_alloc(b: *Build, path: []const u8, limit: u32) ![]u8 {
    const root = if (std.fs.path.isAbsolute(path)) std.Io.Dir.cwd() else b.build_root.handle;

    return root.readFileAlloc(
        b.graph.io,
        path,
        b.allocator,
        .limited(@intCast(limit)),
    );
}

fn is_git_revision(value: []const u8) bool {
    if (value.len != git_revision_length) return false;

    for (value) |byte| {
        switch (byte) {
            '0'...'9' => {},
            'a'...'f' => {},
            else => return false,
        }
    }

    return true;
}

comptime {
    std.debug.assert(is_git_revision(boring_ssl_revision));
}
