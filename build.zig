const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseFast,
    });

    // 1. Standalone DataPlane Executable
    const exe = b.addExecutable(.{
        .name = "backpack-dataplane",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(exe);

    // 2. Shared Library (.so / .dll) for Go CGO integration
    const lib = b.addSharedLibrary(.{
        .name = "backpack_core",
        .root_source_file = b.path("src/c_api.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(lib);

    // 3. Static Library (.a / .lib)
    const static_lib = b.addStaticLibrary(.{
        .name = "backpack_core_static",
        .root_source_file = b.path("src/c_api.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(static_lib);

    // 4. Test Suite
    const main_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_main_tests = b.addRunArtifact(main_tests);

    const test_step = b.step("test", "Run library unit tests");
    test_step.dependOn(&run_main_tests.step);
}
