const std = @import("std");
const Io = std.Io;
const builtin = @import("builtin");

pub fn main(init: std.process.Init) !void {
    var buf: [256]u8 = undefined;
    var w: Io.File.Writer = .init(.stdout(), init.io, &buf);
    try w.interface.print("zray 0.1.0 (zig {s}, {s}-{s})\n", .{
        builtin.zig_version_string,
        @tagName(builtin.cpu.arch),
        @tagName(builtin.os.tag),
    });
    try w.interface.flush();
}
