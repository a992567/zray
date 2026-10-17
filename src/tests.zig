const std = @import("std");

comptime {
    _ = @import("tls/hello.zig");
    _ = @import("tls/key_schedule.zig");
    _ = @import("tls/record.zig");
    _ = @import("tls/handshake.zig");
    _ = @import("tls/signature.zig");
    _ = @import("tls/client.zig");
    _ = @import("tls/reality.zig");
    _ = @import("proxy/vless.zig");
    _ = @import("proxy/vision.zig");
}

test {
    std.testing.refAllDecls(@This());
}
