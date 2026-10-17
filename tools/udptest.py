"""SOCKS5 UDP ASSOCIATE smoke test: DNS queries through the relay.

usage: python udptest.py <socks_host> <socks_port> [name ...]
"""
import socket, struct, sys, time, random

host, port = sys.argv[1], int(sys.argv[2])
names = sys.argv[3:] or ["example.com", "www.cloudflare.com", "ipv6.google.com"]
servers = [("8.8.8.8", 53), ("1.1.1.1", 53), ("9.9.9.9", 53)]

ctl = socket.create_connection((host, port), timeout=10)
ctl.sendall(b"\x05\x01\x00")
assert ctl.recv(2) == b"\x05\x00", "greeting"
ctl.sendall(b"\x05\x03\x00\x01" + bytes(4) + b"\x00\x00")
rep = ctl.recv(64)
assert rep[:2] == b"\x05\x00", f"associate reply {rep!r}"
assert rep[3] == 1
relay = (socket.inet_ntoa(rep[4:8]), struct.unpack("!H", rep[8:10])[0])
relay = (host if relay[0] == "0.0.0.0" else relay[0], relay[1])
print("relay at", relay)

u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.settimeout(8)


def dns_query(name, qtype=1):
    qid = random.randrange(65536)
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + struct.pack("!HH", qtype, 1)
    return qid, q


def socks_udp(dst, payload):
    return b"\x00\x00\x00\x01" + socket.inet_aton(dst[0]) + struct.pack("!H", dst[1]) + payload


ok = 0
for i, name in enumerate(names):
    srv = servers[i % len(servers)]
    qid, q = dns_query(name)
    t0 = time.time()
    u.sendto(socks_udp(srv, q), relay)
    try:
        data, frm = u.recvfrom(4096)
    except socket.timeout:
        print(f"{name:24s} via {srv[0]:10s} TIMEOUT")
        continue
    dt = time.time() - t0
    assert data[:3] == b"\x00\x00\x00"
    atyp = data[3]
    if atyp == 1:
        src = (socket.inet_ntoa(data[4:8]), struct.unpack("!H", data[8:10])[0])
        body = data[10:]
    else:
        raise SystemExit(f"unexpected atyp {atyp}")
    rid, flags, qd, an = struct.unpack("!HHHH", body[:8])
    status = "ok" if rid == qid and flags & 0x8000 else "BAD"
    if rid == qid:
        ok += 1
    print(f"{name:24s} via {srv[0]:10s} -> from {src[0]}:{src[1]} id={'match' if rid==qid else 'MISMATCH'} answers={an} {len(body)}B {dt*1000:.0f}ms {status}")

# Large payload: EDNS query with a fat OPT record padding (~1200 B) to 8.8.8.8.
qid, q = dns_query("example.com", 16)
q = q[:4] + struct.pack("!HHHH", 1, 0, 0, 1) + q[12:]
q += b"\x00" + struct.pack("!HHIH", 41, 4096, 0, 4 + 1200) + struct.pack("!HH", 12, 1200) + bytes(1200)
for srv in servers:
    u.sendto(socks_udp(srv, q), relay)
    try:
        data, _ = u.recvfrom(4096)
        print(f"edns-padded query {len(q)}B via {srv[0]} -> reply {len(data)-10}B ok")
        ok += 1
        break
    except socket.timeout:
        print(f"edns-padded query {len(q)}B via {srv[0]} TIMEOUT")
qid, q = dns_query("example.org")
u.sendto(socks_udp(servers[1], q), relay)
try:
    data, _ = u.recvfrom(4096)
    print("small query after big one: ok", len(data))
except socket.timeout:
    print("small query after big one: TIMEOUT (association broken)")

ctl.close()
print(f"{ok}/{len(names)+1} ok")
