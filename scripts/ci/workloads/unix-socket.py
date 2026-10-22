import socket, threading, os
path = "/srv-sock/" + "d" * 50 + "/echo.sock"
os.makedirs(os.path.dirname(path), exist_ok=True)
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.settimeout(30)
srv.bind(path)
assert srv.getsockname() == path, srv.getsockname()
srv.listen(1)
msg = b"elfuse-unix-sock-ok"
def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        assert chunk, "peer closed early"
        buf += chunk
    return buf
def serve():
    conn, _ = srv.accept()
    conn.settimeout(30)
    conn.sendall(recv_exact(conn, len(msg)))
    conn.close()
t = threading.Thread(target=serve)
t.start()
cli = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
cli.settimeout(30)
cli.connect(path)
cli.sendall(msg)
print(recv_exact(cli, len(msg)).decode())
t.join(30)
assert not t.is_alive(), "echo thread hung"
