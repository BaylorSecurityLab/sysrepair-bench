#!/usr/bin/env python3
"""Simulated S7comm PLC server — listens on 0.0.0.0:102 with no authentication.
Accepts TCP connections and responds with a minimal S7 COTP/S7 handshake byte
sequence so that basic connectivity checks pass.
"""
import socket
import threading
import time

HOST = "0.0.0.0"
PORT = 102

# Minimal COTP Connection Confirm response (enough to satisfy nc -z)
COTP_CC = bytes([
    0x03, 0x00, 0x00, 0x16,  # TPKT header
    0x11, 0xd0, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc0, 0x01, 0x0a, 0xc1, 0x02, 0x01, 0x00, 0xc2, 0x02, 0x01, 0x02,
])


def handle(conn, addr):
    try:
        conn.recv(1024)          # consume client COTP CR
        conn.sendall(COTP_CC)
        conn.recv(1024)          # consume S7 setup comm
        time.sleep(0.1)
    except Exception:
        pass
    finally:
        conn.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(10)
    print(f"S7comm simulator listening on {HOST}:{PORT}", flush=True)
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
