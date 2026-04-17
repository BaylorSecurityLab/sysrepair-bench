#!/usr/bin/env python3
"""Simulated IPMI BMC — listens on UDP 0.0.0.0:623.
Responds with a minimal IPMI Get Channel Authentication Capabilities reply
to simulate a vulnerable BMC that advertises cipher-zero support.
"""
import socket

HOST = "0.0.0.0"
PORT = 623

# Minimal IPMI RMCP response acknowledging the session
RMCP_ACK = bytes([
    0x06, 0x00, 0xff, 0x07,  # RMCP header (version, reserved, seq, class=IPMI)
    0x00,                    # IPMI session auth type = none (cipher 0)
    0x00, 0x00, 0x00, 0x00,  # session ID
    0x00, 0x00, 0x00, 0x00,  # session seq
    0x00,                    # message length placeholder
])


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    print(f"IPMI simulator listening on UDP {HOST}:{PORT}", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        sock.sendto(RMCP_ACK, addr)


if __name__ == "__main__":
    main()
