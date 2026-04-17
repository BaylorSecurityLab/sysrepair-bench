#!/usr/bin/env python3
"""Simulated BACnet/IP server — listens on UDP 0.0.0.0:47808 with no authentication.
Responds to Who-Is broadcasts with an I-Am reply to simulate a real BACnet device.
"""
import socket

HOST = "0.0.0.0"
PORT = 47808  # BAC0 / BACnet/IP standard port

# Minimal BACnet Virtual Link Control (BVLC) + NPDU + APDU I-Am response
BACNET_IAM = bytes([
    0x81, 0x0b,              # BVLC type=Original-Unicast-NPDU
    0x00, 0x19,              # BVLC length
    0x01, 0x20,              # NPDU version + control
    0xff, 0xff,              # DNET broadcast
    0x00,                    # DLEN
    0xff,                    # Hop count
    0x10,                    # APDU unconfirmed service
    0x00,                    # I-Am service choice
    0xc4, 0x02, 0x00, 0x00, 0x00,  # Object identifier (device, 0)
    0x22, 0x05, 0xc4,        # Max APDU length
    0x91, 0x00,              # Segmentation: none
    0x21, 0x08,              # Vendor ID: 8 (ASHRAE)
])


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind((HOST, PORT))
    print(f"BACnet/IP server listening on UDP {HOST}:{PORT}", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        sock.sendto(BACNET_IAM, addr)


if __name__ == "__main__":
    main()
