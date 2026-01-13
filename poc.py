#!/usr/bin/env python3
from pwn import *
from pathlib import Path
import sys

context.log_level = "info"

def usage():
    log.failure(f"Usage: {sys.argv[0]} <host> <port> <packet.bin>")
    sys.exit(1)

def main():
    if len(sys.argv) != 4:
        usage()

    host = sys.argv[1]
    port = int(sys.argv[2])
    packet_path = Path(sys.argv[3])

    if not packet_path.is_file():
        log.failure(f"Packet not found: {packet_path}")
        sys.exit(1)

    data = packet_path.read_bytes()

    log.info(f"Connecting to {host}:{port}")
    io = remote(host, port)

    log.info(f"Sending {packet_path.name} ({len(data)} bytes)")
    io.send(data)

    log.success("Packet sent")
    io.close()

if __name__ == "__main__":
    main()
