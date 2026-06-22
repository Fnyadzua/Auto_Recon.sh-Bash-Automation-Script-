#!/usr/bin/env python3

import socket
import sys


def get_target():
    """
    Get target from command-line argument or stdin.
    """
    if len(sys.argv) > 1:
        return sys.argv[1]
    else:
        return sys.stdin.read().strip()


def resolve_target(target):
    """
    Resolve domain to IP.
    """
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print("Invalid host")
        sys.exit(1)


def scan_ports(ip, start=1, end=1024):
    """
    Scan ports and print open ones.
    """
    open_ports = []

    for port in range(start, end + 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((ip, port))

            if result == 0:
                print(f"Port {port} open")
                open_ports.append(port)

            s.close()

        except socket.error:
            continue

    return open_ports


def main():
    target = get_target()
    ip = resolve_target(target)

    open_ports = scan_ports(ip)

    print(f"{len(open_ports)} open ports")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Error occurred")
