import socket
import struct

from django.conf import settings


class ScanUnavailable(Exception):
    pass


def scan(path):
    if settings.SCAN_MODE == "skip-development" and not settings.PRODUCTION:
        return "development-skip"
    try:
        with socket.create_connection(
            (settings.CLAMAV_HOST, settings.CLAMAV_PORT), timeout=10
        ) as connection:
            connection.settimeout(30)
            connection.sendall(b"zINSTREAM\0")
            with path.open("rb") as stream:
                while chunk := stream.read(65536):
                    connection.sendall(struct.pack("!I", len(chunk)) + chunk)
            connection.sendall(struct.pack("!I", 0))
            reply = bytearray()
            while len(reply) < 4096:
                part = connection.recv(1024)
                if not part:
                    break
                reply.extend(part)
                if b"\0" in part:
                    break
            if bytes(reply).strip(b"\0\r\n ") == b"stream: OK":
                return "clean"
            if b" FOUND" in reply:
                return "infected"
            raise ScanUnavailable("Scanner could not complete the check.")
    except (OSError, TimeoutError) as exc:
        raise ScanUnavailable("Scanner unavailable; file remains quarantined.") from exc
