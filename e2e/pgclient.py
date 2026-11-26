"""A very small Postgres wire client (stdlib only) for driving a local twin.

It speaks just enough of protocol 3.0: startup without authentication, simple
queries, and one parameterized INSERT through the extended protocol, so values
travel as bound parameters and are never spliced into SQL text. Any
ErrorResponse raises, so a rejected write cannot pass silently.
"""

from __future__ import annotations

import socket
import struct

TEXT_OID = 25


class PgError(RuntimeError):
    pass


class Connection:
    def __init__(self, host: str, port: int, timeout: float = 15.0) -> None:
        self.sock = socket.create_connection((host, port), timeout=timeout)
        try:
            body = struct.pack("!I", 196608) + b"user\x00postgres\x00database\x00postgres\x00\x00"
            self.sock.sendall(struct.pack("!I", len(body) + 4) + body)
            self._until_ready()
        except BaseException:
            self.sock.close()
            raise

    def _read_exact(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise PgError("connection closed inside a backend message")
            data += chunk
        return data

    def _until_ready(self) -> list[tuple[bytes, bytes]]:
        frames = []
        while True:
            tag = self._read_exact(1)
            length = struct.unpack("!I", self._read_exact(4))[0]
            frames.append((tag, self._read_exact(length - 4)))
            if tag == b"Z":
                errors = [body for kind, body in frames if kind == b"E"]
                if errors:
                    raise PgError(errors[0].replace(b"\x00", b" ").decode("utf-8", "replace"))
                return frames

    def _send(self, tag: bytes, body: bytes = b"") -> None:
        self.sock.sendall(tag + struct.pack("!I", len(body) + 4) + body)

    def query(self, sql: str) -> list[tuple[bytes, bytes]]:
        self._send(b"Q", sql.encode() + b"\x00")
        return self._until_ready()

    def insert(self, table: str, columns: list[str], values: list[str | None]) -> None:
        placeholders = ", ".join(f"${index}" for index in range(1, len(values) + 1))
        sql = f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})"
        self._send(b"P", b"\x00" + sql.encode() + b"\x00" + struct.pack("!h", len(values))
                   + struct.pack("!I", TEXT_OID) * len(values))
        bind = b"\x00\x00" + struct.pack("!h", 0) + struct.pack("!h", len(values))
        for value in values:
            if value is None:
                bind += struct.pack("!i", -1)
            else:
                encoded = value.encode("utf-8")
                bind += struct.pack("!i", len(encoded)) + encoded
        self._send(b"B", bind + struct.pack("!h", 0))
        self._send(b"E", b"\x00" + struct.pack("!i", 0))
        self._send(b"S")
        tags = [tag for tag, _ in self._until_ready()]
        if b"C" not in tags:
            raise PgError(f"INSERT did not complete: {tags}")

    def close(self) -> None:
        try:
            self._send(b"X")
        finally:
            self.sock.close()
