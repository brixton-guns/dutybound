from __future__ import annotations

import secrets
import time


_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _encode_crockford(value: int, length: int) -> str:
    characters = ["0"] * length
    for index in range(length - 1, -1, -1):
        characters[index] = _CROCKFORD[value & 31]
        value >>= 5
    return "".join(characters)


def new_ulid() -> str:
    timestamp_ms = int(time.time() * 1000)
    if timestamp_ms >= 2**48:
        raise OverflowError("timestamp exceeds ULID capacity")
    randomness = int.from_bytes(secrets.token_bytes(10), "big")
    return _encode_crockford((timestamp_ms << 80) | randomness, 26)

