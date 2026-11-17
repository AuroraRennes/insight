from collections.abc import Generator
from typing import Any

# List Helpers
# \________________


def flatten_list(nested_list: list[Any]) -> list[Any]:
    return [item for sublist in nested_list for item in sublist]


def window(arr: list[Any], k: int) -> Generator[Any]:
    for i in range(len(arr) - k + 1):
        yield arr[i : i + k]


def mean(list: list[int] | list[float]) -> float:
    if not list:
        return 0
    return sum(list) / len(list)


# Sign extension
# \_____________


def to_signed(value: int, size: int) -> int:
    sign_mask: int = 1 << (size - 1)  # 0b100000...
    mask: int = (1 << size) - 1  # 0b01111111...
    return ((value & mask) ^ sign_mask) - sign_mask


def to_unsigned(value: int, size: int) -> int:
    if value >= 0:
        return value
    mask: int = (1 << size) - 1  # 0b01111111...
    return mask - abs(value) + 1


# Byte/int conversion
# \__________________


def int_to_bytes32(value: int) -> bytes:
    return value.to_bytes(4, "little")


def int_to_bytes64(value: int) -> bytes:
    return value.to_bytes(8, "little")


def bytes_to_int(value: bytes) -> int:
    return int.from_bytes(value, "little")


def string_to_bytes(value: str) -> bytes:
    return bytes.fromhex(value)


def string_to_int(value: str) -> int:
    return int(value, 16)


def reverse_endianness32(value: bytes) -> bytes:
    return int_to_bytes32(int.from_bytes(value, "big"))


def reverse_endianness64(value: bytes) -> bytes:
    return int_to_bytes64(int.from_bytes(value, "big"))


# Format
# \_____


def format_to(value: int, size: int) -> int:
    return abs(value) & ((1 << size) - 1)


def format_to_aligned(value: int, size: int) -> int:
    return abs(value) & ((1 << size) - 2)


def align(value: int, alignment: int) -> int:
    return (value // alignment) * alignment
