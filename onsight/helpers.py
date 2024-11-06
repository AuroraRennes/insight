from typing import Any, Generator, List, Union

# List Helpers
# \________________


def flatten_list(nested_list: List[Any]) -> List[Any]:
    return [item for sublist in nested_list for item in sublist]


def window(arr: List[Any], k: int) -> Generator:
    for i in range(len(arr) - k + 1):
        yield arr[i : i + k]


def mean(list: Union[List[int], List[float]]):
    if not list:
        return 0
    return sum(list) / len(list)


# Byte/int conversion
# \__________________


def int_to_bytes32(value: int) -> bytes:
    return value.to_bytes(4, "little")


def int_to_bytes64(value: int) -> bytes:
    return value.to_bytes(8, "little")


def bytes_to_int(value: bytes) -> int:
    return int.from_bytes(value, "little")


def reverse_endianness(value: bytes) -> bytes:
    return int_to_bytes64(int.from_bytes(value, "big"))


# Format
# \_____


def format_to(value: int, size: int) -> int:
    return abs(value) & ((1 << size) - 1)


def format_to_aligned(value: int, size: int) -> int:
    return abs(value) & ((1 << size) - 2)


def align(value: int, alignment: int) -> int:
    return (value // alignment) * alignment
