"""Flip tests over a corpus of forms, in parallel, with a summary per form."""

from __future__ import annotations

import re
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from insight.flips.check import Report, flip_test

if TYPE_CHECKING:
    from collections.abc import Iterator


@dataclass
class Summary:
    reports: list[Report] = field(default_factory=list)

    @property
    def failed(self) -> list[Report]:
        return [r for r in self.reports if r.failures]

    @property
    def skipped(self) -> list[Report]:
        return [r for r in self.reports if r.skipped]

    @property
    def passed(self) -> list[Report]:
        return [r for r in self.reports if r.ok]

    def forms(self, reports: list[Report]) -> set[str]:
        return {r.form for r in reports}


def select(corpus: dict[str, list[str]], pattern: str | None, instances: int) -> list[str]:
    regex = re.compile(pattern) if pattern else None
    return [
        encoding
        for form, encodings in corpus.items()
        if regex is None or regex.search(form)
        for encoding in encodings[:instances]
    ]


def one(encoding: str) -> Report:
    return flip_test(bytes.fromhex(encoding))


def run_corpus(encodings: list[str], jobs: int) -> Iterator[Report]:
    if jobs <= 1:
        yield from map(one, encodings)
        return
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        yield from pool.map(one, encodings, chunksize=1)
