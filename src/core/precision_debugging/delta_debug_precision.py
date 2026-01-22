"""Delta debugging helper for precision bottleneck isolation."""

from __future__ import annotations

from typing import Callable, Iterable, List, Set, TypeVar

T = TypeVar("T")


class DeltaDebugger:
    """Generic delta-debugging for minimal failure-inducing sets."""

    def __init__(self, items: Iterable[T], predicate: Callable[[Set[T]], bool]) -> None:
        self.items = set(items)
        self.predicate = predicate

    def find_minimal_set(self) -> Set[T]:
        current = set(self.items)
        reduced = True
        while reduced:
            reduced = False
            for item in list(current):
                candidate = current - {item}
                if self.predicate(candidate):
                    current = candidate
                    reduced = True
                    break
        return current
