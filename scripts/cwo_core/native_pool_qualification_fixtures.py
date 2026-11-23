"""Fixed synthetic tasks shared by offline preparation and pool qualification."""

from types import MappingProxyType
from typing import Any


POOL_QUALIFICATION_COHORT_SIZES = (2, 3)
POOL_QUALIFICATION_SEED = MappingProxyType({"README.txt": "Synthetic CWO pool qualification fixture.\n"})


def _worker_task(size: int, slot: int) -> dict[str, str]:
    path = f"result-n{size}-worker-{slot}.txt"
    marker = f"CWO_POOL_N{size}_WORKER_{slot}_DONE"
    contents = f"CWO pool qualification for N={size}, worker {slot}\n"
    return {
        "worker_slot": f"worker-{slot}",
        "write_path": path,
        "expected_utf8": contents,
        "completion_marker": marker,
        "prompt": (
            f"In your assigned disposable clone, create only {path}. "
            f"Write this single UTF-8 line, including its final newline.\n{contents}"
            "Leave the seed file and Git state untouched. Use only the registered local "
            f"write operation. After the write, return this exact marker.\n{marker}"
        ),
    }


def fixed_pool_qualification_cohorts() -> list[dict[str, Any]]:
    """Return fresh copies of the synthetic N=2 and N=3 task definitions."""
    return [{"size": size, "tasks": [_worker_task(size, slot) for slot in range(1, size + 1)]}
            for size in POOL_QUALIFICATION_COHORT_SIZES]
