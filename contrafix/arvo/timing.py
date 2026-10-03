"""Wall-clock timing instrumentation for the ARVO pipeline.

The pipeline is measured as a flat list of timing events.  Each event is
tagged with a ``kind``:

``"stage"``
    Top-level, mutually exclusive spans (setup, mutate, analyze, patch,
    select, finalize).  These do not overlap, so their durations sum to
    approximately the pipeline wall time.

``"detail"``
    Spans nested inside a stage (the LLM call within ``mutate``, the build
    and repro gates within ``patch``) or spans that run concurrently with
    each other (the parallel Patchers).  They are reported separately and
    are never summed into the total, since doing so would double-count.

Usage::

    timer = StageTimer()
    with track(timer, "analyze", round_num=0):
        ...
    result["timing"] = timer.summary()
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from contextlib import contextmanager

logger = logging.getLogger(__name__)

# Durations are stored raw — the full float returned by time.perf_counter()
# differencing, with no rounding.  Rounding is a lossy, one-way operation:
# the original value cannot be recovered from a saved result file, so any
# rounding decision made here is permanent.  Round at presentation time
# instead (see arvo.timing_report).


class StageTimer:
    """Collects wall-clock timings for pipeline stages.

    All events are recorded from a single asyncio event loop, so appending
    to ``self.events`` needs no locking.
    """

    def __init__(self) -> None:
        self._t0 = time.perf_counter()
        self.started_at = time.time()  # epoch, for correlating with logs
        self.events: list[dict] = []

    @contextmanager
    def track(
        self,
        stage: str,
        *,
        kind: str = "stage",
        round_num: int | None = None,
        attempt: int | None = None,
        agent: str | None = None,
        **extra,
    ):
        """Time the wrapped block and record it as one event.

        The event is recorded even when the block raises, with the
        exception type stored under ``"error"``.
        """
        start = time.perf_counter()
        rec = {
            "stage": stage,
            "kind": kind,
            "round": round_num,
            "attempt": attempt,
            "agent": agent,
            "start": start - self._t0,
            **extra,
        }
        error = ""
        try:
            yield rec
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            error = type(exc).__name__
            raise
        finally:
            end = time.perf_counter()
            rec["end"] = end - self._t0
            rec["duration"] = end - start
            if error:
                rec["error"] = error
            self.events.append(rec)
            logger.info(
                "[timing] %s%s%s: %.1fs%s",
                stage,
                f" round={round_num}" if round_num is not None else "",
                f" ({agent})" if agent else "",
                rec["duration"],
                f" [{error}]" if error else "",
            )

    def summary(self) -> dict:
        """Aggregate the recorded events into a JSON-serialisable dict."""
        totals: dict[str, dict] = {}
        per_round: dict[str, dict[str, float]] = defaultdict(dict)

        for e in self.events:
            bucket = totals.setdefault(
                e["stage"], {"kind": e["kind"], "total": 0.0, "count": 0}
            )
            bucket["total"] += e["duration"]
            bucket["count"] += 1
            if e["round"] is not None:
                rnd = per_round[f"round_{e['round']}"]
                rnd[e["stage"]] = rnd.get(e["stage"], 0.0) + e["duration"]

        stage_totals = {
            k: v["total"] for k, v in totals.items() if v["kind"] == "stage"
        }
        detail_totals = {
            k: v["total"] for k, v in totals.items() if v["kind"] == "detail"
        }

        return {
            "started_at": self.started_at,
            "total_wall_seconds": time.perf_counter() - self._t0,
            # Non-overlapping spans: safe to sum.
            "stage_wall_seconds": stage_totals,
            "stage_counts": {k: v["count"] for k, v in totals.items() if v["kind"] == "stage"},
            # Nested / concurrent spans: reported, never summed into the total.
            "detail_seconds": detail_totals,
            "detail_counts": {k: v["count"] for k, v in totals.items() if v["kind"] == "detail"},
            "per_round": {k: dict(v) for k, v in per_round.items()},
            "events": list(self.events),
        }


@contextmanager
def _noop():
    yield {}


def track(timer: StageTimer | None, stage: str, **kwargs):
    """Time a block, or do nothing when *timer* is ``None``.

    Lets the pipeline helpers accept an optional timer without every call
    site having to guard for it.
    """
    if timer is None:
        return _noop()
    return timer.track(stage, **kwargs)


# ---------------------------------------------------------------------------
# Process-global "current" timer
# ---------------------------------------------------------------------------
#
# Agent tools (arvo.tools) run builds and PoC executions of their own —
# ``check_vul`` rebuilds and re-runs the PoC, ``run_probed`` builds, ``bash``
# may invoke the build command directly.  That work happens deep inside an
# agent's tool loop, far from any function that could be handed a timer, so
# those costs would otherwise be invisible inside the enclosing ``*.agent``
# span.  A module-level current timer lets the tools record them.
#
# This is safe because ``arvo.main`` solves instances strictly sequentially
# (``for instance in instances: await solve_instance(...)``), so at most one
# StageTimer is live at a time.  Should instances ever be solved
# concurrently in one process, replace this with a ContextVar.

_current: StageTimer | None = None


def set_current(timer: StageTimer | None) -> None:
    """Install (or clear, with ``None``) the process-wide current timer."""
    global _current
    _current = timer


def get_current() -> StageTimer | None:
    return _current


def track_current(stage: str, **kwargs):
    """Time a block against the current timer, or no-op if none is set."""
    return track(_current, stage, **kwargs)
