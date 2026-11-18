"""The hard request counter and pacer every check sends through.

Every SIP request message and every TLS probe connection goes through
:meth:`Budget.spend` *before* the bytes leave. A check that tries to exceed
its declared bound (or the run's ``max_requests``) gets
:class:`BudgetExceeded` instead of a packet; the runner reports that as an
internal error and stops. Nothing is ever retried.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable


class BudgetExceeded(RuntimeError):
    """A check tried to send more than it declared; nothing was sent."""


class Stopped(RuntimeError):
    """The run was cancelled or authorization lapsed; nothing was sent."""


@dataclass
class Budget:
    total_limit: int
    interval: float = 1.0
    monotonic: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
    should_stop: Callable[[], str | None] = lambda: None
    total: int = 0
    check_id: str | None = None
    check_limit: int = 0
    check_sent: int = 0
    _last_paced: float | None = None
    log: list[dict[str, object]] = field(default_factory=list)

    def begin(self, check_id: str, limit: int) -> None:
        self.check_id = check_id
        self.check_limit = limit
        self.check_sent = 0

    def end(self) -> int:
        sent = self.check_sent
        self.check_id = None
        self.check_limit = 0
        self.check_sent = 0
        return sent

    def spend(self, what: str, *, paced: bool = True) -> None:
        """Account for one request about to be sent; pace new transactions.

        ``paced`` is False only for the ACK, CANCEL, or BYE that correctly
        ends an INVITE already sent: cleanup must not wait.
        """
        if self.check_id is None:
            raise BudgetExceeded(f"{what}: no check is active, so nothing may be sent")
        if self.check_sent + 1 > self.check_limit:
            raise BudgetExceeded(
                f"{self.check_id} tried to send request {self.check_sent + 1} ({what}) but declared "
                f"at most {self.check_limit}; nothing was sent"
            )
        if self.total + 1 > self.total_limit:
            raise BudgetExceeded(
                f"{self.check_id} tried to send request {self.total + 1} of the run ({what}) but "
                f"security_checks.max_requests is {self.total_limit}; nothing was sent"
            )
        if paced:
            reason = self.should_stop()
            if reason:
                raise Stopped(reason)
            if self._last_paced is not None:
                wait = self._last_paced + self.interval - self.monotonic()
                if wait > 0:
                    self.sleep(wait)
            reason = self.should_stop()
            if reason:
                raise Stopped(reason)
            self._last_paced = self.monotonic()
        self.check_sent += 1
        self.total += 1
        self.log.append({"check": self.check_id, "request": what, "paced": paced})

    def reserve(self, what: str, count: int) -> int:
        """Account for up to ``count`` requests that a child process will send.

        A softphone call sends a number of requests only it knows. The worst
        case is charged *before* the call starts, with the same bound and
        pacing checks as :meth:`spend`; :meth:`settle` then replaces it by the
        number the call really sent.
        """
        if self.check_id is None:
            raise BudgetExceeded(f"{what}: no check is active, so nothing may be sent")
        if count < 1:
            raise ValueError("reserve at least one request")
        if self.check_sent + count > self.check_limit:
            raise BudgetExceeded(
                f"{self.check_id} tried to reserve {count} requests ({what}) after sending "
                f"{self.check_sent} but declared at most {self.check_limit}; nothing was sent"
            )
        if self.total + count > self.total_limit:
            raise BudgetExceeded(
                f"{self.check_id} tried to reserve {count} requests ({what}) after {self.total} in the "
                f"run, but security_checks.max_requests is {self.total_limit}; nothing was sent"
            )
        reason = self.should_stop()
        if reason:
            raise Stopped(reason)
        if self._last_paced is not None:
            wait = self._last_paced + self.interval - self.monotonic()
            if wait > 0:
                self.sleep(wait)
        reason = self.should_stop()
        if reason:
            raise Stopped(reason)
        self._last_paced = self.monotonic()
        self.check_sent += count
        self.total += count
        self.log.append({"check": self.check_id, "request": what, "paced": True, "reserved": count})
        return count

    def settle(self, what: str, reserved: int, actual: int) -> None:
        """Replace a reservation by what was really sent (from the call's own log).

        Sending fewer is refunded. Sending more than reserved cannot be
        undone: the excess is counted and :class:`BudgetExceeded` is raised
        so the check ends as an error.
        """
        if actual <= reserved:
            self.check_sent -= reserved - actual
            self.total -= reserved - actual
            self.log.append({"check": self.check_id, "request": what, "settled": actual, "reserved": reserved})
            return
        extra = actual - reserved
        self.check_sent += extra
        self.total += extra
        self.log.append({"check": self.check_id, "request": what, "settled": actual, "reserved": reserved})
        raise BudgetExceeded(f"{self.check_id}: {what} sent {actual} requests but only {reserved} were reserved")
