"""Caching UDP DNS resolver for one fixed internal domain, with a
per-source-IP fair scheduler for upstream re-fetches.

Behaviour (all timings from app.common, defaults are the spec values):

  * a successful A answer is cached fresh for FRESH_TTL (5s) and served from
    cache with the remaining TTL;  fresh cache hits are answered immediately
    and never touch the scheduler;
  * after expiry the resolver re-fetches upstream, but only through the fair
    scheduler:
      - at most MAX_INFLIGHT_TOTAL (2) upstream fetches in flight overall;
      - at most MAX_INFLIGHT_PER_IP (1) in-flight fetch per source IP, and
        MAX_QUEUED_PER_IP (2) queued waiters per source IP;
      - freed slots are handed to queued waiters round-robin by source IP;
      - a request that finds its per-IP queue full, or that is not granted a
        slot within QUEUE_WAIT_MAX (4s), is NOT sent upstream: it is answered
        from the cache as it stands at that moment -- the old A record while
        its original STALE_WINDOW (20s) lasts, otherwise SERVFAIL;
  * a waiter that is finally granted a slot re-checks the cache before
    fetching: if another in-flight fetch meanwhile refreshed the A record or
    confirmed NXDOMAIN, the waiter answers from the current cache instead of
    fetching -- so a purged old A record is never emitted again;
  * NXDOMAIN is cached fresh only -- it is never used as stale backup;
  * confirming NXDOMAIN purges the old A record durably (SQLite), so no later
    answer contains the old A again;
  * every upstream attempt uses a dedicated socket with a random transaction
    ID and matches the question section, so a late answer to an already
    timed-out query is never read and can never resurrect the old A;
  * cache deadlines are absolute epochs persisted in SQLite, so a restart does
    not extend the validity of an old A record.

The resolver reports where each answer came from in an additional-section TXT
record (_src.<domain> TXT "source=... client=... queued=.. waited=..s up=..")
and logs every query to the query_log table for the web console.
"""
from __future__ import annotations

import collections
import random
import socket
import threading
import time
import traceback

from dnslib import A, CLASS, QTYPE, RCODE, RR, TXT, DNSHeader, DNSRecord

from . import common


# --------------------------------------------------------------------------
# Fair upstream scheduler
# --------------------------------------------------------------------------
class _Waiter:
    __slots__ = ("ip", "event", "granted", "cancelled")

    def __init__(self, ip: str):
        self.ip = ip
        self.event = threading.Event()
        self.granted = False
        self.cancelled = False


class FairUpstreamScheduler:
    """Per-source-IP fair scheduler for upstream re-fetch slots.

      * at most ``max_inflight`` upstream fetches in flight overall;
      * at most ``per_ip_inflight`` in-flight fetch per source IP, and at most
        ``per_ip_queue`` queued waiters per source IP;
      * freed slots are handed to queued waiters in round-robin order across
        source IPs (one grant per IP per pass, in enqueue order);
      * a request that finds its per-IP queue full is rejected outright, and
        a waiter not granted a slot within ``wait_max`` seconds gives up --
        neither is sent upstream.

    Invariant: a queued waiter that could be granted (its IP below the per-IP
    in-flight limit) never coexists with a free global slot -- releases grant
    eagerly, so an immediate grant can never overtake a grantable waiter.
    """

    def __init__(self, max_inflight: int = 2, per_ip_inflight: int = 1,
                 per_ip_queue: int = 2, wait_max: float = 4.0, on_stats=None):
        self.max_inflight = max_inflight
        self.per_ip_inflight = per_ip_inflight
        self.per_ip_queue = per_ip_queue
        self.wait_max = wait_max
        self._on_stats = on_stats
        self._lock = threading.Lock()
        self._inflight = 0                              # global in-flight slots
        self._ips: dict[str, dict] = {}                 # ip -> {inflight, queue}
        self._rr: collections.deque[str] = collections.deque()  # IPs with waiters
        self._stats = {
            "inflight": 0, "queued": 0,
            "upstream_total": 0, "grant_immediate_total": 0,
            "grant_queued_total": 0, "rejected_total": 0,
            "wait_timeout_total": 0,
        }

    # -- helpers (lock held) -------------------------------------------------
    def _state(self, ip: str) -> dict:
        return self._ips.setdefault(ip, {"inflight": 0, "queue": collections.deque()})

    @staticmethod
    def _pop_live(st: dict):
        """Pop the oldest non-cancelled waiter, dropping cancelled ones."""
        while st["queue"]:
            w = st["queue"].popleft()
            if not w.cancelled:
                return w
        return None

    def _sync_gauges(self) -> None:
        self._stats["inflight"] = self._inflight
        self._stats["queued"] = sum(len(st["queue"]) for st in self._ips.values())

    def _emit(self) -> None:
        cb = self._on_stats
        if cb is not None:
            try:
                cb(dict(self._stats))
            except Exception:
                pass  # best-effort telemetry must never break scheduling

    def _schedule(self) -> None:
        """Grant freed slots to queued waiters, round-robin across source IPs."""
        while self._inflight < self.max_inflight and self._rr:
            granted = False
            for _ in range(len(self._rr)):
                ip = self._rr.popleft()
                st = self._ips[ip]
                w = self._pop_live(st)
                if w is None:
                    continue  # queue drained: drop the IP from the rotation
                if st["inflight"] >= self.per_ip_inflight:
                    st["queue"].appendleft(w)
                    self._rr.append(ip)  # blocked by its own in-flight: next IP
                    continue
                st["inflight"] += 1
                self._inflight += 1
                w.granted = True
                w.event.set()
                if st["queue"]:
                    self._rr.append(ip)  # still has waiters: back of the rotation
                self._stats["grant_queued_total"] += 1
                granted = True
                break
            if not granted:
                break
        self._sync_gauges()

    # -- public API -----------------------------------------------------------
    def acquire(self, ip: str) -> tuple[bool, float, str]:
        """Wait for an upstream slot.

        Returns (granted, waited_seconds, note) with note one of
        immediate | queued | queue-full | wait-timeout.
        """
        t0 = time.monotonic()
        with self._lock:
            st = self._state(ip)
            if (st["inflight"] < self.per_ip_inflight
                    and self._inflight < self.max_inflight):
                st["inflight"] += 1
                self._inflight += 1
                self._stats["grant_immediate_total"] += 1
                self._sync_gauges()
                self._emit()
                return True, 0.0, "immediate"
            if len(st["queue"]) >= self.per_ip_queue:
                self._stats["rejected_total"] += 1
                self._emit()
                return False, 0.0, "queue-full"
            w = _Waiter(ip)
            st["queue"].append(w)
            if len(st["queue"]) == 1:
                self._rr.append(ip)
            self._sync_gauges()
            self._emit()
        w.event.wait(self.wait_max)
        waited = time.monotonic() - t0
        with self._lock:
            if w.granted:
                return True, waited, "queued"
            # Timed out: cancel so the scheduler can never grant this waiter a
            # slot afterwards (grant and cancel are serialised by the lock).
            w.cancelled = True
            st = self._ips.get(ip)
            if st is not None:
                try:
                    st["queue"].remove(w)
                except ValueError:
                    pass
                if not st["queue"] and ip in self._rr:
                    self._rr.remove(ip)
            self._stats["wait_timeout_total"] += 1
            self._sync_gauges()
            self._emit()
            return False, waited, "wait-timeout"

    def release(self, ip: str) -> None:
        with self._lock:
            st = self._ips.get(ip)
            if st is not None and st["inflight"] > 0:
                st["inflight"] -= 1
                self._inflight -= 1
            self._schedule()
            self._emit()

    def note_upstream(self) -> None:
        """Count one actual upstream fetch."""
        with self._lock:
            self._stats["upstream_total"] += 1
            self._emit()

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self._stats)


SCHED = FairUpstreamScheduler(
    max_inflight=common.MAX_INFLIGHT_TOTAL,
    per_ip_inflight=common.MAX_INFLIGHT_PER_IP,
    per_ip_queue=common.MAX_QUEUED_PER_IP,
    wait_max=common.QUEUE_WAIT_MAX,
    on_stats=common.put_resolver_stats,
)


def _same_name(a, b) -> bool:
    return str(a).rstrip(".").lower() == str(b).rstrip(".").lower()


def upstream_query() -> DNSRecord | None:
    """One-shot upstream A query for the fixed domain.

    A dedicated UDP socket per attempt plus a random transaction ID means a
    late answer to an earlier, already timed-out query can never be read back
    (the socket is closed) and can never be mistaken for the answer to a later
    query (ID + question must match).
    """
    query = DNSRecord.question(common.FQDN, "A")
    query.header.id = random.randint(0, 0xFFFF)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(query.pack(), (common.AUTH_HOST, common.AUTH_PORT))
        deadline = time.monotonic() + common.UPSTREAM_TIMEOUT
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(remaining)
            try:
                data, _addr = sock.recvfrom(4096)
            except socket.timeout:
                return None
            try:
                resp = DNSRecord.parse(data)
            except Exception:
                continue  # unparsable stray datagram: keep waiting
            if resp.header.id != query.header.id:
                continue  # stray/late packet for someone else: ignore
            if not _same_name(resp.q.qname, query.q.qname):
                continue
            return resp
    except OSError:
        return None
    finally:
        sock.close()


def _a_rr(ip: str, ttl: int) -> RR:
    return RR(common.FQDN, QTYPE.A, CLASS.IN, ttl, A(ip))


def _reply(query: DNSRecord, rcode: int, answers=(), source="none", client="-",
           queued=0, waited=0.0, up=0, extra="") -> DNSRecord:
    rep = DNSRecord(
        DNSHeader(
            id=query.header.id, qr=1, aa=0, ra=1, rd=query.header.rd, rcode=rcode
        ),
        q=query.q,
    )
    for rr in answers:
        rep.add_answer(rr)
    meta = (f"source={source} client={client} queued={queued} "
            f"waited={waited:.1f}s up={up}")
    if extra:
        meta += f" {extra}"
    rep.add_ar(RR(f"_src.{common.FQDN}", QTYPE.TXT, CLASS.IN, 0, TXT(meta)))
    return rep


def _fresh_reply(query: DNSRecord, row, now: float, client: str,
                 queued: int, waited: float, up: int):
    """Build a fresh-cache answer from `row`, or None if nothing is fresh."""
    if row and row["rcode"] == "NOERROR" and row["a_record"] and now < row["fresh_until"]:
        ttl = max(1, int(row["fresh_until"] - now + 0.999))
        return (
            _reply(query, RCODE.NOERROR, [_a_rr(row["a_record"], ttl)],
                   "cache-fresh", client, queued, waited, up,
                   f"fresh_left={row['fresh_until'] - now:.1f}"),
            "cache-fresh",
            "fresh A from cache",
        )
    if row and row["rcode"] == "NXDOMAIN" and now < row["fresh_until"]:
        return (
            _reply(query, RCODE.NXDOMAIN, [], "cache-fresh",
                   client, queued, waited, up,
                   f"fresh_left={row['fresh_until'] - now:.1f}"),
            "cache-fresh",
            "fresh NXDOMAIN from cache",
        )
    return None


def _cache_fallback(query: DNSRecord, client: str, queued: int, waited: float,
                    up: int, note: str):
    """Answer without (another) upstream fetch, from the cache as it stands
    *now*: a fresh entry if some other fetch just refreshed it, else the old
    A record while its original STALE_WINDOW lasts, else SERVFAIL."""
    row = common.get_cache()
    now = time.time()
    hit = _fresh_reply(query, row, now, client, queued, waited, up)
    if hit:
        return hit
    if (
        row
        and row["rcode"] == "NOERROR"
        and row["a_record"]
        and row["stale_until"]
        and now < row["stale_until"]
    ):
        ttl = max(1, int(row["stale_until"] - now + 0.999))
        return (
            _reply(query, RCODE.NOERROR, [_a_rr(row["a_record"], ttl)],
                   "cache-stale", client, queued, waited, up,
                   f"stale_left={row['stale_until'] - now:.1f} reason={note}"),
            "cache-stale",
            f"{note}; serving stale A",
        )
    return (
        _reply(query, RCODE.SERVFAIL, [], "none", client, queued, waited, up,
               f"reason={note}"),
        "none",
        f"{note}; no usable cache",
    )


def resolve_a(query: DNSRecord, client_ip: str) -> tuple[DNSRecord, str, str]:
    """Resolve the fixed domain's A record.  Returns (reply, source, detail)."""
    # 1) fresh cache hits are answered immediately, no scheduling involved
    hit = _fresh_reply(query, common.get_cache(), time.time(), client_ip, 0, 0.0, 0)
    if hit:
        return hit

    # 2) expired: upstream re-fetch, but only through the fair scheduler
    granted, waited, note = SCHED.acquire(client_ip)
    queued = 1 if note in ("queued", "wait-timeout") else 0
    if not granted:
        # Per-IP queue full, or waited too long: no upstream fetch.  Answer
        # from the cache as it stands *now* (another in-flight fetch may have
        # refreshed it meanwhile).
        return _cache_fallback(query, client_ip, queued, waited, 0, note)

    try:
        # Re-check before spending an upstream fetch: while this request was
        # queued, another in-flight fetch may have refreshed the A record or
        # confirmed NXDOMAIN.  Waiters must use the current cache -- the old
        # (possibly purged) A record must not be emitted again.
        hit = _fresh_reply(query, common.get_cache(), time.time(),
                           client_ip, queued, waited, 0)
        if hit:
            return hit

        SCHED.note_upstream()
        resp = upstream_query()
        now2 = time.time()

        if resp is not None and resp.header.rcode == RCODE.NOERROR:
            ips = [str(rr.rdata) for rr in resp.rr if rr.rtype == QTYPE.A]
            if ips:
                common.put_cache_a(ips[0], now2)
                return (
                    _reply(query, RCODE.NOERROR, [_a_rr(ips[0], int(common.FRESH_TTL))],
                           "upstream", client_ip, queued, waited, 1),
                    "upstream",
                    f"fetched A={ips[0]}",
                )

        if resp is not None and resp.header.rcode == RCODE.NXDOMAIN:
            # Confirming NXDOMAIN purges the old A record (durably, in SQLite).
            common.put_cache_nxdomain(now2)
            return (
                _reply(query, RCODE.NXDOMAIN, [], "upstream",
                       client_ip, queued, waited, 1, "nxdomain-confirmed"),
                "upstream",
                "NXDOMAIN confirmed; old A purged",
            )

        # 3) upstream timeout / unusable reply: fall back to the current cache
        #    (a parallel fetch may have refreshed it while we waited).
        return _cache_fallback(query, client_ip, queued, waited, 1,
                               "upstream-timeout")
    finally:
        SCHED.release(client_ip)


def handle_packet(data: bytes, addr, sock: socket.socket) -> None:
    qname = qtype = "?"
    client = addr[0] if addr else "?"
    try:
        query = DNSRecord.parse(data)
        qname = str(query.q.qname)
        qtype = QTYPE[query.q.qtype]
        if not _same_name(query.q.qname, common.FQDN):
            rep = _reply(query, RCODE.REFUSED, [], "none", client, extra="out-of-scope")
            source, detail = "none", "out-of-scope"
        elif query.q.qtype == QTYPE.A:
            rep, source, detail = resolve_a(query, client)
        else:
            rep = _reply(query, RCODE.NOERROR, [], "none", client, extra="nodata")
            source, detail = "none", "nodata"
        sock.sendto(rep.pack(), addr)
        answers = ";".join(
            f"{QTYPE[rr.rtype]}={rr.rdata}(ttl={rr.ttl})" for rr in rep.rr
        ) or "-"
        common.log_query(qname, qtype, source, RCODE[rep.header.rcode], answers,
                         detail, client)
    except Exception:
        common.log_query(qname, qtype, "error", "SERVFAIL", "-",
                         traceback.format_exc(limit=3), client)


def main() -> None:
    common.init_db()
    common.put_resolver_stats({"inflight": 0, "queued": 0})  # reset gauges
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", common.RESOLVER_PORT))
    print(
        f"[resolver] {common.FQDN} on udp/{common.RESOLVER_PORT}, "
        f"upstream {common.AUTH_HOST}:{common.AUTH_PORT}, "
        f"fresh={common.FRESH_TTL}s stale={common.STALE_WINDOW}s "
        f"timeout={common.UPSTREAM_TIMEOUT}s "
        f"inflight<={common.MAX_INFLIGHT_TOTAL} "
        f"per-ip<={common.MAX_INFLIGHT_PER_IP}+{common.MAX_QUEUED_PER_IP}q "
        f"queue-wait<={common.QUEUE_WAIT_MAX}s",
        flush=True,
    )
    while True:
        data, addr = sock.recvfrom(4096)
        threading.Thread(target=handle_packet, args=(data, addr, sock),
                         daemon=True).start()


if __name__ == "__main__":
    main()
