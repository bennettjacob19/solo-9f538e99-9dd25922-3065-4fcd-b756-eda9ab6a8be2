#!/usr/bin/env python3
"""End-to-end self-test for the serve-stale DNS duty system.

Spawns auth + resolver + web on loopback with the production timing
parameters (fresh TTL 5s, stale window 20s, upstream timeout 2s) and drives
the key interleavings:

  A. basic fetch / fresh-cache hit / TTL countdown / refresh after expiry
  B. upstream timeout after expiry -> stale A (<=20s) -> SERVFAIL beyond
  C. confirmed NXDOMAIN purges the old A; NXDOMAIN is never served stale
  D. a late (delayed) old answer cannot resurrect anything
  E. resolver restart does not extend the old A's validity
  F. fair-scheduler unit logic (limits, round-robin, wait timeout, no leaks)
  G. per-source-IP fair scheduling end to end (queue limits, waiters use the
     refreshed/purged cache, fairness across source IPs)
  H. web console smoke test (page, mode switch, single + batch query, state)

Exits non-zero if any check fails.  Runtime: ~2 minutes.
"""
from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from dnslib import QTYPE, DNSRecord  # noqa: E402

DOMAIN = "service.example"
AUTH_PORT, RES_PORT, WEB_PORT = 15354, 15353, 18000
TMP = tempfile.mkdtemp(prefix="dns-selftest-")
DB = os.path.join(TMP, "app.db")

env = dict(os.environ)
env.update(
    DB_PATH=DB,
    FIXED_DOMAIN=DOMAIN,
    AUTH_HOST="127.0.0.1",
    AUTH_PORT=str(AUTH_PORT),
    RESOLVER_HOST="127.0.0.1",
    RESOLVER_PORT=str(RES_PORT),
    WEB_PORT=str(WEB_PORT),
    FRESH_TTL="5",
    STALE_WINDOW="20",
    UPSTREAM_TIMEOUT="2",
    MAX_INFLIGHT_TOTAL="2",
    MAX_INFLIGHT_PER_IP="1",
    MAX_QUEUED_PER_IP="2",
    QUEUE_WAIT_MAX="4",
    DEFAULT_IP="192.0.2.10",
    DEFAULT_DELAY="3",
    PYTHONPATH=ROOT,
    PYTHONUNBUFFERED="1",
)

procs: dict[str, subprocess.Popen] = {}
FAILS: list[str] = []


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def start(name: str, module: str) -> None:
    log = open(os.path.join(TMP, f"{name}.log"), "ab")
    procs[name] = subprocess.Popen(
        [sys.executable, "-m", module],
        cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
    )


def stop(name: str) -> None:
    p = procs.get(name)
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()


def set_mode(mode: str, ip: str = "192.0.2.10", delay: float = 3.0) -> None:
    conn = sqlite3.connect(DB, timeout=15)
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute(
        "INSERT INTO control(id, mode, ip, delay_seconds, updated_at)"
        " VALUES (1, ?, ?, ?, ?)"
        " ON CONFLICT(id) DO UPDATE SET mode=excluded.mode, ip=excluded.ip,"
        " delay_seconds=excluded.delay_seconds, updated_at=excluded.updated_at",
        (mode, ip, delay, time.time()),
    )
    conn.commit()
    conn.close()


def get_cache() -> dict | None:
    conn = sqlite3.connect(DB, timeout=15)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM cache WHERE id = 1").fetchone()
    conn.close()
    return dict(row) if row else None


def auth_actions() -> list[tuple]:
    conn = sqlite3.connect(DB, timeout=15)
    rows = conn.execute(
        "SELECT mode, action, detail FROM auth_log ORDER BY id"
    ).fetchall()
    conn.close()
    return rows


def clear_cache() -> None:
    conn = sqlite3.connect(DB, timeout=15)
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("DELETE FROM cache WHERE id = 1")
    conn.commit()
    conn.close()


def dns_query() -> tuple[int, list[tuple], str | None]:
    """Returns (rcode, [(type, data, ttl)], source)."""
    q = DNSRecord.question(DOMAIN, "A")
    data = q.send("127.0.0.1", RES_PORT, timeout=8)
    rep = DNSRecord.parse(data)
    answers = [(QTYPE[rr.rtype], str(rr.rdata), rr.ttl) for rr in rep.rr]
    src = None
    for rr in rep.ar:
        if rr.rtype == QTYPE.TXT:
            txt = str(rr.rdata).strip('"')
            if txt.startswith("source="):
                src = txt.split("=", 1)[1].split()[0]
    return rep.header.rcode, answers, src


def dns_query_meta(src_ip: str | None = None) -> dict:
    """One real A query; returns rcode/answers plus the scheduler meta the
    resolver reports (source, client IP, queued, waited, up, reason)."""
    q = DNSRecord.question(DOMAIN, "A")
    if src_ip:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind((src_ip, 0))  # 127.0.0.0/8 is all loopback on Linux
            s.settimeout(12)
            s.sendto(q.pack(), ("127.0.0.1", RES_PORT))
            data, _ = s.recvfrom(4096)
        finally:
            s.close()
    else:
        data = q.send("127.0.0.1", RES_PORT, timeout=12)
    rep = DNSRecord.parse(data)
    kv = {}
    for rr in rep.ar:
        if rr.rtype == QTYPE.TXT:
            for tok in str(rr.rdata).strip('"').split():
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    kv[k] = v
    return {
        "rcode": rep.header.rcode,
        "answers": [(QTYPE[rr.rtype], str(rr.rdata), rr.ttl) for rr in rep.rr],
        "source": kv.get("source", "?"),
        "client": kv.get("client", "?"),
        "queued": kv.get("queued", "0"),
        "waited": kv.get("waited", "0s"),
        "up": kv.get("up", "0"),
        "reason": kv.get("reason", ""),
    }


def fire_concurrent(src_ips: list[str | None]) -> list[dict]:
    """Fire one real query per given source IP, all at once."""
    results: list[dict] = [None] * len(src_ips)  # type: ignore[list-item]

    def worker(i: int, ip: str | None) -> None:
        results[i] = dns_query_meta(ip)

    threads = [threading.Thread(target=worker, args=(i, ip))
               for i, ip in enumerate(src_ips)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    return results


def check(name: str, cond: bool, info: str = "") -> None:
    print(f"  [{'PASS' if cond else 'FAIL'}] {name} {info}", flush=True)
    if not cond:
        FAILS.append(name)


def sleep_until(ts: float) -> None:
    time.sleep(max(0.0, ts - time.time()))


def wait_resolver_ready(timeout: float = 25) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            dns_query()
            return True
        except Exception:
            time.sleep(0.3)
    return False


def wait_web_ready(timeout: float = 25) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{WEB_PORT}/api/state", timeout=2
            ) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.3)
    return False


def unit_scheduler() -> None:
    """In-process checks of FairUpstreamScheduler (no services needed)."""
    from app.resolver import FairUpstreamScheduler

    s = FairUpstreamScheduler(max_inflight=2, per_ip_inflight=1,
                              per_ip_queue=2, wait_max=5.0)
    r = s.acquire("A")
    check("F1 首个请求立即获得回源名额", r[0] and r[2] == "immediate", f"{r}")
    got: dict[str, tuple] = {}

    def worker(tag: str, ip: str) -> None:
        got[tag] = s.acquire(ip)

    t1 = threading.Thread(target=worker, args=("t1", "A"))
    t1.start()
    time.sleep(0.15)  # deterministic enqueue order
    t2 = threading.Thread(target=worker, args=("t2", "A"))
    t2.start()
    time.sleep(0.3)  # both queued now
    r = s.acquire("A")
    check("F2 同 IP 队列满（2 条）即拒绝", not r[0] and r[2] == "queue-full", f"{r}")
    r = s.acquire("B")
    check("F3 其他 IP 可立即获得全局空位（互不占满）",
          r[0] and r[2] == "immediate", f"{r}")
    t3 = threading.Thread(target=worker, args=("t3", "C"))
    t3.start()
    time.sleep(0.3)  # C queues: global slots full
    s.release("A")   # frees a slot -> A's first waiter
    t1.join(3)
    check("F4 空位先授予同 IP 最早等待者",
          got.get("t1", (None,))[0] is True and got["t1"][2] == "queued",
          f"{got.get('t1')}")
    s.release("B")   # next slot -> C's waiter (A still has one in flight)
    t3.join(3)
    check("F5 空位按来源轮流分配给下一 IP",
          got.get("t3", (None,))[0] is True, f"{got.get('t3')}")
    s.release("A")   # t1 done -> A's second waiter
    t2.join(3)
    check("F6 同 IP 第二等待者随后获授",
          got.get("t2", (None,))[0] is True, f"{got.get('t2')}")
    s.release("A")
    s.release("C")
    snap = s.snapshot()
    check("F7 全部释放后名额无泄漏",
          snap["inflight"] == 0 and snap["queued"] == 0, f"{snap}")

    s2 = FairUpstreamScheduler(max_inflight=2, per_ip_inflight=1,
                               per_ip_queue=2, wait_max=0.3)
    s2.acquire("X")
    t0 = time.monotonic()
    r = s2.acquire("X")  # queued; nobody releases -> must give up
    dt = time.monotonic() - t0
    check("F8 等待超时不再回源",
          not r[0] and r[2] == "wait-timeout" and 0.25 <= dt <= 2.0,
          f"{r} waited={dt:.2f}s")
    s2.release("X")
    snap = s2.snapshot()
    check("F9 超时取消不占名额",
          snap["inflight"] == 0 and snap["queued"] == 0, f"{snap}")


# --------------------------------------------------------------------------
# scenario
# --------------------------------------------------------------------------
def main() -> int:
    print(f"[selftest] workdir={TMP}", flush=True)
    start("auth", "app.auth_server")
    start("resolver", "app.resolver")
    start("web", "app.web")
    try:
        if not (wait_resolver_ready() and wait_web_ready()):
            print("  [FAIL] services did not come up")
            return 1

        # -- A. basic fetch / fresh cache / refresh --------------------------
        print("A. 基本应答与新鲜缓存", flush=True)
        clear_cache()  # the readiness probe already populated the cache
        set_mode("a", "192.0.2.10")
        rc, ans, src = dns_query()
        check("A1 上游取回 A", rc == 0 and ans == [("A", "192.0.2.10", 5)]
              and src == "upstream", f"rcode={rc} ans={ans} src={src}")
        rc, ans, src = dns_query()
        check("A2 命中新鲜缓存", rc == 0 and src == "cache-fresh"
              and ans and ans[0][1] == "192.0.2.10" and 1 <= ans[0][2] <= 5,
              f"ans={ans} src={src}")
        set_mode("a", "192.0.2.20")  # change the A record on the auth side
        rc, ans, src = dns_query()
        check("A3 缓存期内仍给旧 IP", rc == 0 and src == "cache-fresh"
              and ans and ans[0][1] == "192.0.2.10", f"ans={ans} src={src}")
        time.sleep(5.5)
        rc, ans, src = dns_query()
        check("A4 过期后重新取回新 IP", rc == 0 and src == "upstream"
              and ans == [("A", "192.0.2.20", 5)], f"ans={ans} src={src}")
        cache = get_cache()
        fresh_until, stale_until = cache["fresh_until"], cache["stale_until"]

        # -- B. stale on timeout, SERVFAIL beyond the window -----------------
        print("B. 过期+上游超时 -> 旧 A 沿用 <=20s -> SERVFAIL", flush=True)
        set_mode("timeout")
        sleep_until(fresh_until + 0.5)
        t0 = time.time()
        rc, ans, src = dns_query()
        check("B1 上游超时后给旧 A(stale)",
              rc == 0 and src == "cache-stale" and ans
              and ans[0][1] == "192.0.2.20"
              and stale_until - time.time() - 1 <= ans[0][2] <= 20,
              f"ans={ans} src={src} 耗时={time.time()-t0:.1f}s")
        sleep_until(stale_until - 4)
        rc, ans, src = dns_query()
        check("B2 窗口末尾仍是 stale", rc == 0 and src == "cache-stale",
              f"ans={ans} src={src}")
        sleep_until(stale_until + 1)
        rc, ans, src = dns_query()
        check("B3 超过 20s 返回 SERVFAIL", rc == 2 and not ans and src == "none",
              f"rcode={rc} ans={ans} src={src}")

        # -- C. NXDOMAIN purges old A; NXDOMAIN never served stale -----------
        print("C. 确认 NXDOMAIN 清除旧 A；NXDOMAIN 不作过期备用", flush=True)
        set_mode("a", "192.0.2.30")
        rc, ans, src = dns_query()
        assert rc == 0 and src == "upstream", f"setup failed: {rc} {src}"
        set_mode("nxdomain")
        time.sleep(5.5)  # let the fresh A expire
        rc, ans, src = dns_query()
        check("C1 上游确认 NXDOMAIN", rc == 3 and not ans and src == "upstream",
              f"rcode={rc} ans={ans} src={src}")
        cache = get_cache()
        check("C2 旧 A 已被持久清除",
              cache["rcode"] == "NXDOMAIN" and cache["a_record"] is None
              and cache["stale_until"] is None,
              f"cache={cache}")
        set_mode("timeout")
        time.sleep(5.5)  # let the fresh NXDOMAIN expire
        rc, ans, src = dns_query()
        check("C3 NXDOMAIN 不作 stale 备用 -> SERVFAIL",
              rc == 2 and not ans and src == "none",
              f"rcode={rc} ans={ans} src={src}")

        # -- D. late old answer cannot resurrect -----------------------------
        print("D. 超时后迟到的旧答复不能复活记录", flush=True)
        set_mode("a", "192.0.2.40")
        rc, ans, src = dns_query()
        assert rc == 0 and src == "upstream", f"setup failed: {rc} {src}"
        set_mode("delay", "192.0.2.40", 3.0)  # 3s delay > 2s upstream timeout
        time.sleep(5.5)  # fresh A expires
        t0 = time.time()
        rc, ans, src = dns_query()  # upstream times out at 2s; delayed A lands ~1s later
        check("D1 延迟模式下先按超时处理 -> stale",
              rc == 0 and src == "cache-stale" and 1.8 <= time.time() - t0 <= 4,
              f"ans={ans} src={src} 耗时={time.time()-t0:.1f}s")
        time.sleep(1.5)  # the delayed A has now arrived at a closed socket
        set_mode("nxdomain")
        rc, ans, src = dns_query()
        check("D2 随后确认 NXDOMAIN", rc == 3 and src == "upstream",
              f"rcode={rc} src={src}")
        set_mode("timeout")
        time.sleep(5.5)  # past NXDOMAIN freshness; delayed A long arrived
        rc, ans, src = dns_query()
        check("D3 迟到旧 A 未复活任何记录 -> SERVFAIL",
              rc == 2 and not ans, f"rcode={rc} ans={ans} src={src}")
        cache = get_cache()
        check("D4 缓存中仍无 A 记录", cache["a_record"] is None,
              f"cache={cache}")
        delayed = [r for r in auth_actions() if r[0] == "delay" and r[1] == "answered"]
        check("D5 权威端确实发出过延迟应答（被解析器丢弃）", len(delayed) >= 1,
              f"delay 应答次数={len(delayed)}")

        # -- E. restart does not extend validity -----------------------------
        print("E. 重启不延长旧 A 有效期", flush=True)
        set_mode("a", "192.0.2.50")
        rc, ans, src = dns_query()
        assert rc == 0 and src == "upstream", f"setup failed: {rc} {src}"
        stale_until = get_cache()["stale_until"]
        time.sleep(4)
        stop("resolver")
        time.sleep(1)
        start("resolver", "app.resolver")  # restart with the same DB
        set_mode("timeout")
        assert wait_resolver_ready(), "resolver did not come back"
        sleep_until(stale_until - 4)
        rc, ans, src = dns_query()
        check("E1 重启后窗口内仍可用旧 A(绝对期限未变)",
              rc == 0 and src == "cache-stale" and ans
              and ans[0][1] == "192.0.2.50", f"ans={ans} src={src}")
        sleep_until(stale_until + 2)
        rc, ans, src = dns_query()
        check("E2 到达原绝对期限即 SERVFAIL（未被重启延长）",
              rc == 2 and not ans, f"rcode={rc} ans={ans} src={src}")

        # -- F. fair-scheduler unit logic (in-process, no services) ---------
        print("F. 回源调度器单元逻辑（名额/排队/轮流/超时）", flush=True)
        unit_scheduler()

        # -- G. per-source-IP fair scheduling, end to end --------------------
        print("G. 按来源 IP 公平的回源调度（端到端）", flush=True)
        set_mode("a", "192.0.2.70")
        clear_cache()
        r0 = dns_query_meta()
        assert r0["rcode"] == 0 and r0["up"] == "1", f"setup failed: {r0}"
        time.sleep(5.5)  # fresh A expires; 20s stale window stays open
        set_mode("timeout")

        # G1: 4 concurrent queries from ONE IP -> 1 in-flight, 2 queued,
        #     1 rejected (queue full); everyone still gets the stale old A.
        auth_before = len(auth_actions())
        res = fire_concurrent([None] * 4)
        ok_stale = all(r["rcode"] == 0 and r["answers"]
                       and r["answers"][0][1] == "192.0.2.70" for r in res)
        check("G1 同 IP 并发 4 条：全部拿到窗口内旧 A", ok_stale,
              f"{[(r['rcode'], r['answers'], r['reason']) for r in res]}")
        check("G1 恰好 1 条因队列满未回源",
              sum(1 for r in res if r["reason"] == "queue-full") == 1,
              f"reasons={[r['reason'] for r in res]}")
        check("G1 恰好 2 条经历排队",
              sum(1 for r in res if r["queued"] == "1") == 2,
              f"queued={[r['queued'] for r in res]}")
        ups = sum(1 for r in res if r["up"] == "1")
        check("G1 回源 2~3 次（每 IP 在途≤1，排队者依次回源）", 2 <= ups <= 3,
              f"up={ups}")
        check("G1 权威端收到查询数与回源数一致",
              len(auth_actions()) - auth_before == ups,
              f"auth={len(auth_actions()) - auth_before} up={ups}")
        check("G1 未回源者均按当时缓存答复（无新增旧 A 之外内容）",
              all(r["up"] == "1" or r["source"] == "cache-stale" for r in res),
              f"sources={[r['source'] for r in res]}")

        # G2: while one fetch is in flight, the queued waiter must reuse the
        #     refreshed cache instead of fetching again.
        set_mode("a", "192.0.2.71")
        auth_before = len(auth_actions())
        res = fire_concurrent([None] * 2)
        check("G2 等待者改用已刷新缓存：仅 1 次回源",
              sum(1 for r in res if r["up"] == "1") == 1
              and len(auth_actions()) - auth_before == 1,
              f"up={[r['up'] for r in res]}")
        check("G2 两条都拿到新 IP（未发旧 A）",
              all(r["rcode"] == 0 and r["answers"]
                  and r["answers"][0][1] == "192.0.2.71" for r in res),
              f"{[(r['rcode'], r['answers']) for r in res]}")
        check("G2 等待者来自 cache-fresh",
              any(r["source"] == "cache-fresh" and r["up"] == "0" for r in res),
              f"sources={[r['source'] for r in res]}")

        # G3: NXDOMAIN confirmed while another request waits -> the waiter
        #     must use the current cache and never emit the purged old A.
        time.sleep(5.5)  # let the fresh .71 expire
        set_mode("nxdomain")
        auth_before = len(auth_actions())
        res = fire_concurrent([None] * 2)
        check("G3 两条均为 NXDOMAIN 且不含旧 A",
              all(r["rcode"] == 3 and not r["answers"] for r in res),
              f"{[(r['rcode'], r['answers']) for r in res]}")
        check("G3 仅 1 次回源确认 NXDOMAIN",
              sum(1 for r in res if r["up"] == "1") == 1
              and len(auth_actions()) - auth_before == 1,
              f"up={[r['up'] for r in res]}")
        cache = get_cache()
        check("G3 旧 A 已被持久清除",
              cache["rcode"] == "NXDOMAIN" and cache["a_record"] is None,
              f"cache={cache}")

        # G4: two source IPs, 2 queries each -> each IP gets its own
        #     in-flight slot, nobody is rejected; the queued second queries
        #     of each IP are granted after ~2s and fetch upstream themselves.
        time.sleep(5.5)  # let the fresh NXDOMAIN expire
        set_mode("a", "192.0.2.72")
        r0 = dns_query_meta()
        assert r0["up"] == "1" and r0["answers"][0][1] == "192.0.2.72", \
            f"setup failed: {r0}"
        time.sleep(5.5)  # fresh A expires; stale window open
        set_mode("timeout")
        auth_before = len(auth_actions())
        res = fire_concurrent(["127.0.0.2", "127.0.0.2", "127.0.0.3", "127.0.0.3"])
        check("G4 两 IP 各 2 条并发：无人因队列满被拒",
              all(r["reason"] != "queue-full" for r in res),
              f"reasons={[r['reason'] for r in res]}")
        check("G4 每 IP 第二条排队后仍获回源（全局在途 2 被公平分享）",
              sum(1 for r in res if r["queued"] == "1") == 2
              and all(r["up"] == "1" for r in res),
              f"queued={[r['queued'] for r in res]} up={[r['up'] for r in res]}")
        check("G4 全部拿到窗口内旧 A",
              all(r["rcode"] == 0 and r["answers"]
                  and r["answers"][0][1] == "192.0.2.72" for r in res),
              f"{[(r['rcode'], r['answers']) for r in res]}")
        check("G4 回源共 4 次",
              len(auth_actions()) - auth_before == 4,
              f"auth={len(auth_actions()) - auth_before}")
        check("G4 答复带回各自来源 IP",
              sorted(r["client"] for r in res)
              == ["127.0.0.2", "127.0.0.2", "127.0.0.3", "127.0.0.3"],
              f"clients={[r['client'] for r in res]}")
        waited = [float(r["waited"].rstrip("s")) for r in res if r["queued"] == "1"]
        check("G4 排队者等待约一个上游超时（<4s 上限）",
              len(waited) == 2 and all(1.5 <= w < 4.0 for w in waited),
              f"waited={waited}")

        # -- H. web console smoke test ---------------------------------------
        print("H. 网页控制台冒烟", flush=True)
        with urllib.request.urlopen(f"http://127.0.0.1:{WEB_PORT}/", timeout=5) as r:
            body = r.read().decode()
        check("H1 主页可访问", r.status == 200 and "DNS" in body)
        req = urllib.request.Request(
            f"http://127.0.0.1:{WEB_PORT}/api/mode",
            data=json.dumps({"mode": "a", "ip": "192.0.2.60"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            ok = json.load(r)["ok"]
        check("H2 网页切换模式生效", ok and get_control_mode() == "a")
        req = urllib.request.Request(f"http://127.0.0.1:{WEB_PORT}/api/query",
                                     method="POST")
        with urllib.request.urlopen(req, timeout=15) as r:
            res = json.load(r)
        check("H3 网页发起查询并显示来源",
              res["ok"] and res["rcode"] == "NOERROR"
              and res["source"] in ("upstream", "cache-fresh")
              and res["answers"] and res["answers"][0]["data"] == "192.0.2.60",
              f"res={res.get('rcode')} src={res.get('source')}")
        req = urllib.request.Request(
            f"http://127.0.0.1:{WEB_PORT}/api/query_batch",
            data=json.dumps({"count": 4}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=20) as r:
            batch = json.load(r)
        check("H4 网页并发查询逐条显示来源/来源IP/排队/回源",
              batch["ok"] and len(batch["results"]) == 4
              and all(q["ok"] and q["rcode"] == "NOERROR" and q["client"]
                      and q["queued"] in ("0", "1") and q["up"] in ("0", "1")
                      for q in batch["results"])
              and batch["summary"]["total"] == 4
              and batch["summary"]["upstream"] >= 0,
              f"summary={batch.get('summary')}")
        with urllib.request.urlopen(
                f"http://127.0.0.1:{WEB_PORT}/api/state", timeout=5) as r:
            st = json.load(r)
        check("H5 状态接口含控制/缓存/调度/日志",
              st["control"]["mode"] == "a" and st["cache"]
              and st["resolver_stats"] and "upstream_total" in st["resolver_stats"]
              and len(st["resolver_log"]) > 0 and len(st["auth_log"]) > 0)
        check("H6 查询日志带来源 IP",
              all("client" in row for row in st["resolver_log"])
              and any(row["client"] for row in st["resolver_log"]),
              f"row={st['resolver_log'][0] if st['resolver_log'] else None}")
        req = urllib.request.Request(
            f"http://127.0.0.1:{WEB_PORT}/api/mode",
            data=json.dumps({"mode": "bogus"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=5)
            check("H7 非法模式被拒绝", False)
        except urllib.error.HTTPError as e:
            check("H7 非法模式被拒绝", e.code == 400)
    finally:
        for name in list(procs):
            stop(name)
        print(f"[selftest] logs in {TMP}", flush=True)

    print(f"\n{'=' * 60}\n结果: {len(FAILS)} 项失败" if FAILS
          else f"\n{'=' * 60}\n结果: 全部通过", flush=True)
    return 1 if FAILS else 0


def get_control_mode() -> str:
    conn = sqlite3.connect(DB, timeout=15)
    mode = conn.execute("SELECT mode FROM control WHERE id = 1").fetchone()[0]
    conn.close()
    return mode


if __name__ == "__main__":
    sys.exit(main())
