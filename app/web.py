"""FastAPI operations console.

Serves a single-page console that can
  * switch the authoritative endpoint's behaviour for the fixed domain
    (A record / NXDOMAIN / delayed A / timeout),
  * fire a single real DNS query -- or a batch of concurrent real queries --
    at the resolver and show each actual reply: where it came from
    (upstream / cache-fresh / cache-stale / none), the source IP the resolver
    saw, whether it queued, how long it waited, and whether it triggered an
    upstream fetch,
  * show the resolver cache state (with live countdowns), the fair-scheduler
    counters (in-flight / queued / cumulative grants and rejections) and the
    query logs of both the resolver and the authoritative endpoint.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import time

import uvicorn
from dnslib import QTYPE, RCODE, DNSRecord
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from . import common

app = FastAPI(title="DNS duty console")

PAGE = """<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>DNS 值班控制台</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 2rem; background:#f6f7f9; color:#222; }
  h1 { font-size: 1.3rem; }
  section { background:#fff; border:1px solid #ddd; border-radius:8px;
            padding:1rem 1.2rem; margin-bottom:1rem; }
  h2 { font-size:1rem; margin-top:0; }
  label { margin-right:1rem; cursor:pointer; }
  input[type=text] { width:9rem; }
  input[type=number] { width:5rem; }
  button { padding:.35rem 1rem; cursor:pointer; }
  table { border-collapse:collapse; width:100%; font-size:.82rem; }
  th, td { border:1px solid #e2e2e2; padding:.25rem .5rem; text-align:left; }
  th { background:#f0f1f4; }
  pre { background:#0d1420; color:#cfe3ff; padding:.7rem; border-radius:6px;
        overflow:auto; font-size:.78rem; }
  .pill { display:inline-block; padding:.1rem .55rem; border-radius:1rem;
          background:#e8ecf3; font-size:.8rem; margin-right:.4rem; }
  .ok { color:#0a7a2f; } .bad { color:#b00020; } .muted { color:#777; }
  #qresult b { font-size:1.05rem; }
</style>
</head>
<body>
<h1>DNS 值班控制台 — <code id="dom">…</code></h1>
<p class="muted" id="params"></p>

<section>
  <h2>1. 权威端行为切换</h2>
  <label><input type="radio" name="mode" value="a"> A 记录</label>
  <label><input type="radio" name="mode" value="nxdomain"> NXDOMAIN</label>
  <label><input type="radio" name="mode" value="delay"> 延迟应答</label>
  <label><input type="radio" name="mode" value="timeout"> 超时（不应答）</label>
  <p>
    A 记录 IP：<input type="text" id="ip" value="192.0.2.10">
    &nbsp; 延迟秒数：<input type="number" id="delay" value="3" min="0" step="0.5">
    &nbsp; <button onclick="applyMode()">应用</button>
    <span id="modemsg"></span>
  </p>
  <p class="muted">当前权威端模式：<b id="curmode">…</b>（每 2 秒自动刷新）</p>
</section>

<section>
  <h2>2. 发起查询（经解析器）</h2>
  <p>
    <button onclick="doQuery()">单条查询 A 记录</button>
    &nbsp; &nbsp;
    并发数 <input type="number" id="batchn" value="6" min="1" max="16" style="width:4rem">
    <button onclick="doBatch()">发起一组并发查询</button>
    <span id="qmsg"></span>
  </p>
  <p class="muted">提示：先把权威端切到「超时」或「延迟」，等缓存过期后再发并发查询，
    可观察按来源 IP 的排队与回源调度（本页所有查询的来源 IP 相同，
    每 IP 在途≤1、排队≤2，其余请求按当时缓存直接答复）。</p>
  <div id="qresult"></div>
  <pre id="qraw" style="display:none"></pre>
  <div id="batchresult"></div>
</section>

<section>
  <h2>3. 解析器缓存与回源调度状态</h2>
  <div id="cache">…</div>
  <p id="sched"></p>
</section>

<section>
  <h2>4. 解析器查询日志（最近 15 条）</h2>
  <table id="rlog"><thead><tr>
    <th>时间</th><th>来源IP</th><th>名称</th><th>类型</th><th>来源</th><th>RCODE</th><th>答复</th><th>说明</th>
  </tr></thead><tbody></tbody></table>
</section>

<section>
  <h2>5. 权威端接收日志（最近 15 条）</h2>
  <table id="alog"><thead><tr>
    <th>时间</th><th>名称</th><th>类型</th><th>模式</th><th>动作</th><th>说明</th>
  </tr></thead><tbody></tbody></table>
</section>

<script>
let serverOffset = 0;  // server_now - client_now

function fmtTs(ts) {
  return new Date((ts) * 1000).toLocaleTimeString();
}
function countdown(ts) {
  const left = ts - (Date.now() / 1000 + serverOffset);
  if (left <= 0) return '<span class="bad">已过期</span>';
  return '<span class="ok">剩 ' + left.toFixed(1) + 's</span>';
}

async function refresh() {
  try {
    const s = await (await fetch('/api/state')).json();
    serverOffset = s.now - Date.now() / 1000;
    document.getElementById('dom').textContent = s.domain;
    document.getElementById('params').textContent =
      `成功答复 TTL=${s.params.fresh_ttl}s · 过期后旧 A 最多沿用 ${s.params.stale_window}s` +
      ` · 上游超时 ${s.params.upstream_timeout}s` +
      ` · 回源调度：全局在途≤${s.params.max_inflight_total}` +
      ` · 每IP在途≤${s.params.max_inflight_per_ip}、排队≤${s.params.max_queued_per_ip}` +
      ` · 排队等待≤${s.params.queue_wait_max}s`;
    const c = s.control;
    if (c) {
      document.getElementById('curmode').textContent =
        `${c.mode}（A=${c.ip}，延迟=${c.delay_seconds}s，更新于 ${fmtTs(c.updated_at)}）`;
      document.querySelector(`input[name=mode][value=${c.mode}]`).checked = true;
      if (document.activeElement.id !== 'ip') document.getElementById('ip').value = c.ip;
      if (document.activeElement.id !== 'delay')
        document.getElementById('delay').value = c.delay_seconds;
    }
    const k = s.cache;
    document.getElementById('cache').innerHTML = k ?
      `<span class="pill">rcode=${k.rcode}</span>` +
      (k.a_record ? `<span class="pill">A=${k.a_record}</span>` : '<span class="pill">无 A 记录</span>') +
      `<span class="pill">fresh: ${countdown(k.fresh_until)}</span>` +
      (k.stale_until ? `<span class="pill">stale: ${countdown(k.stale_until)}</span>`
                     : '<span class="pill">无 stale 备用</span>') +
      (k.nx_confirmed_at ? `<span class="pill">NXDOMAIN 确认于 ${fmtTs(k.nx_confirmed_at)}</span>` : '')
      : '<span class="muted">（缓存为空）</span>';
    const st = s.resolver_stats;
    document.getElementById('sched').innerHTML = st ?
      `<span class="pill">在途回源 ${st.inflight}/${s.params.max_inflight_total}</span>` +
      `<span class="pill">当前排队 ${st.queued}</span>` +
      `<span class="pill">累计回源 ${st.upstream_total}</span>` +
      `<span class="pill">立即授权 ${st.grant_immediate_total}</span>` +
      `<span class="pill">排队授权 ${st.grant_queued_total}</span>` +
      `<span class="pill">队列满拒绝 ${st.rejected_total}</span>` +
      `<span class="pill">等待超时 ${st.wait_timeout_total}</span>` : '';
    fillLog('rlog', s.resolver_log, r =>
      [fmtTs(r.ts), r.client || '', r.qname, r.qtype, r.source, r.rcode, r.answers, r.detail]);
    fillLog('alog', s.auth_log, r =>
      [fmtTs(r.ts), r.qname, r.qtype, r.mode, r.action, r.detail]);
  } catch (e) { console.log(e); }
}

function fillLog(id, rows, cols) {
  const tb = document.querySelector('#' + id + ' tbody');
  tb.innerHTML = rows.map(r =>
    '<tr>' + cols(r).map(x => `<td>${x ?? ''}</td>`).join('') + '</tr>').join('');
}

async function applyMode() {
  const mode = document.querySelector('input[name=mode]:checked').value;
  const body = { mode, ip: document.getElementById('ip').value,
                 delay_seconds: parseFloat(document.getElementById('delay').value) };
  const r = await (await fetch('/api/mode', { method: 'POST',
    headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body) })).json();
  document.getElementById('modemsg').textContent = r.ok ? ' ✔ 已切换' : ' ✘ ' + r.error;
  refresh();
}

async function doQuery() {
  document.getElementById('qmsg').textContent = ' 查询中…';
  const r = await (await fetch('/api/query', {method: 'POST'})).json();
  document.getElementById('qmsg').textContent = '';
  const el = document.getElementById('qresult');
  if (!r.ok) { el.innerHTML = '<b class="bad">查询失败：' + r.error + '</b>'; return; }
  const ans = r.answers.length
    ? r.answers.map(a => `${a.type} ${a.data} <span class="muted">TTL=${a.ttl}s</span>`).join('，')
    : '（无应答记录）';
  el.innerHTML = `<p><b>${r.rcode}</b> &nbsp; ${ans} &nbsp; ` +
    `<span class="pill">来源：${r.source}</span> ` +
    `<span class="pill">来源IP：${r.client}</span> ` +
    `<span class="muted">${r.elapsed_ms}ms · ${r.meta.join(' ')}</span></p>`;
  const raw = document.getElementById('qraw');
  raw.style.display = 'block';
  raw.textContent = r.raw;
  refresh();
}

async function doBatch() {
  const n = parseInt(document.getElementById('batchn').value || '6', 10);
  document.getElementById('qmsg').textContent = ` 并发查询 ${n} 条中…`;
  const r = await (await fetch('/api/query_batch', {method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({count: n})})).json();
  document.getElementById('qmsg').textContent = '';
  const el = document.getElementById('batchresult');
  if (!r.ok) { el.innerHTML = '<b class="bad">并发查询失败</b>'; return; }
  const s = r.summary;
  let html = `<p><span class="pill">共 ${s.total} 条</span>` +
    `<span class="pill">回源 ${s.upstream} 次</span>` +
    `<span class="pill">排队 ${s.queued} 条</span>` +
    `<span class="pill">未回源（队列满/等待超时） ${s.no_fetch} 条</span></p>`;
  html += '<table><thead><tr><th>#</th><th>RCODE</th><th>答复</th><th>来源</th>' +
    '<th>来源IP</th><th>排队</th><th>等待</th><th>回源</th><th>原因</th><th>耗时</th>' +
    '</tr></thead><tbody>';
  r.results.forEach((q, i) => {
    if (!q.ok) {
      html += `<tr><td>${i + 1}</td><td colspan="9" class="bad">${q.error}</td></tr>`;
      return;
    }
    const ans = q.answers.length
      ? q.answers.map(a => `${a.data} <span class="muted">TTL=${a.ttl}s</span>`).join('，')
      : '—';
    html += `<tr><td>${i + 1}</td><td>${q.rcode}</td><td>${ans}</td>` +
      `<td>${q.source}</td><td>${q.client}</td>` +
      `<td>${q.queued === '1' ? '是' : '否'}</td><td>${q.waited}</td>` +
      `<td>${q.up === '1' ? '是' : '否'}</td><td>${q.reason || '—'}</td>` +
      `<td>${q.elapsed_ms}ms</td></tr>`;
  });
  html += '</tbody></table>';
  el.innerHTML = html;
  refresh();
}

setInterval(refresh, 2000);
refresh();
</script>
</body>
</html>
"""


class ModeIn(BaseModel):
    mode: str
    ip: str | None = None
    delay_seconds: float | None = None


class BatchIn(BaseModel):
    count: int = 6


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return PAGE


@app.get("/api/state")
def state() -> dict:
    return {
        "now": time.time(),
        "domain": common.FQDN,
        "params": {
            "fresh_ttl": common.FRESH_TTL,
            "stale_window": common.STALE_WINDOW,
            "upstream_timeout": common.UPSTREAM_TIMEOUT,
            "max_inflight_total": common.MAX_INFLIGHT_TOTAL,
            "max_inflight_per_ip": common.MAX_INFLIGHT_PER_IP,
            "max_queued_per_ip": common.MAX_QUEUED_PER_IP,
            "queue_wait_max": common.QUEUE_WAIT_MAX,
        },
        "control": common.get_control(),
        "cache": common.get_cache(),
        "resolver_stats": common.get_resolver_stats(),
        "resolver_log": common.recent("query_log"),
        "auth_log": common.recent("auth_log"),
    }


@app.post("/api/mode")
def set_mode(m: ModeIn):
    if m.mode not in ("a", "nxdomain", "delay", "timeout"):
        return JSONResponse({"ok": False, "error": f"unknown mode {m.mode!r}"}, 400)
    cur = common.get_control() or {"ip": common.DEFAULT_IP,
                                   "delay_seconds": common.DEFAULT_DELAY}
    ip = m.ip if m.ip is not None else cur["ip"]
    delay = m.delay_seconds if m.delay_seconds is not None else cur["delay_seconds"]
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return JSONResponse({"ok": False, "error": f"bad IPv4 address {ip!r}"}, 400)
    if not (0 <= float(delay) <= 60):
        return JSONResponse({"ok": False, "error": "delay must be 0..60s"}, 400)
    common.set_control(m.mode, ip, float(delay))
    return {"ok": True, "control": common.get_control()}


def _one_query() -> dict:
    """Fire one real A query at the resolver and report the actual reply."""
    query = DNSRecord.question(common.FQDN, "A")
    t0 = time.time()
    try:
        data = query.send(
            common.RESOLVER_HOST, common.RESOLVER_PORT,
            timeout=common.QUEUE_WAIT_MAX + common.UPSTREAM_TIMEOUT + 4,
        )
        rep = DNSRecord.parse(data)
    except Exception as exc:  # noqa: BLE001 - report any transport failure
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    answers = [
        {"name": str(rr.rname), "type": QTYPE[rr.rtype], "data": str(rr.rdata),
         "ttl": rr.ttl}
        for rr in rep.rr
    ]
    txts = [str(rr.rdata).strip('"') for rr in rep.ar if rr.rtype == QTYPE.TXT]
    kv = {}
    for t in txts:
        for tok in t.split():
            if "=" in tok:
                k, v = tok.split("=", 1)
                kv[k] = v
    return {
        "ok": True,
        "rcode": RCODE[rep.header.rcode],
        "answers": answers,
        "source": kv.get("source", "unknown"),
        "client": kv.get("client", "?"),
        "queued": kv.get("queued", "0"),
        "waited": kv.get("waited", "0s"),
        "up": kv.get("up", "0"),
        "reason": kv.get("reason", ""),
        "meta": txts,
        "elapsed_ms": int((time.time() - t0) * 1000),
        "raw": str(rep),
    }


@app.post("/api/query")
def do_query() -> dict:
    """Fire a single real A query at the resolver and report the reply."""
    return _one_query()


@app.post("/api/query_batch")
def query_batch(b: BatchIn) -> dict:
    """Fire a batch of concurrent real A queries at the resolver.

    All of them leave from this console's source IP, so the resolver's
    per-source-IP fair scheduling (<=1 in-flight, <=2 queued per IP) is
    directly visible in the per-query results.
    """
    n = max(1, min(16, int(b.count)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
        results = list(ex.map(lambda _: _one_query(), range(n)))
    summary = {
        "total": n,
        "upstream": sum(1 for r in results if r.get("up") == "1"),
        "queued": sum(1 for r in results if r.get("queued") == "1"),
        "no_fetch": sum(1 for r in results
                        if r.get("reason") in ("queue-full", "wait-timeout")),
    }
    return {"ok": True, "results": results, "summary": summary}


def main() -> None:
    common.init_db()
    uvicorn.run(app, host="0.0.0.0", port=common.WEB_PORT, log_level="warning")


if __name__ == "__main__":
    main()
