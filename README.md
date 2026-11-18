# DNS 值班解析系统（serve-stale 演练）

平台值班场景：内部服务的权威 DNS 失联时，解析器继续为已确认的地址提供解析，
但记录被删除（NXDOMAIN）后绝不把旧地址交给调用方。权威端延迟/失联时，
解析器按**来源 IP 公平调度回源名额**，单个客户端的连续过期查询不会占满回源。

## 组成

| 服务 | 模块 | 端口 | 说明 |
|---|---|---|---|
| `auth` | `app.auth_server` | UDP 5354 | 本地权威端，行为可由网页实时切换 |
| `resolver` | `app.resolver` | UDP 5353 | 缓存/serve-stale UDP 解析器（含公平回源调度） |
| `web` | `app.web` | HTTP 8000 | FastAPI 操作网页 |

三者通过共享卷上的 SQLite（WAL 模式）协作：`control` 表存权威端行为，
`cache` 表存解析器缓存（**绝对时间戳**），`resolver_stats` 表存调度器计数器，
`query_log`/`auth_log` 表供网页展示。

## 运行

```bash
docker compose up --build
# 网页:  http://localhost:8000
# 查询:  dig @127.0.0.1 -p 5353 service.example A
```

无 Docker 的本地运行（等价三进程）：

```bash
pip install -r requirements.txt
DB_PATH=/tmp/dns/app.db AUTH_PORT=15354 python -m app.auth_server &
DB_PATH=/tmp/dns/app.db RESOLVER_PORT=15353 AUTH_PORT=15354 python -m app.resolver &
DB_PATH=/tmp/dns/app.db RESOLVER_PORT=15353 WEB_PORT=8000 python -m app.web &
```

自测（自动拉起三进程，跑全部关键交错，约 2 分钟）：

```bash
python tests/selftest.py
```

## 语义（默认值，可用环境变量调整）

- 成功答复 TTL = **5 秒**（`FRESH_TTL`），缓存命中时 TTL 倒数。
- 过期后重新回源；上游超时（`UPSTREAM_TIMEOUT`=2s）时旧 A 最多沿用 **20 秒**
  （`STALE_WINDOW`），应答 TTL 为剩余可用时长；超过即 **SERVFAIL**。
- **NXDOMAIN 只作 5 秒新鲜缓存，绝不作过期备用**：过期+上游超时 → SERVFAIL。
- 解析器确认 NXDOMAIN 时**立即持久清除旧 A**：此后任何答复都不再含旧 A。
- 每次回源用**独立 socket + 随机事务 ID + 问题匹配**，超时后迟到的旧答复
  无人接收、也不会被错配给后续查询，因此无法复活旧记录。
- 缓存期限以绝对 epoch 存于 SQLite，**重启不延长旧 A 的有效期**
  （窗口继续倒数，不会重新计时）。

### 按来源 IP 公平的回源调度

新鲜缓存仍立即答复（不经调度）。缓存过期后的回源请求一律经过调度器：

- **全局最多 2 次在途回源**（`MAX_INFLIGHT_TOTAL`）。
- **每个来源 IP 至多 1 条在途、2 条排队**（`MAX_INFLIGHT_PER_IP` /
  `MAX_QUEUED_PER_IP`）——单个客户端连续发起过期查询不会占满全局回源名额。
- 空出的名额**按来源 IP 轮流**授予排队者（每个来源每轮一个，按入队顺序）。
- **队列已满**或**排队等待超过 4 秒**（`QUEUE_WAIT_MAX`）的请求不再回源，
  按*当时*缓存答复：仍在原 20 秒窗口内的旧 A，否则 SERVFAIL。
- 排队期间若其他在途回源**刷新了 A 或确认了 NXDOMAIN**，等待者获授权时
  先复查缓存、直接按当前缓存答复（不再回源），**绝不再发出已清除的旧 A**。

网页可切换权威端行为：`a`（可改 IP）/ `nxdomain` / `delay`（延迟应答，默认 3s，
大于上游超时，用于演练迟到应答）/ `timeout`（不应答，模拟权威端失联）。
网页可发起**单条或一组并发**真实 DNS 查询，逐条展示实际答复（rcode、应答、TTL）、
**来源 IP**、是否**排队**、排队等待时长、是否触发**回源**（由解析器在
additional 段 TXT `_src.<域名>` 中带回），并展示调度器计数器
（在途/排队/累计回源/队列满拒绝/等待超时）与双方日志。

固定域名默认 `service.example`（`FIXED_DOMAIN` 可改）。解析器只服务该域名，
其余名称 REFUSED，非 A 查询返回 NODATA。

## 文件

```
app/common.py       配置 + SQLite 状态面（含 resolver_stats 调度计数器）
app/auth_server.py  可控权威端（dnslib 编解码，线程并发）
app/resolver.py     缓存/serve-stale 解析器 + 按来源 IP 公平的回源调度器
app/web.py          FastAPI 操作网页（单条/并发查询、调度状态）
tests/selftest.py   端到端自测（A–H 八组场景，含调度器单元与并发端到端）
Dockerfile / docker-compose.yml / requirements.txt
```
