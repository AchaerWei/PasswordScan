# Golin ↔ NetSpider 融合实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** 将 Golin (Go, 11协议, 高质量) 源码级融合进 NetSpider-Max v3 (Python, 22协议, 广覆盖)，从 72/100 → 88/100

**Architecture:** Sprint 0 建基线 → Sprint 1 代码健康(database.py拆分) → Sprint 2 驱动替换(psycopg2/pymongo/cryptography/oracledb) → Sprint 3 Go协议补齐(agent-swarm并行) → Sprint 4 融合验证+门禁加固

**Tech Stack:** Python 3.10+, Go 1.21+, psycopg2, pymongo, cryptography, oracledb, go-ldap

**Hard Rule:** 每任务完成 → episodic-memory checkpoint → 下一任务。失败则阻塞。

---

## Sprint 0: 审计基线

### Task 0.1: Retrospective — Phase 0-1 教训提取

**Files:** `.claude/memory/retro-phase01-patterns.md`

- [ ] 用 retrospective-bot 回顾 Phase 0-1 的 8 个修复，提炼可复用模式
- [ ] episodic-memory 写入 checkpoint: `sprint0-t01-retro-done`

### Task 0.2: Golin 源码映射

**Files:** `.claude/memory/golin-code-map.md`

- [ ] 用 repo-cartographer 扫描 `/tmp/Golin`，输出：协议→文件→依赖映射
- [ ] episodic-memory 写入 checkpoint: `sprint0-t02-golin-map-done`

### Task 0.3: database.py 拆分方案

**Files:** `.claude/memory/database-split-plan.md`

- [ ] 用 refactor-lens 分析 `netspider/protocols/database.py` (1100+行)，输出拆分方案
- [ ] episodic-memory 写入 checkpoint: `sprint0-t03-split-plan-done`

### Task 0.4: 依赖风险扫描

**Files:** `.claude/memory/dependency-risk-matrix.md`

- [ ] 用 dependency-audit 扫描 NetSpider + Golin 依赖链
- [ ] episodic-memory 写入 checkpoint: `sprint0-t04-dep-risk-done`

### Task 0.5: 决策日志初始化

**Files:** `docs/decisions/decision-log.md`

- [ ] 用 decision-log 创建决策日志，记录：方案选择、Skill 使用策略、checkpoint 格式
- [ ] episodic-memory 写入 checkpoint: `sprint0-t05-decision-log-done`

---

## Sprint 1: 代码健康

### Task 1.1-1.5: database.py 拆分

**Files:** `netspider/protocols/database.py` → `netspider/protocols/{postgresql,mongodb,mysql,mssql,oracle,redis}.py`

- [ ] T1.1 拆分 PostgreSQL (SCRAM + MD5) → `postgresql.py`
- [ ] T1.2 拆分 MongoDB (SCRAM-SHA1 + SCRAM-256) → `mongodb.py`
- [ ] T1.3 拆分 MySQL (native + caching_sha2) → `mysql.py`
- [ ] T1.4 拆分 MSSQL + Oracle + Redis → 各自文件
- [ ] T1.5 `verify_weakpass.py --quick` + `test_protocols.py` 全绿

---

## Sprint 2: 驱动替换

### Task 2.1-2.6: pip + 驱动库替换

- [ ] T2.1 PostgreSQL: `psycopg2.connect()` 替代手写 SCRAM
- [ ] T2.2 MongoDB: `pymongo` 必选化
- [ ] T2.3 MySQL: `cryptography` 必选化
- [ ] T2.4 Oracle: `oracledb` 必选化
- [ ] T2.5 每协议单独验证
- [ ] T2.6 全量 `verify_dev_gate.py` + `verify_weakpass.py` (full)

---

## Sprint 3: Go 协议补齐

### Task 3.1-3.8: agent-swarm 并行

- [ ] T3.1 SNMPv1/v2c → Go
- [ ] T3.2 LDAP (多DN) → Go go-ldap
- [ ] T3.3 WinRM (NTLM) → 保留 Python 或 Go
- [ ] T3.4 HTTP Form + 厂商 Web → 保留 Python
- [ ] T3.5 VNC → Go
- [ ] T3.6 IMAP/POP3 → Go
- [ ] T3.7 RTSP → Go
- [ ] T3.8 IPMI (RAKP) → 评估

---

## Sprint 4: 融合验证

### Task 4.1-4.4: 交叉验证 + 门禁

- [ ] T4.1 Golin ↔ NetSpider 交叉验证
- [ ] T4.2 `dev-gate` 新检查编码
- [ ] T4.3 `verify_weakpass.py` Go 协议入 Tier 1
- [ ] T4.4 终验 145+ PASS, 0 FAIL, 88/100
