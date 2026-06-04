# Golin ↔ NetSpider 融合方案 v2

**日期**: 2026-06-04 | **状态**: 执行中 | **取代**: Phase 2-4 原计划

## 核心决策

原方案 B（Python 驱动库对齐）废弃。采用**代码级融合**：Golin Go 源码嵌入 NetSpider，Python 负责 GUI/调度/报告。

## 新增 Skill 利用

| Skill | 用途 |
|-------|------|
| `migration-buddy` | Go 迁移策略 |
| `agent-swarm` | 多协议并行移植 |
| `refactor-lens` | database.py 拆分 |
| `dependency-audit` | 依赖风险扫描 |
| `retrospective-bot` | Phase 0-1 教训提取 |
| `repo-cartographer` | Golin 源码映射 |
| `decision-log` | 架构决策追踪 |
| `dev-gate` | 门禁检查编码 |
| `episodic-memory` | 每任务 checkpoint |

## Sprint 结构

```
Sprint 0: 审计基线 (5 tasks) → 看清再动手
Sprint 1: 代码健康 (5 tasks) → database.py 拆分
Sprint 2: 驱动替换 (6 tasks) → psycopg2/pymongo/cryptography/oracledb
Sprint 3: Go 协议补齐 (8 tasks) → SNMP/LDAP/WinRM/VNC/IMAP/POP3/RTSP/IPMI
Sprint 4: 融合验证 (4 tasks) → 交叉验证 + 门禁加固
```

## 验收标准

- verify_dev_gate.py: 12/12 PASS
- verify_weakpass.py (full): 24+ PASS, 0 FAIL
- test_protocols.py: 41+ PASS, 0 FAIL
- 综合评分: 88/100
