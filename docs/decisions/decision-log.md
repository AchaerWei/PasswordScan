# 决策日志 — NetSpider-Max v3 融合 Golin

## 决策 1: 选择代码级融合而非子进程包装 (2026-06-04)

### 背景
Golin (Go, 11协议, 62/100) 和 NetSpider-Max v3 (Python, 22协议, 72/100) 需要融合。原方案 B 是用 Python 驱动库模仿 Golin 思路，但无法真正利用 Golin 源码。

### 决策
选择方案 C — 代码级融合：将 Go 实现嵌入 NetSpider，Python 负责 GUI/调度/报告。

### 考虑的方案
| 方案 | 优点 | 缺点 | 为什么不选？|
|------|------|------|------------|
| A: 子进程包装 | 最快(1天), 松耦合 | 仅11协议, 进程开销 | 覆盖不足 |
| B: 驱动库对齐 | 投入产出比高 | 不利用Golin源码, Python依赖重 | 绕远路 |
| C: 代码级融合 | 最终88/100, 利用Golin源码 | 3-6周, 复杂度高 | ✅ 选它 |

### 后果
- ✅ 真正融合双方优势 (Golin质量 + NetSpider覆盖)
- ⚠️ 需要 Go 编译环境, 混合语言维护成本高
- ⚠️ Windows 上 Go→Python 桥接可能遇到 cgo 问题

### 何时重新评估
- Sprint 2 完成后评估 Go 协议的实际可靠性
- 如果 Go 子进程模式更稳定, 可退化到方案 A

## 决策 2: database.py 拆分为独立协议文件 (2026-06-04)

### 背景
database.py 1124 行, 6 个协议+3 个驱动路径混在一起。Sprint 2 要对每个协议做驱动替换, 单文件改动风险高。

### 决策
拆分为 `netspider/protocols/database/{redis,mysql,postgresql,mssql,oracle,mongodb}.py`, 保留 database.py 作为兼容层重导出。

### 考虑的方案
| 方案 | 优点 | 缺点 | 选择？|
|------|------|------|--------|
| 原地修改 | 无拆分成本 | 耦合高, 回归风险大 | ❌ |
| 拆分子模块 | 隔离, 独立验证 | 需要改所有 import 点 | ✅ 选它 |
| 微服务化 | 终极解耦 | 过度工程, 不适合 | ❌ |

### 后果
- ✅ Sprint 2 每协议驱动替换在隔离文件进行
- ⚠️ 需要找到所有 `from netspider.protocols.database import test_*` 并更新

### 何时重新评估
- 拆分后跑全量门禁, 任何回归立即回滚

## 决策 3: Sprint 粒度 — 22 个原子任务 + episodic-memory checkpoint (2026-06-04)

### 背景
原 Phase 2-4 每块 1 天 ~ 3 个月, 任务太大会中途失忆。用户要求更细粒度 + 每步记录。

### 决策
22 个 ≤30 分钟原子任务, 每步写 episodic-memory checkpoint, 失败阻塞不进下一步。

### 后果
- ✅ 随时可中断恢复 (读 memory 链即可)
- ✅ 单任务失败不影响其他
- ⚠️ 22 个任务 overhead 较大 (~10% 在写 memory)
