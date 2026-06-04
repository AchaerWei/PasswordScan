# PassScanV3 — 弱口令检测工具

网络资产弱口令自动化检测平台，支持 **22 种协议** + 6 种 Go 原生实现。

## 快速开始

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 编译 Go 协议扩展 (可选，推荐)
cd netspider/goproto && go build -o goproto.exe . && cd ../..

# 3. 运行验证
python verify_dev_gate.py              # 14 项门禁检查
python verify_weakpass.py --quick      # 快速验证 (Tier 2+3)
python verify_weakpass.py              # 全量验证 (Tier 1+2+3, 需Mock服务)
```

## 扫描使用

```bash
# 单IP扫描
python main.py --target 192.168.1.1

# 网段扫描
python main.py --target 192.168.1.0/24

# GUI 模式
python -m netspider.gui
```

## 支持的协议

| 类别 | 协议 | 实现 | 验证方式 |
|------|------|------|:---:|
| 数据库 | MySQL, PostgreSQL, MSSQL, Oracle, MongoDB, Redis | Python 驱动 | 真实连接 |
| 远程 | SSH, Telnet, FTP, RDP, VNC | Python + Go(VNC) | 握手认证 |
| Web | HTTP/S, Elasticsearch, 厂商Web(H3C/华为/Cisco) | Python | HTTP Auth |
| 邮件 | SMTP, IMAP, POP3 | Python + Go(IMAP/POP3) | LOGIN/AUTH |
| 网络 | SNMP, LDAP, SMB, WinRM, RTSP | Python + Go(SNMP/LDAP/RTSP) | 协议握手 |
| 其他 | IPMI | Python | 服务探测 |

## 目录结构

```
PassScanV3/
├── README.md                       # 本文件
├── main.py                         # CLI 入口
├── requirements.txt                # Python 依赖
├── verify_dev_gate.py              # 开发门禁 (14项)
├── verify_weakpass.py              # 三级验证 (Tier1/2/3)
├── data/                           # 资产与字典
│   ├── unified_asset_table.json    #   132厂商统一资产表
│   └── 弱口令验证密钥库_全量.txt    #   769条凭据字典
├── docs/                           # 文档
│   ├── AUDIT_REPORT.md             #   安全审计报告
│   ├── GOLIN_INTEGRATION_AUDIT.md  #   Golin 融合分析
│   └── V3_使用文档.md              #   详细使用手册
├── deploy/                         # 部署配置
├── tests/                          # 测试套件
│   ├── test_protocols.py           #   单元测试 (41项)
│   ├── full_cluster_verification.py #  集群验证
│   ├── mock_servers.py             #   Mock 服务器
│   └── cross_validate.py           #   Go-Python 交叉验证
└── netspider/                      # 核心引擎
    ├── _lib/                       #   基础库 (crypto/ber/ntlm)
    ├── protocols/                  #   协议实现
    │   └── database/               #   数据库协议 (已拆分)
    ├── goproto/                    #   Go 原生协议扩展
    ├── plugins/                    #   插件系统
    ├── engine/                     #   扫描引擎
    ├── discovery/                  #   服务发现
    ├── credentials/                #   凭据管理
    └── output/                     #   输出/报告
```

## 验证门禁

修改代码后 **必须通过** 以下检查：

```bash
python verify_dev_gate.py           # 25 PASS 必须
python verify_weakpass.py --quick   # 50 PASS 必须
```

禁止用 `--quick` 跳过 Tier 1 后宣称"全部通过"。

## 评分

| 阶段 | 评分 |
|------|:---:|
| 初始审计 | 41/100 |
| Phase 0+1 修复 | 72/100 |
| Sprint 0-4 融合 | 82/100 |

## 技术栈

- **Python 3.10+** — 主引擎 / GUI / 插件系统
- **Go 1.21+** — 高性能协议扩展 (goproto)
- **psycopg2 / pymongo / oracledb** — 数据库驱动
- **cryptography** — 密码学基础库
