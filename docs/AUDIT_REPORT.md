# 弱口令检测工具 — 完整代码审计报告

**审计日期**: 2026-05-26  
**审计类型**: 白盒代码审计 + 模拟服务验证  
**代码版本**: weak_pass_scanner_gui.py v2 (3373行)  
**验证范围**: 16个协议测试器 + 凭据字典 + 扫描引擎 + GUI  

---

## 审计方法

1. **静态分析**: 逐行审查所有 tester 函数的协议实现
2. **单元测试**: 运行 test_protocols.py (38项全部通过)
3. **模拟服务验证**: 运行 _validate_scanner.py (32项全部通过) + 自定义 deep_audit_verification.py
4. **密码学验证**: 对比已知测试向量验证算法正确性
5. **覆盖完整性**: 检查 TESTER_MAP、SVC_TO_CREDGROUP、NAMED_PORTS 之间的一致性

---

## 一、BUG 汇总

### BUG-1 🔴 CRITICAL: MySQL native_password 算法实现错误

**文件**: `weak_pass_scanner_gui.py:766-795`  
**影响**: 对所有使用 mysql_native_password 的 MySQL 服务器 100% 漏报(FN)

**根因**: `_mysql_native_auth()` 中的密码哈希算法与 MySQL 协议规范不符。

正确算法(MySQL官方):
```
SHA1(password) → stage1
SHA1(stage1) → stage2
response = XOR(stage1, SHA1(scramble + stage2))
```

当前实现:
```python
hash1 = SHA1(password)
hash2 = SHA1(hash1)
scrambled = hash1 XOR hash2       # 无意义的XOR
hash3 = SHA1(scrambled)            # 对无意义值取哈希
response = hash3 XOR hash2 XOR auth_data  # 错误的三重XOR
```

**验证**: 用已知测试向量对比，输出完全不匹配(hex值完全不同)。模拟MySQL服务器验证：正确凭据 `root/root123` 期望返回 True，实际返回 False。

**影响范围**: MySQL 5.x 全系列(默认 native_password)、MySQL 8.0 配置 native_password 的实例。`caching_sha2_password` 路径(MySQL 8.0默认)未受影响。

---

### BUG-2 🔴 CRITICAL: test_oracle 完全忽略凭据参数

**文件**: `weak_pass_scanner_gui.py:1411-1432`  
**影响**: 对所有 Oracle TNS 监听器 100% 误报(FP)

**根因**: 函数参数 `user` 和 `pwd` 在函数体中从未被使用。它仅做 TNS CONNECT 探测定性(检测端口是否为 Oracle)，无论传什么凭据都返回 True。

```python
def test_oracle(ip, port, user, pwd) -> bool:  # user/pwd 从未使用!
    ...
    if pkt_type in (2, 5, 11):  # 只要响应类型是ACCEPT/REDIRECT/RESEND
        return True              # 就返回True —— 无视user/pwd!
    if pkt_type == 4:
        return True
```

**影响范围**: 字典中所有匹配到 oracle 服务的组合(56条database组凭据)都会误报为成功。

---

### BUG-3 🟠 HIGH: PostgreSQL 不支持 SCRAM-SHA-256

**文件**: `weak_pass_scanner_gui.py:935-985`  
**影响**: 对所有 PostgreSQL 10+ 服务器(默认 SCRAM-SHA-256) 100% 漏报(FN)

**根因**: `test_postgresql` 仅处理 `auth_type == 0`(无认证)和 `auth_type == 5`(MD5)。遇到 `auth_type == 10`(SCRAM-SHA-256)时直接 `return False`。

**验证**: 模拟 PG14 服务器返回 SCRAM-SHA-256 认证请求, 正确凭据 `postgres/postgres` 返回 False。

**影响范围**: PostgreSQL 10(2017年发布)+ 所有版本。仅 PG 9.x 和老版本使用 MD5 的实例可被测试。

---

### BUG-4 🟠 HIGH: RDP NLA 认证误判偏向

**文件**: `weak_pass_scanner_gui.py:2582-2594`  
**影响**: 多种异常路径返回 True，导致误报

**根因**: `_rdp_nla_auth` 的最终响应解析逻辑存在严重偏向:

```python
try:
    resp2 = tls_sock.recv(4096)
    if resp2 and len(resp2) > 4:
        spnego_final = _rdp_parse_tsrequest(resp2)
        if spnego_final:
            inner = _spnego_unwrap(spnego_final)
            if inner and len(inner) >= 8:
                ftype = struct.unpack('<I', inner[8:12])[0]
                if ftype == 2:
                    return False
    return True       # <-- 默认返回True!
except Exception:
    return True       # <-- 异常也返回True!
```

只有显式检测到 NTLM Challenge(type=2)才判失败；其他所有情况(空响应、解析失败、数据不完整)均判成功。

---

### BUG-5 🟠 HIGH: MSSQL 加密标志误判

**文件**: `weak_pass_scanner_gui.py:1245-1263`  
**影响**: 错误跳过支持加密但不强制加密的 MSSQL 服务器

**根因**: `_parse_tds_prelogin_encryption` 将 `ENCRYPT_ON(0x01)` 当作 `ENCRYPT_REQ(0x08)`:

```python
# 注释声称 0x01 = ENCRYPT_REQ, 但实际 0x01 = ENCRYPT_ON(加密可用,可选)
return len(val) > 0 and val[0] == 0x01
```

TDS 协议中: 0x01=ENCRYPT_ON(可选), 0x08=ENCRYPT_REQ(强制)。许多 MSSQL 服务器返回 0x01 表示支持加密但登录可以不加密，当前代码会错误跳过这些服务器。

---

### BUG-6 🟡 MEDIUM: _test_mongodb_scram 死代码

**文件**: `weak_pass_scanner_gui.py:1776-1782`  
**影响**: 逻辑错误，特定代码路径永不可达

```python
ok = _bson_get_int32(doc, 'ok')
if ok != 1:               # ok 确认 != 1
    done = _bson_get_bool(doc, 'done')
    if done and ok == 1:  # ok == 1 永远为 False!
        return True
```

`if done and ok == 1` 在 `ok != 1` 的条件下永不为真，该分支为死代码。虽不直接影响功能，但表明该区域未经充分测试。

---

## 二、覆盖缺失

### 缺失-1 🟠 HIGH: elasticsearch 无测试器

- 端口 9200 映射:`"elasticsearch"`，在 NAMED_PORTS 中有定义
- SVC_TO_CREDGROUP 中 `"elasticsearch"` 路由了 database + middleware + general 组
- 实际可路由 **104 条凭据** 
- 但 TESTER_MAP 中没有 `"elasticsearch"` 条目
- **扫描到 Elasticsearch 服务时静默跳过，显示"(需手动测试)"**

### 缺失-2 🟠 HIGH: winrm 无测试器

- 端口 5985/5986 映射: `"winrm"`
- SVC_TO_CREDGROUP 路由了 remote + general 组，**41 条凭据**可用
- 同样无 tester 函数

### 缺失-3 🟡 MEDIUM: memcached 完全无覆盖

- 端口 11211: 无 tester + 无 credgroup
- 但 memcached 通常无认证机制，影响有限

### 缺失-4 🟡 MEDIUM: "高频纯密码 Top 150" 静默丢弃

- TXT 文件第 1263 行: `# 第十六大类：高频纯密码 Top 150 (无用户名，用于喷洒攻击)`
- 这些条目没有用户名(纯密码)，加载时因 `if ':' not in line` 被跳过
- "general" 分组凭据数为 **0**
- **150 条高频密码完全丢失**，无法用于密码喷洒攻击

---

## 三、测试覆盖率评估

### 现有测试通过率

| 测试套件 | 结果 |
|---------|------|
| test_protocols.py (单元测试) | 38/38 PASS |
| _validate_scanner.py (模拟服务) | 32/32 PASS |
| deep_audit_verification.py (Bug验证) | 5 FAIL (确认Bug存在) |

### 未覆盖的测试场景

| 协议 | 模拟验证 | 真实服务 | 备注 |
|------|---------|---------|------|
| MySQL | ✅ Bug确认 | ❌ | native_password算法错误 |
| Oracle | ✅ 代码确认 | ❌ | 忽略凭据的FP |
| PostgreSQL SCRAM | ✅ Bug确认 | ❌ | 现代PG全漏报 |
| RDP NLA | ⚠️ 部分 | ❌ | 误判偏向 |
| MSSQL TLS | ❌ | ❌ | 加密标志误判 |
| Elasticsearch | ❌ | ❌ | 无tester |
| WinRM | ❌ | ❌ | 无tester |
| memcached | ❌ | ❌ | 无tester |

---

## 四、建议修复顺序

| 优先级 | Bug | 修复方案 | 工时 |
|--------|-----|---------|------|
| P0 | MySQL native_auth 算法 | 重写为正确算法 `XOR(SHA1(pwd), SHA1(scramble+SHA1(SHA1(pwd))))` | 30min |
| P0 | Oracle 忽略凭据 | 实现真正的 Oracle AUTH 协议(需 TNS AUTH 握手)或标记为"仅检测" | 4-8hr |
| P1 | PostgreSQL SCRAM | 添加 auth_type==10 的 SCRAM-SHA-256 处理 | 2-4hr |
| P1 | RDP NLA 误判 | 最终响应默认为 False，仅明确成功时返回 True | 30min |
| P1 | MSSQL 加密标志 | 修正为 `val[0] & 0x08`(ENCRYPT_REQ) | 10min |
| P2 | elasticsearch tester | 添加 ES 的 Basic Auth / API Key 测试 | 2hr |
| P2 | winrm tester | 添加 WinRM NTLM/Kerberos 测试或使用 pywinrm | 2hr |
| P2 | 高频纯密码丢失 | 将此150条密码与常见用户名交叉组合生成凭据对 | 1hr |
| P3 | MongoDB 死代码 | 清理不可达分支 `if done and ok==1` | 5min |

---

## 五、正面评估

该工具在以下方面表现优秀:

1. **协议实现深度高**: 自主实现了 MySQL(含 caching_sha2)、MongoDB(SCRAM)、MSSQL(TDS)、RDP(CredSSP/NLA) 等复杂二进制协议，减少了对第三方库的依赖
2. **防误判机制有效**: HTTP 两阶段验证、Telnet 严格提示词检查设计良好
3. **凭据智能路由**: SVC_TO_CREDGROUP 按设备类型分组，避免无意义的跨类测试
4. **测试框架完善**: _validate_scanner.py 和 test_protocols.py 提供了系统化的验证体系
5. **密码字典全面**: 769 条凭据覆盖 16 大类设备(网络/安全/摄像头/打印机/DB/中间件/Web/工控等)

---

## 六、已修复项 (2026-05-27)

| 项目 | 状态 | 说明 |
|------|------|------|
| PostgreSQL SCRAM-SHA-256 | ✅ 已修复 | 新增 `_pg_scram_auth` 完整 HMAC 链, auth_type==10 路径 |
| RDP NLA 误判偏向 | ✅ 已修复 | 最终响应默认返回 False, 仅明确成功(AUTH_ACCEPT)返回 True |
| Elasticsearch tester | ✅ 已实现 | Basic Auth 测试 + NAMED_PORTS:9200 |
| WinRM tester | ✅ 已实现 | NTLMSSP/SPNEGO over HTTP 401 Negotiate |
| 凭据路由缺失 (ics/security/printer) | ✅ 已修复 | SVC_TO_CREDGROUP 扩展覆盖 |
| NAMED_PORTS 端口盲区 | ✅ 已修复 | 18 个 HTTP 可管理端口已加入 (3000..18083) |
| 高频纯密码 150 条丢失 | ✅ 已修复 | "general" 分组凭据数 0→150, 密码喷洒可用 |
| 字典 vs 调研表交叉比对 | ✅ 已完成 | 15 条遗漏凭据已从调研表提取并加入字典 |
| Telnet IAC 协商干扰 | ✅ 已修复 | 扫描器静默剥离 IAC, 不再发送 WONT/DONT 响应 |
| MySQL native_password 算法 | ✅ 已修复 | 重写为正确 XOR 算法, 全量验证通过 |

### 硬限制 (文档化, 暂不支持)

| 协议 | 原因 |
|------|------|
| Oracle AUTH (凭据验证) | 需 python-oracledb + Oracle Instant Client, TNS CONNECT 可检测服务存活 |
| S7comm (102), Modbus (502), EtherNet/IP (44818) | ICS 专用协议, 无 tester |
| SNMPv3 | 仅支持 SNMPv1/v2c community |
| ONVIF | 无专用 tester |
| Memcached (11211) | 通常无认证, 低优先级 |

*最后更新: 2026-05-27 | 验证: test_protocols.py(38/38) + full_cluster_verification.py(39/39)*
