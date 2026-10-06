# 跨机构人工智能风险沟通服务

本项目提供人工智能治理协作的服务端基础能力，用于登记主体、任务、权限、风险事件和结构化证据；并支持多家机构在**不暴露原始敏感内容**的前提下沟通同一风险事件：提交脱敏摘要、映射本地编号与本地敏感级别、协商统一等级、按顺序完成处置回执。服务通过角色权限、请求幂等、SQLite 事务与哈希链审计保持业务状态一致。

## 风险沟通能力

- **数据最小化**：只接受脱敏摘要 `sanitized_summary` 与可选的内容指纹 `content_hash`；边界拒绝 `raw_content`、`original_content`、`sensitive_content` 等原始内容字段，审计日志只记录摘要哈希。
- **本地编号映射**：各机构通过 `/risk/incidents/{id}/local-references` 把自己的编号与本地敏感级别（如“隔离”“普通提醒”）并排映射到同一事件，互不覆盖。
- **统一等级协商**：标准等级为 `info/low/medium/high/critical`；各参与方主张追加留痕，全员最新主张一致时在当前版本定格 `agreed_level`，修订后重新协商。
- **修订可追溯**：每次修订生成不可变版本快照（`risk_incident_versions`），历史摘要、提案与主张均可回溯。
- **撤回不抹除义务**：撤回只把事件与现存通告置为 tombstone，并向各机构追加一条 `after_withdrawal` 撤回通告；**撤回通告仍须回执**，处置义务不消失。
- **离线顺序补齐**：每个机构有单调递增的 outbox 序号；接收方用 `after_sequence` 游标拉取，离线期间积压的通告在重连后按序补齐；同一事件内须按 `ordinal` 顺序回执，不得跳号。
- **三类权限分离**：
  - 提交（operator/admin）：提交/修订/撤回事件、映射编号、提出等级主张；
  - 查看（operator/reviewer/admin）：查看事件与待办、回执状态；
  - 确认（reviewer/admin）：代表机构确认通告；
  - auditor 无业务视图，非参与方访问得到“不存在”，避免跨机构探测。
- **回执看板**：`/risk/incidents/{id}/receipt-status` 展示每家机构总义务数、已回执数及尚未完成的待办，含撤回后仍待确认的义务。

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/risk/incidents` | 提交脱敏风险事件并通告接收机构 |
| POST | `/risk/incidents/{id}/revisions` | 发起机构修订事件（生成新版本） |
| POST | `/risk/incidents/{id}/withdrawal` | 发起机构撤回事件（义务保留） |
| POST | `/risk/incidents/{id}/local-references` | 映射本机构编号与本地敏感级别 |
| POST | `/risk/incidents/{id}/level-proposals` | 提出/变更统一等级主张 |
| GET | `/risk/incidents/{id}` | 查看事件、版本、映射、主张与当前定格等级 |
| GET | `/risk/incidents/{id}/receipt-status` | 查看各机构回执完成情况 |
| GET | `/risk/pending?after_sequence=&limit=` | 按机构顺序拉取待办/补齐离线积压 |
| POST | `/risk/advisories/{advisory_id}/acknowledgements` | 确认一条通告（含撤回通告） |

所有写接口沿用 `request_id` 幂等：相同 `request_id` + 相同请求体返回原始收据（`replayed=true`），不同内容返回冲突。

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
PYTHONPATH=src python3 -m ai_governance_foundation.acceptance
```

## HTTP 服务

```bash
PYTHONPATH=src python3 -m ai_governance_foundation.api --database ai_governance.sqlite3 --host 127.0.0.1 --port 8080
```

服务提供健康检查和带操作者身份（`X-Actor-Id` 头）的业务请求，重启后 SQLite 中的状态、未完成处置义务与审计历史继续保留。
