# 跨机构人工智能风险沟通服务

本项目在人工智能治理基础服务之上，提供**跨机构风险沟通**能力，解决联合安全评估中各方对同一风险使用不同编号、不同敏感级别，导致处置不同步（一家已隔离、另一家仍当普通提醒）的问题。

服务允许各参与机构在不暴露原始敏感内容的前提下提交事件摘要、映射本地编号、协商统一等级并确认接收；同一事件的修订全程可追溯；撤回消息不会抹除已经产生的处置义务；接收方离线期间的待办在重连后按顺序补齐。

## 核心能力

| 需求 | 实现 |
| --- | --- |
| 不暴露原始敏感内容 | 事件摘要只对**参与机构**与 admin/auditor 可见；非参与方查看返回 403。审计哈希链、状态视图只携带 `content_hash`，修订说明/撤回理由仅存摘要值 |
| 提交事件摘要 | `POST /risk/events`，生成统一 `event_id`、首版修订与内容摘要值，并按机构投递 |
| 映射本地编号 | `POST /risk/mappings`，各机构把本地编号（如 `JIA-ISO-0117`、`YI-NOTICE-8842`）挂到同一事件，编号唯一约束防止错挂 |
| 协商统一等级 | `POST /risk/level-proposals`，五级 `info/low/medium/high/critical`；各方可改票，**全部参与方对同一修订意见一致时自动定稿**，定稿后该修订锁定，调整须发起新修订 |
| 确认接收 | `POST /risk/receipts`，需 `risk:confirm`；确认高版本自动按序补齐历史版本回执 |
| 修订可追溯 | `POST /risk/events/revise` 追加不可变修订版本，重置协商状态，历史版本与内容摘要值永久保留 |
| 撤回不抹除义务 | `POST /risk/withdrawals` 仅置事件为 `withdrawn`；已生成的 `risk_obligations` 仍为 `open`，须由责任机构显式 `POST /risk/obligations/discharge` 履行 |
| 离线按序补齐 | 每个机构一条单调递增投递队列（`risk_deliveries`），`GET /risk/pending` 按序返回待办，确认后按 `revision<=N` 结清 |
| 区分提交/查看/确认权限 | 三种能力 `risk:submit`、`risk:view`、`risk:confirm`，由管理员经 `POST /risk/capabilities` 显式授予 |
| 展示未回执机构 | `GET /risk/events/{id}/status` 返回各方本地编号、当前等级主张、已回执版本、待办及 `organizations_pending_receipt` |

所有写操作都要求 `request_id` 做幂等控制，所有状态变更进入与基础服务共用的 SHA-256 哈希链审计日志，并在 SQLite 单事务内完成。

## HTTP 接口（均以 `X-Actor-Id` 标识操作者）

```
POST /risk/capabilities        管理员授权（target_actor_id, capability）
GET  /risk/capabilities?actor_id=...
POST /risk/events              提交事件（summary, proposed_level, recipient_organizations[, origin_local_reference]）
POST /risk/events/revise       追加修订（event_id, change_note[, summary, proposed_level]）
POST /risk/mappings            映射本地编号（event_id, local_reference）
POST /risk/level-proposals     主张/调整等级（event_id, revision, proposed_level, rationale）
POST /risk/withdrawals         撤回事件（event_id, reason）
POST /risk/receipts            确认接收（event_id, revision[, note]）
GET  /risk/pending             本机构按序待办
GET  /risk/obligations         本机构处置义务（?include_discharged=true）
POST /risk/obligations/discharge  履行处置义务（obligation_id[, note]）
GET  /risk/events/{id}         事件与修订（参与方见原文，其余仅摘要值）
GET  /risk/events/{id}/status  协商状态与未回执机构
```

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
PYTHONPATH=src python3 -m ai_governance_foundation.acceptance        # 基础登记链
PYTHONPATH=src python3 -m ai_governance_foundation.risk_acceptance    # 跨机构风险沟通链
```

风险沟通验收覆盖：甲已隔离（high）、乙误判普通提醒（info）→ 乙复核改判后统一为 high 并生成处置义务 → 乙离线期间甲发布修订并撤回 → 乙重连后按序看到 `submitted/level_agreed/revised/withdrawn` 待办、直接确认第 2 版自动补齐第 1 版回执 → 撤回后义务仍在并被显式履行。

## HTTP 服务

```bash
PYTHONPATH=src python3 -m ai_governance_foundation.api --database ai_governance.sqlite3 --host 127.0.0.1 --port 8080
```

服务提供健康检查和带操作者身份的业务请求，重启后 SQLite 中的事件、修订、义务、待办与审计历史继续保留。
