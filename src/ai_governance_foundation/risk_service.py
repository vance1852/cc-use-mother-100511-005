"""提供跨机构风险事件沟通、编号映射、等级协商与回执能力。

设计要点：

* 事件正文（摘要）只对参与机构可见，跨机构审计与状态视图只携带内容摘要值；
* 每个事件由不可变修订版本组成，修订、等级协商、撤回都进入审计哈希链；
* 撤回只改变事件状态，已经生成的处置义务保持有效；
* 接收方离线期间的消息进入按机构递增的投递序列，重新连接后按序补齐；
* 写权限按 risk:submit / risk:view / risk:confirm 三种能力显式授权。
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Callable

from .audit import append_event, canonical_json, digest
from .clock import Clock, SystemClock
from .errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .models import PendingDelivery, RiskEventView, RiskReceiptView, RiskRevision, WriteReceipt
from .storage import Database

CAPABILITIES = frozenset({"risk:submit", "risk:view", "risk:confirm"})
LEVELS = ("info", "low", "medium", "high", "critical")
LEVEL_RANK = {level: index for index, level in enumerate(LEVELS)}
ACK_DELIVERY_KINDS = ("submitted", "revised", "level_agreed", "withdrawn")
IDENTIFIER_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-"


class RiskService:
    """协调风险沟通的权限、版本、义务、投递顺序与审计规则。"""

    def __init__(self, database: Database, clock: Clock | None = None) -> None:
        self.database = database
        self.clock = clock or SystemClock()

    def _now(self) -> str:
        return self.clock.now().isoformat().replace("+00:00", "Z")

    # ------------------------------------------------------------------ 基础校验

    def _identifier(self, value: str, field: str) -> str:
        value = str(value).strip()
        if not value or len(value) > 64 or any(char not in IDENTIFIER_CHARS for char in value):
            raise ValidationError(f"{field} 格式无效")
        return value

    def _text(self, value: str, field: str, limit: int) -> str:
        value = str(value).strip()
        if not value or len(value) > limit:
            raise ValidationError(f"{field} 不能为空且不能超过 {limit} 个字符")
        return value

    def _actor(self, connection, actor_id: str):
        row = connection.execute("SELECT * FROM actors WHERE actor_id=?", (actor_id,)).fetchone()
        if row is None:
            raise NotFoundError("操作者不存在")
        if not row["active"]:
            raise PermissionDenied("操作者已停用")
        return row

    def _capable(self, connection, actor_id: str, capability: str) -> bool:
        row = connection.execute(
            "SELECT 1 FROM actor_capabilities WHERE actor_id=? AND capability=?",
            (actor_id, capability),
        ).fetchone()
        return row is not None

    def _require_capability(self, connection, actor, capability: str) -> None:
        if not self._capable(connection, actor["actor_id"], capability):
            raise PermissionDenied(f"缺少 {capability} 权限")

    def _load_event(self, connection, event_id: str):
        row = connection.execute("SELECT * FROM risk_events WHERE event_id=?", (event_id,)).fetchone()
        if row is None:
            raise NotFoundError("风险事件不存在")
        return row

    def _participant_orgs(self, connection, event_id: str) -> list[str]:
        rows = connection.execute(
            "SELECT organization_id FROM risk_participants WHERE event_id=? ORDER BY organization_id",
            (event_id,),
        ).fetchall()
        return [row["organization_id"] for row in rows]

    def _is_participant(self, connection, event_id: str, organization_id: str) -> bool:
        return connection.execute(
            "SELECT 1 FROM risk_participants WHERE event_id=? AND organization_id=?",
            (event_id, organization_id),
        ).fetchone() is not None

    def _require_participant(self, connection, event_id: str, organization_id: str) -> None:
        if not self._is_participant(connection, event_id, organization_id):
            raise PermissionDenied("本机构未参与该风险事件")

    def _enqueue(self, connection, *, organization_id: str, event_id: str,
                 kind: str, revision: int, now: str) -> None:
        """向某机构的有序投递队列追加一条待办。"""

        row = connection.execute(
            "SELECT COALESCE(MAX(seq),0) + 1 AS next_seq FROM risk_deliveries WHERE organization_id=?",
            (organization_id,),
        ).fetchone()
        connection.execute(
            "INSERT INTO risk_deliveries(organization_id,seq,event_id,kind,revision,enqueued_at) "
            "VALUES(?,?,?,?,?,?)",
            (organization_id, row["next_seq"], event_id, kind, revision, now),
        )

    def _enqueue_recipients(self, connection, *, event_id: str, kind: str,
                            revision: int, now: str) -> None:
        for organization_id in connection.execute(
            "SELECT organization_id FROM risk_participants WHERE event_id=? AND relation='recipient' "
            "ORDER BY organization_id",
            (event_id,),
        ).fetchall():
            self._enqueue(connection, organization_id=organization_id["organization_id"],
                          event_id=event_id, kind=kind, revision=revision, now=now)

    def _idempotent(self, connection, *, request_id: str, action: str,
                    payload: dict[str, Any],
                    create: Callable[[], tuple[str, str, dict[str, Any]]]):
        request_id = self._identifier(request_id, "request_id")
        payload_hash = digest(payload)
        row = connection.execute(
            "SELECT * FROM request_receipts WHERE request_id=?", (request_id,)
        ).fetchone()
        if row:
            if row["action"] != action or row["payload_hash"] != payload_hash:
                raise ConflictError("request_id 已被不同内容使用")
            return WriteReceipt(request_id, row["resource_type"], row["resource_id"], True,
                                json.loads(row["response_json"]))
        resource_type, resource_id, response = create()
        connection.execute(
            "INSERT INTO request_receipts(request_id,action,payload_hash,resource_type,resource_id,"
            "response_json,created_at) VALUES(?,?,?,?,?,?,?)",
            (request_id, action, payload_hash, resource_type, resource_id,
             canonical_json(response), self._now()),
        )
        return WriteReceipt(request_id, resource_type, resource_id, False, response)

    # ------------------------------------------------------------------ 授权管理

    def grant_capability(self, *, request_id: str, actor_id: str, target_actor_id: str,
                         capability: str):
        """由管理员授予某个操作者提交、查看或确认权限。"""

        if capability not in CAPABILITIES:
            raise ValidationError("capability 不在允许范围内")
        payload = {"actor_id": actor_id, "target_actor_id": target_actor_id, "capability": capability}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            if actor["role"] != "admin":
                raise PermissionDenied("只有管理员可以授权")
            target = self._actor(connection, target_actor_id)

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute(
                    "INSERT OR IGNORE INTO actor_capabilities(actor_id,capability,granted_by,created_at) "
                    "VALUES(?,?,?,?)",
                    (target_actor_id, capability, actor_id, self._now()),
                )
                append_event(connection, actor_id=actor_id, action="capability.granted",
                             resource_type="actor", resource_id=target_actor_id,
                             detail={"capability": capability, "organization_id": target["organization_id"]},
                             occurred_at=self._now())
                return "actor_capability", f"{target_actor_id}:{capability}", \
                    {"actor_id": target_actor_id, "capability": capability}

            return self._idempotent(connection, request_id=request_id, action="grant_capability",
                                    payload=payload, create=create)

    def list_capabilities(self, actor_id: str, target_actor_id: str) -> list[str]:
        """列出某操作者被授予的风险沟通能力。"""

        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            if actor["role"] != "admin" and actor["actor_id"] != target_actor_id:
                raise PermissionDenied("只能查询本人的授权")
            rows = connection.execute(
                "SELECT capability FROM actor_capabilities WHERE actor_id=? ORDER BY capability",
                (target_actor_id,),
            ).fetchall()
            return [row["capability"] for row in rows]

    # ------------------------------------------------------------------ 事件提交与修订

    def submit_risk_event(self, *, request_id: str, actor_id: str, summary: str,
                          proposed_level: str, recipient_organizations: list[str],
                          origin_local_reference: str | None = None):
        """提交事件摘要并投递给参与机构；原始敏感内容保留在参与边界内。"""

        summary = self._text(summary, "summary", 2000)
        if proposed_level not in LEVEL_RANK:
            raise ValidationError("proposed_level 不在允许范围内")
        if not isinstance(recipient_organizations, list) or not recipient_organizations:
            raise ValidationError("recipient_organizations 必须是非空数组")
        recipients = sorted({self._identifier(org, "recipient_organizations")
                             for org in recipient_organizations})
        origin_local_reference = (self._identifier(origin_local_reference, "origin_local_reference")
                                  if origin_local_reference else None)
        payload = {"actor_id": actor_id, "summary": summary, "proposed_level": proposed_level,
                   "recipient_organizations": recipients,
                   "origin_local_reference": origin_local_reference}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require_capability(connection, actor, "risk:submit")
            origin_org = actor["organization_id"]
            if origin_org in recipients:
                raise ValidationError("提交方不能同时作为接收方")
            for org in recipients:
                if connection.execute("SELECT 1 FROM organizations WHERE organization_id=?",
                                      (org,)).fetchone() is None:
                    raise NotFoundError(f"接收机构不存在: {org}")

            def create() -> tuple[str, str, dict[str, Any]]:
                now = self._now()
                event_id = uuid.uuid4().hex
                content_hash = digest({"summary": summary})
                connection.execute(
                    "INSERT INTO risk_events(event_id,origin_organization_id,summary,content_hash,"
                    "current_revision,status,agreed_level,submitted_by,created_at,updated_at) "
                    "VALUES(?,?,?,?,1,'active',NULL,?,?,?)",
                    (event_id, origin_org, summary, content_hash, actor_id, now, now),
                )
                connection.execute(
                    "INSERT INTO risk_event_revisions(event_id,revision,summary,content_hash,"
                    "change_note,proposed_level,created_by,created_at) VALUES(?,1,?,?,?,?,?,?)",
                    (event_id, summary, content_hash, "首次提交", proposed_level, actor_id, now),
                )
                connection.execute(
                    "INSERT INTO risk_participants(event_id,organization_id,relation,added_at) "
                    "VALUES(?,?,'originator',?)",
                    (event_id, origin_org, now),
                )
                for org in recipients:
                    connection.execute(
                        "INSERT INTO risk_participants(event_id,organization_id,relation,added_at) "
                        "VALUES(?,?,'recipient',?)",
                        (event_id, org, now),
                    )
                connection.execute(
                    "INSERT INTO risk_level_proposals(proposal_id,event_id,organization_id,revision,"
                    "proposed_level,rationale,proposed_by,created_at) VALUES(?,?,?,1,?,?,?,?)",
                    (uuid.uuid4().hex, event_id, origin_org, proposed_level, "提交方建议等级",
                     actor_id, now),
                )
                if origin_local_reference:
                    self._insert_mapping(connection, event_id=event_id,
                                         organization_id=origin_org,
                                         local_reference=origin_local_reference,
                                         actor_id=actor_id, now=now)
                for org in recipients:
                    self._enqueue(connection, organization_id=org, event_id=event_id,
                                  kind="submitted", revision=1, now=now)
                append_event(connection, actor_id=actor_id, action="risk_event.submitted",
                             resource_type="risk_event", resource_id=event_id,
                             detail={"origin_organization_id": origin_org,
                                     "recipient_organizations": recipients,
                                     "content_hash": content_hash,
                                     "proposed_level": proposed_level},
                             occurred_at=now)
                return "risk_event", event_id, {"event_id": event_id, "revision": 1,
                                                "content_hash": content_hash}

            return self._idempotent(connection, request_id=request_id, action="submit_risk_event",
                                    payload=payload, create=create)

    def revise_risk_event(self, *, request_id: str, actor_id: str, event_id: str,
                          change_note: str, summary: str | None = None,
                          proposed_level: str | None = None):
        """对同一事件追加一个可追溯的修订版本。"""

        event_id = self._identifier(event_id, "event_id")
        change_note = self._text(change_note, "change_note", 500)
        if summary is not None:
            summary = self._text(summary, "summary", 2000)
        if proposed_level is not None and proposed_level not in LEVEL_RANK:
            raise ValidationError("proposed_level 不在允许范围内")
        payload = {"actor_id": actor_id, "event_id": event_id, "change_note": change_note,
                   "summary": summary, "proposed_level": proposed_level}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require_capability(connection, actor, "risk:submit")
            event = self._load_event(connection, event_id)
            if event["origin_organization_id"] != actor["organization_id"]:
                raise PermissionDenied("只有提交方可以修订事件")
            if event["status"] != "active":
                raise ConflictError("事件已撤回，不能继续修订")

            def create() -> tuple[str, str, dict[str, Any]]:
                now = self._now()
                new_revision = event["current_revision"] + 1
                next_summary = summary if summary is not None else event["summary"]
                content_hash = digest({"summary": next_summary})
                if summary is not None:
                    connection.execute(
                        "UPDATE risk_events SET summary=?, content_hash=?, current_revision=?, "
                        "agreed_level=NULL, updated_at=? WHERE event_id=?",
                        (next_summary, content_hash, new_revision, now, event_id),
                    )
                else:
                    connection.execute(
                        "UPDATE risk_events SET content_hash=?, current_revision=?, agreed_level=NULL, "
                        "updated_at=? WHERE event_id=?",
                        (content_hash, new_revision, now, event_id),
                    )
                carried_level = proposed_level
                if carried_level is None:
                    previous = connection.execute(
                        "SELECT proposed_level FROM risk_level_proposals WHERE event_id=? "
                        "AND organization_id=? AND revision=? ORDER BY created_at DESC LIMIT 1",
                        (event_id, event["origin_organization_id"], event["current_revision"]),
                    ).fetchone()
                    carried_level = previous["proposed_level"] if previous else None
                connection.execute(
                    "INSERT INTO risk_event_revisions(event_id,revision,summary,content_hash,"
                    "change_note,proposed_level,created_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (event_id, new_revision, next_summary, content_hash, change_note,
                     carried_level, actor_id, now),
                )
                if carried_level is not None:
                    connection.execute(
                        "INSERT INTO risk_level_proposals(proposal_id,event_id,organization_id,"
                        "revision,proposed_level,rationale,proposed_by,created_at) "
                        "VALUES(?,?,?,?,?,?,?,?)",
                        (uuid.uuid4().hex, event_id, event["origin_organization_id"], new_revision,
                         carried_level, "随修订延续提交方等级建议", actor_id, now),
                    )
                self._enqueue_recipients(connection, event_id=event_id, kind="revised",
                                         revision=new_revision, now=now)
                append_event(connection, actor_id=actor_id, action="risk_event.revised",
                             resource_type="risk_event", resource_id=event_id,
                             detail={"revision": new_revision, "content_hash": content_hash,
                                     "change_note_hash": digest(change_note),
                                     "proposed_level": carried_level},
                             occurred_at=now)
                self._settle_if_unanimous(connection, event_id=event_id, revision=new_revision,
                                          actor_id=actor_id, now=now)
                return "risk_event_revision", f"{event_id}:{new_revision}", \
                    {"event_id": event_id, "revision": new_revision, "content_hash": content_hash}

            return self._idempotent(connection, request_id=request_id, action="revise_risk_event",
                                    payload=payload, create=create)

    # ------------------------------------------------------------------ 本地编号映射

    def _insert_mapping(self, connection, *, event_id: str, organization_id: str,
                        local_reference: str, actor_id: str, now: str) -> str:
        try:
            connection.execute(
                "INSERT INTO risk_id_mappings(mapping_id,event_id,organization_id,local_reference,"
                "mapped_by,created_at) VALUES(?,?,?,?,?,?)",
                (uuid.uuid4().hex, event_id, organization_id, local_reference, actor_id, now),
            )
        except Exception as exc:
            raise ConflictError("本机构编号已经映射到其他事件，或该事件已有本机构映射") from exc
        return local_reference

    def map_local_reference(self, *, request_id: str, actor_id: str, event_id: str,
                            local_reference: str):
        """把机构本地编号映射到统一事件，使不同编号体系可以对齐同一风险。"""

        event_id = self._identifier(event_id, "event_id")
        local_reference = self._text(local_reference, "local_reference", 128)
        payload = {"actor_id": actor_id, "event_id": event_id, "local_reference": local_reference}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require_capability(connection, actor, "risk:submit")
            event = self._load_event(connection, event_id)
            self._require_participant(connection, event_id, actor["organization_id"])

            def create() -> tuple[str, str, dict[str, Any]]:
                now = self._now()
                self._insert_mapping(connection, event_id=event_id,
                                     organization_id=actor["organization_id"],
                                     local_reference=local_reference, actor_id=actor_id, now=now)
                append_event(connection, actor_id=actor_id, action="risk_reference.mapped",
                             resource_type="risk_event", resource_id=event_id,
                             detail={"organization_id": actor["organization_id"],
                                     "local_reference": local_reference},
                             occurred_at=now)
                return "risk_id_mapping", f"{event_id}:{actor['organization_id']}", \
                    {"event_id": event_id, "local_reference": local_reference}

            return self._idempotent(connection, request_id=request_id,
                                    action="map_local_reference", payload=payload, create=create)

    # ------------------------------------------------------------------ 等级协商

    def propose_level(self, *, request_id: str, actor_id: str, event_id: str,
                      revision: int, proposed_level: str, rationale: str):
        """记录某机构对指定修订的等级主张，意见一致时自动达成统一等级。"""

        event_id = self._identifier(event_id, "event_id")
        if proposed_level not in LEVEL_RANK:
            raise ValidationError("proposed_level 不在允许范围内")
        rationale = self._text(rationale, "rationale", 500)
        if not isinstance(revision, int) or revision < 1:
            raise ValidationError("revision 必须是正整数")
        payload = {"actor_id": actor_id, "event_id": event_id, "revision": revision,
                   "proposed_level": proposed_level, "rationale": rationale}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require_capability(connection, actor, "risk:submit")
            event = self._load_event(connection, event_id)
            self._require_participant(connection, event_id, actor["organization_id"])
            if revision > event["current_revision"]:
                raise ValidationError("不能为尚未发布的修订主张等级")
            if connection.execute(
                "SELECT 1 FROM risk_level_agreements WHERE event_id=? AND revision=?",
                (event_id, revision),
            ).fetchone() is not None:
                raise ConflictError("该修订的统一等级已经定稿，调整请发起新修订")

            def create() -> tuple[str, str, dict[str, Any]]:
                now = self._now()
                existing = connection.execute(
                    "SELECT * FROM risk_level_proposals WHERE event_id=? "
                    "AND organization_id=? AND revision=?",
                    (event_id, actor["organization_id"], revision),
                ).fetchone()
                if existing is not None:
                    if existing["proposed_level"] == proposed_level:
                        return "risk_level_proposal", existing["proposal_id"], \
                            {"event_id": event_id, "revision": revision,
                             "proposed_level": proposed_level, "replayed": True}
                    connection.execute(
                        "UPDATE risk_level_proposals SET proposed_level=?, rationale=?, created_at=? "
                        "WHERE proposal_id=?",
                        (proposed_level, rationale, now, existing["proposal_id"]),
                    )
                    proposal_id = existing["proposal_id"]
                else:
                    proposal_id = uuid.uuid4().hex
                    connection.execute(
                        "INSERT INTO risk_level_proposals(proposal_id,event_id,organization_id,"
                        "revision,proposed_level,rationale,proposed_by,created_at) "
                        "VALUES(?,?,?,?,?,?,?,?)",
                        (proposal_id, event_id, actor["organization_id"], revision, proposed_level,
                         rationale, actor_id, now),
                    )
                append_event(connection, actor_id=actor_id, action="risk_level.proposed",
                             resource_type="risk_event", resource_id=event_id,
                             detail={"organization_id": actor["organization_id"], "revision": revision,
                                     "proposed_level": proposed_level,
                                     "adjusted": existing is not None},
                             occurred_at=now)
                agreement = self._settle_if_unanimous(connection, event_id=event_id,
                                                      revision=revision, actor_id=actor_id, now=now)
                response = {"event_id": event_id, "revision": revision,
                            "proposed_level": proposed_level}
                if agreement:
                    response["agreed_level"] = agreement
                return "risk_level_proposal", proposal_id, response

            return self._idempotent(connection, request_id=request_id, action="propose_level",
                                    payload=payload, create=create)

    def _settle_if_unanimous(self, connection, *, event_id: str, revision: int,
                             actor_id: str, now: str) -> str | None:
        """所有参与机构对同一修订意见一致时，固化统一等级并生成处置义务。"""

        event = connection.execute("SELECT * FROM risk_events WHERE event_id=?",
                                   (event_id,)).fetchone()
        if event["agreed_level"] is not None and event["current_revision"] == revision:
            return event["agreed_level"]
        participants = self._participant_orgs(connection, event_id)
        rows = connection.execute(
            "SELECT organization_id, proposed_level FROM risk_level_proposals WHERE event_id=? "
            "AND revision=?",
            (event_id, revision),
        ).fetchall()
        levels = {row["organization_id"]: row["proposed_level"] for row in rows}
        if not participants or any(org not in levels for org in participants):
            return None
        agreed_level = next(iter(levels.values()))
        if any(level != agreed_level for level in levels.values()):
            return None
        if connection.execute(
            "SELECT 1 FROM risk_level_agreements WHERE event_id=? AND revision=?",
            (event_id, revision),
        ).fetchone() is not None:
            return agreed_level
        connection.execute(
            "INSERT INTO risk_level_agreements(event_id,revision,agreed_level,agreed_by,created_at) "
            "VALUES(?,?,?,?,?)",
            (event_id, revision, agreed_level, actor_id, now),
        )
        connection.execute(
            "UPDATE risk_events SET agreed_level=?, updated_at=? WHERE event_id=?",
            (agreed_level, now, event_id),
        )
        for org in participants:
            if org == event["origin_organization_id"]:
                continue
            connection.execute(
                "INSERT OR IGNORE INTO risk_obligations(obligation_id,event_id,organization_id,kind,"
                "required_level,status,created_revision,created_at) "
                "VALUES(?,?,?, 'handle_level', ?, 'open', ?, ?)",
                (uuid.uuid4().hex, event_id, org, agreed_level, revision, now),
            )
            self._enqueue(connection, organization_id=org, event_id=event_id,
                          kind="level_agreed", revision=revision, now=now)
        append_event(connection, actor_id=actor_id, action="risk_level.agreed",
                     resource_type="risk_event", resource_id=event_id,
                     detail={"revision": revision, "agreed_level": agreed_level,
                             "participants": participants},
                     occurred_at=now)
        return agreed_level

    # ------------------------------------------------------------------ 撤回与义务

    def withdraw_event(self, *, request_id: str, actor_id: str, event_id: str, reason: str):
        """撤回通讯事件；已有回执与处置义务不被抹除。"""

        event_id = self._identifier(event_id, "event_id")
        reason = self._text(reason, "reason", 500)
        payload = {"actor_id": actor_id, "event_id": event_id, "reason": reason}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require_capability(connection, actor, "risk:submit")
            event = self._load_event(connection, event_id)
            if event["origin_organization_id"] != actor["organization_id"]:
                raise PermissionDenied("只有提交方可以撤回事件")

            def create() -> tuple[str, str, dict[str, Any]]:
                now = self._now()
                connection.execute(
                    "UPDATE risk_events SET status='withdrawn', updated_at=? WHERE event_id=?",
                    (now, event_id),
                )
                self._enqueue_recipients(connection, event_id=event_id, kind="withdrawn",
                                         revision=event["current_revision"], now=now)
                append_event(connection, actor_id=actor_id, action="risk_event.withdrawn",
                             resource_type="risk_event", resource_id=event_id,
                             detail={"revision": event["current_revision"],
                                     "reason_hash": digest(reason)},
                             occurred_at=now)
                open_obligations = connection.execute(
                    "SELECT COUNT(*) AS count FROM risk_obligations WHERE event_id=? AND status='open'",
                    (event_id,),
                ).fetchone()["count"]
                return "risk_event", event_id, {"event_id": event_id, "status": "withdrawn",
                                                "open_obligations_preserved": open_obligations}

            return self._idempotent(connection, request_id=request_id, action="withdraw_event",
                                    payload=payload, create=create)

    def acknowledge_revision(self, actor_id: str, event_id: str, revision: int,
                             note: str | None = None) -> RiskReceiptView:
        """确认接收某修订；重复确认幂等，并顺手结清该机构已覆盖的有序待办。"""

        event_id = self._identifier(event_id, "event_id")
        if not isinstance(revision, int) or revision < 1:
            raise ValidationError("revision 必须是正整数")
        if note is not None:
            note = self._text(note, "note", 500)
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require_capability(connection, actor, "risk:confirm")
            event = self._load_event(connection, event_id)
            relation = connection.execute(
                "SELECT relation FROM risk_participants WHERE event_id=? AND organization_id=?",
                (event_id, actor["organization_id"]),
            ).fetchone()
            if relation is None:
                raise PermissionDenied("本机构未参与该风险事件")
            if relation["relation"] != "recipient":
                raise PermissionDenied("提交方不需要接收回执")
            if revision > event["current_revision"]:
                raise NotFoundError("该修订版本不存在")
            now = self._now()
            org_id = actor["organization_id"]
            # 确认高版本即视为已按序接收此前各版本，离线补齐时回执一并落账。
            for earlier in connection.execute(
                "SELECT * FROM risk_event_revisions WHERE event_id=? AND revision<=? ORDER BY revision",
                (event_id, revision),
            ).fetchall():
                already = connection.execute(
                    "SELECT 1 FROM risk_receipts WHERE event_id=? AND organization_id=? AND revision=?",
                    (event_id, org_id, earlier["revision"]),
                ).fetchone()
                if already is not None:
                    continue
                backfill_note = note if earlier["revision"] == revision else f"随第 {revision} 版确认按序补齐"
                connection.execute(
                    "INSERT INTO risk_receipts(receipt_id,event_id,organization_id,revision,"
                    "content_hash,note,received_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (uuid.uuid4().hex, event_id, org_id, earlier["revision"],
                     earlier["content_hash"], backfill_note, actor_id, now),
                )
                append_event(connection, actor_id=actor_id, action="risk_receipt.acknowledged",
                             resource_type="risk_event", resource_id=event_id,
                             detail={"organization_id": org_id, "revision": earlier["revision"],
                                     "content_hash": earlier["content_hash"],
                                     "backfilled": earlier["revision"] != revision},
                             occurred_at=now)
            target_row = connection.execute(
                "SELECT * FROM risk_receipts WHERE event_id=? AND organization_id=? AND revision=?",
                (event_id, org_id, revision),
            ).fetchone()
            connection.execute(
                "UPDATE risk_deliveries SET completed_at=? WHERE organization_id=? AND event_id=? "
                "AND completed_at IS NULL AND revision<=? AND kind IN ({})".format(
                    ",".join("?" for _ in ACK_DELIVERY_KINDS)),
                (now, org_id, event_id, revision, *ACK_DELIVERY_KINDS),
            )
            return RiskReceiptView(event_id, org_id, revision,
                                   target_row["content_hash"], target_row["note"],
                                   target_row["received_by"], target_row["created_at"])

    def discharge_obligation(self, actor_id: str, obligation_id: str,
                             note: str | None = None) -> dict[str, Any]:
        """由义务所属机构履行处置义务；撤回事件不会自动免除义务。"""

        obligation_id = self._identifier(obligation_id, "obligation_id")
        if note is not None:
            note = self._text(note, "note", 500)
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require_capability(connection, actor, "risk:confirm")
            row = connection.execute("SELECT * FROM risk_obligations WHERE obligation_id=?",
                                     (obligation_id,)).fetchone()
            if row is None:
                raise NotFoundError("处置义务不存在")
            if row["organization_id"] != actor["organization_id"]:
                raise PermissionDenied("只能履行本机构的处置义务")
            now = self._now()
            if row["status"] == "discharged":
                return {"obligation_id": obligation_id, "status": "discharged", "replayed": True,
                        "discharged_at": row["discharged_at"]}
            connection.execute(
                "UPDATE risk_obligations SET status='discharged', discharged_at=?, discharge_note=? "
                "WHERE obligation_id=?",
                (now, note, obligation_id),
            )
            append_event(connection, actor_id=actor_id, action="risk_obligation.discharged",
                         resource_type="risk_obligation", resource_id=obligation_id,
                         detail={"event_id": row["event_id"], "organization_id": row["organization_id"],
                                 "required_level": row["required_level"],
                                 "created_revision": row["created_revision"]},
                         occurred_at=now)
            return {"obligation_id": obligation_id, "status": "discharged", "replayed": False,
                    "discharged_at": now}

    # ------------------------------------------------------------------ 查询视图

    def get_risk_event(self, actor_id: str, event_id: str) -> RiskEventView:
        """查看事件；非参与机构只能看到内容摘要值，看不到原始摘要。"""

        event_id = self._identifier(event_id, "event_id")
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            self._require_capability(connection, actor, "risk:view")
            event = self._load_event(connection, event_id)
            participant = self._is_participant(connection, event_id, actor["organization_id"])
            privileged = actor["role"] in ("admin", "auditor")
            if not participant and not privileged:
                raise PermissionDenied("本机构未参与该风险事件")
            revision_rows = connection.execute(
                "SELECT * FROM risk_event_revisions WHERE event_id=? ORDER BY revision",
                (event_id,),
            ).fetchall()
            if participant:
                revisions = [RiskRevision(row["revision"], row["summary"], row["content_hash"],
                                          row["change_note"], row["proposed_level"],
                                          row["created_by"], row["created_at"]) for row in revision_rows]
                latest_summary = event["summary"]
            else:
                revisions = [RiskRevision(row["revision"], "", row["content_hash"],
                                          row["change_note"], None, row["created_by"],
                                          row["created_at"]) for row in revision_rows]
                latest_summary = None
            participants = self._participant_orgs(connection, event_id)
            return RiskEventView(event_id, event["origin_organization_id"],
                                 event["current_revision"], event["status"],
                                 event["agreed_level"], latest_summary, revisions,
                                 participants, event["created_at"], event["updated_at"])

    def list_pending(self, actor_id: str, limit: int = 100) -> list[PendingDelivery]:
        """按投递顺序列出本机构离线期间积压的待办。"""

        if not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValidationError("limit 必须在 1 到 1000 之间")
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            self._require_capability(connection, actor, "risk:view")
            rows = connection.execute(
                "SELECT seq,event_id,kind,revision,enqueued_at FROM risk_deliveries "
                "WHERE organization_id=? AND completed_at IS NULL ORDER BY seq LIMIT ?",
                (actor["organization_id"], limit),
            ).fetchall()
            return [PendingDelivery(row["seq"], row["event_id"], row["kind"],
                                    row["revision"], row["enqueued_at"]) for row in rows]

    def list_obligations(self, actor_id: str, include_discharged: bool = False) -> list[dict[str, Any]]:
        """列出本机构的处置义务，默认只返回仍需履行的部分。"""

        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            self._require_capability(connection, actor, "risk:confirm")
            query = ("SELECT obligation_id,event_id,kind,required_level,status,created_revision,"
                     "created_at,discharged_at,discharge_note FROM risk_obligations "
                     "WHERE organization_id=?")
            parameters: list[Any] = [actor["organization_id"]]
            if not include_discharged:
                query += " AND status='open'"
            query += " ORDER BY created_at, obligation_id"
            rows = connection.execute(query, parameters).fetchall()
            return [dict(row) for row in rows]

    def communication_status(self, actor_id: str, event_id: str) -> dict[str, Any]:
        """展示统一等级、各机构本地编号映射与回执完成情况。"""

        event_id = self._identifier(event_id, "event_id")
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            self._require_capability(connection, actor, "risk:view")
            event = self._load_event(connection, event_id)
            participant = self._is_participant(connection, event_id, actor["organization_id"])
            if not participant and actor["role"] not in ("admin", "auditor"):
                raise PermissionDenied("本机构未参与该风险事件")
            current = event["current_revision"]
            organizations: list[dict[str, Any]] = []
            for row in connection.execute(
                "SELECT organization_id, relation FROM risk_participants WHERE event_id=? "
                "ORDER BY organization_id",
                (event_id,),
            ).fetchall():
                org_id = row["organization_id"]
                mapping = connection.execute(
                    "SELECT local_reference FROM risk_id_mappings WHERE event_id=? AND organization_id=?",
                    (event_id, org_id),
                ).fetchone()
                proposal = connection.execute(
                    "SELECT proposed_level FROM risk_level_proposals WHERE event_id=? "
                    "AND organization_id=? AND revision=? ORDER BY created_at DESC LIMIT 1",
                    (event_id, org_id, current),
                ).fetchone()
                receipt_rows = connection.execute(
                    "SELECT revision FROM risk_receipts WHERE event_id=? AND organization_id=? "
                    "ORDER BY revision",
                    (event_id, org_id),
                ).fetchall()
                acked = [item["revision"] for item in receipt_rows]
                pending_rows = connection.execute(
                    "SELECT seq,kind,revision FROM risk_deliveries WHERE event_id=? "
                    "AND organization_id=? AND completed_at IS NULL ORDER BY seq",
                    (event_id, org_id),
                ).fetchall()
                open_obligations = connection.execute(
                    "SELECT COUNT(*) AS count FROM risk_obligations WHERE event_id=? "
                    "AND organization_id=? AND status='open'",
                    (event_id, org_id),
                ).fetchone()["count"]
                organizations.append({
                    "organization_id": org_id,
                    "relation": row["relation"],
                    "local_reference": mapping["local_reference"] if mapping else None,
                    "current_level_proposal": proposal["proposed_level"] if proposal else None,
                    "acked_revisions": acked,
                    "acked_current": bool(acked) and acked[-1] == current and len(acked) == current,
                    "receipt_complete": row["relation"] == "originator"
                        or (bool(acked) and acked[-1] == current and len(acked) == current),
                    "pending_deliveries": [dict(item) for item in pending_rows],
                    "open_obligations": open_obligations,
                })
            missing = [item["organization_id"] for item in organizations
                       if not item["receipt_complete"]]
            return {
                "event_id": event_id,
                "status": event["status"],
                "current_revision": current,
                "agreed_level": event["agreed_level"],
                "content_hash": event["content_hash"],
                "organizations": organizations,
                "organizations_pending_receipt": missing,
            }
