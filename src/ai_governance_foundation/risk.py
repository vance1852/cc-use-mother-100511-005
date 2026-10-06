"""提供跨机构风险事件沟通：脱敏提交、编号映射、等级协商、不可抹除的处置义务与离线顺序补齐。"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any, Callable

from .audit import append_event, canonical_json, digest
from .clock import Clock, SystemClock
from .domain import is_allowed_risk_level
from .errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .models import (
    Advisory,
    DeliveryItem,
    IncidentVersion,
    LevelProposal,
    LocalReference,
    WriteReceipt,
)
from .storage import Database


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{1,63}$")
HEX64 = re.compile(r"^[a-f0-9]{64}$")

# 三类权限：提交、查看、确认彼此分离；admin 为全局兜底角色。
SUBMIT_ROLES = frozenset({"admin", "operator"})
CONFIRM_ROLES = frozenset({"admin", "reviewer"})
VIEW_ROLES = frozenset({"admin", "operator", "reviewer"})


class RiskCommunicationService:
    """协调风险事件跨机构沟通的权限、顺序义务、幂等与审计规则。"""

    def __init__(self, database: Database, clock: Clock | None = None) -> None:
        self.database = database
        self.clock = clock or SystemClock()

    # ------------------------------------------------------------------ 基础工具

    def _now(self) -> str:
        return self.clock.now().isoformat().replace("+00:00", "Z")

    def _identifier(self, value: str, field: str) -> str:
        value = str(value).strip()
        if not IDENTIFIER.fullmatch(value):
            raise ValidationError(f"{field} 格式无效")
        return value

    def _text(self, value: Any, field: str, limit: int) -> str:
        value = str(value or "").strip()
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

    @staticmethod
    def _require_role(actor, roles: frozenset[str]) -> None:
        if actor["role"] not in roles:
            raise PermissionDenied("当前角色不能执行该动作")

    def _idempotent(self, connection, *, request_id: str, action: str,
                    payload: dict[str, Any],
                    create: Callable[[], tuple[str, str, dict[str, Any]]]) -> WriteReceipt:
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

    def _incident(self, connection, incident_id: str):
        row = connection.execute(
            "SELECT * FROM risk_incidents WHERE incident_id=?", (incident_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("风险事件不存在")
        return row

    def _recipients(self, connection, incident_id: str) -> list[str]:
        """返回通告接收机构列表（不含发起方），按编号排序保证顺序稳定。"""

        return [row["target_organization_id"] for row in connection.execute(
            "SELECT DISTINCT target_organization_id FROM risk_advisories "
            "WHERE incident_id=? ORDER BY target_organization_id", (incident_id,)
        )]

    def _participants(self, connection, incident) -> list[str]:
        """等级协商参与方 = 发起方 + 全部接收机构。"""

        return sorted(set([incident["origin_organization_id"]]) | set(self._recipients(connection, incident["incident_id"])))

    def _require_participant(self, connection, incident, actor) -> None:
        """非参与方一律得到“不存在”，避免跨机构探测。"""

        if actor["role"] == "admin":
            return
        if actor["organization_id"] not in self._participants(connection, incident):
            raise NotFoundError("风险事件不存在或未向你所在机构通告")

    def _require_recipient(self, connection, incident, actor) -> None:
        if actor["role"] == "admin":
            return
        if actor["organization_id"] not in self._recipients(connection, incident["incident_id"]):
            raise NotFoundError("风险事件不存在或未向你所在机构通告")

    def _next_ordinal(self, connection, incident_id: str, organization_id: str) -> int:
        row = connection.execute(
            "SELECT COALESCE(MAX(ordinal),0)+1 AS next FROM risk_advisories "
            "WHERE incident_id=? AND target_organization_id=?",
            (incident_id, organization_id),
        ).fetchone()
        return int(row["next"])

    def _next_outbox_seq(self, connection, organization_id: str) -> int:
        row = connection.execute(
            "SELECT COALESCE(MAX(sequence_number),0)+1 AS next FROM risk_outbox "
            "WHERE organization_id=?", (organization_id,)
        ).fetchone()
        return int(row["next"])

    def _emit_advisory(self, connection, *, incident_id: str, version: int,
                       organization_id: str, kind: str, status: str,
                       after_withdrawal: bool) -> Advisory:
        """为一家机构追加一条不可变通告（处置义务），同时写入其顺序 outbox。"""

        ordinal = self._next_ordinal(connection, incident_id, organization_id)
        sequence_number = self._next_outbox_seq(connection, organization_id)
        advisory_id = uuid.uuid4().hex
        now = self._now()
        connection.execute(
            "INSERT INTO risk_advisories(advisory_id,incident_id,version,target_organization_id,"
            "ordinal,kind,status,after_withdrawal,sequence_number,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (advisory_id, incident_id, version, organization_id, ordinal, kind, status,
             1 if after_withdrawal else 0, sequence_number, now),
        )
        connection.execute(
            "INSERT INTO risk_outbox(organization_id,sequence_number,incident_id,advisory_id,"
            "version,kind,status,after_withdrawal,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (organization_id, sequence_number, incident_id, advisory_id, version, kind, status,
             1 if after_withdrawal else 0, now),
        )
        return Advisory(advisory_id, incident_id, version, organization_id, status,
                        after_withdrawal, sequence_number, now)

    def _latest_stances(self, connection, incident, version: int) -> dict[str, str]:
        """返回各参与方在指定版本上的最新等级主张；发起方未表态时以版本提案等级为其主张。"""

        stances: dict[str, str] = {}
        for organization_id in self._participants(connection, incident):
            row = connection.execute(
                "SELECT proposed_level FROM risk_level_proposals "
                "WHERE incident_id=? AND version=? AND organization_id=? "
                "ORDER BY sequence_in_version DESC LIMIT 1",
                (incident["incident_id"], version, organization_id),
            ).fetchone()
            if row is not None:
                stances[organization_id] = row["proposed_level"]
        if incident["origin_organization_id"] not in stances:
            version_row = connection.execute(
                "SELECT proposed_level FROM risk_incident_versions "
                "WHERE incident_id=? AND version=?", (incident["incident_id"], version)
            ).fetchone()
            if version_row is not None:
                stances[incident["origin_organization_id"]] = version_row["proposed_level"]
        return stances

    def _maybe_lock_level(self, connection, incident, version: int) -> str | None:
        """所有参与方（其最新主张）一致时，把统一等级在该版本上定格。"""

        participants = self._participants(connection, incident)
        stances = self._latest_stances(connection, incident, version)
        if len(stances) != len(participants):
            return None
        levels = set(stances.values())
        if len(levels) != 1:
            return None
        level = next(iter(levels))
        connection.execute(
            "UPDATE risk_incidents SET agreed_level=?, level_locked_at=? WHERE incident_id=?",
            (level, self._now(), incident["incident_id"]),
        )
        append_event(connection, actor_id="system", action="risk_level.agreed",
                     resource_type="risk_incident", resource_id=incident["incident_id"],
                     detail={"version": version, "level": level,
                             "participant_count": len(participants), "stances": stances},
                     occurred_at=self._now())
        return level

    # ------------------------------------------------------------------ 提交与修订

    def submit_incident(self, *, request_id: str, actor_id: str, incident_id: str,
                        sanitized_summary: str, category: str, proposed_level: str,
                        recipient_organizations: list[str], content_hash: str | None = None) -> WriteReceipt:
        payload = {"actor_id": actor_id, "incident_id": incident_id,
                   "sanitized_summary": sanitized_summary, "category": category,
                   "proposed_level": proposed_level,
                   "recipient_organizations": recipient_organizations,
                   "content_hash": content_hash}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require_role(actor, SUBMIT_ROLES)
            incident_id = self._identifier(incident_id, "incident_id")
            summary = self._text(sanitized_summary, "sanitized_summary", 2000)
            category = self._text(category, "category", 80)
            if not is_allowed_risk_level(proposed_level):
                raise ValidationError("proposed_level 不在允许的统一等级内")
            if not isinstance(recipient_organizations, list) or not recipient_organizations:
                raise ValidationError("recipient_organizations 必须是非空数组")
            recipients: list[str] = []
            for organization_id in recipient_organizations:
                organization_id = self._identifier(organization_id, "recipient_organizations")
                if organization_id == actor["organization_id"] and actor["role"] != "admin":
                    raise ValidationError("发起方无需把自己列为接收机构")
                if connection.execute("SELECT 1 FROM organizations WHERE organization_id=?",
                                      (organization_id,)).fetchone() is None:
                    raise NotFoundError(f"接收机构不存在: {organization_id}")
                if organization_id not in recipients:
                    recipients.append(organization_id)
            if content_hash is not None and not HEX64.fullmatch(str(content_hash)):
                raise ValidationError("content_hash 必须是 64 位十六进制 SHA-256 指纹")
            summary_hash = digest(summary)
            stored_content_hash = content_hash or digest(summary)
            now = self._now()

            def create() -> tuple[str, str, dict[str, Any]]:
                if connection.execute("SELECT 1 FROM risk_incidents WHERE incident_id=?",
                                      (incident_id,)).fetchone():
                    raise ConflictError("风险事件编号已经存在")
                connection.execute(
                    "INSERT INTO risk_incidents(incident_id,current_version,agreed_level,"
                    "level_locked_at,origin_organization_id,status,withdrawn_at,"
                    "withdrawn_by_actor_id,withdraw_reason,obligation_note,created_at) "
                    "VALUES(?,1,NULL,NULL,?,'active',NULL,NULL,NULL,?,?)",
                    (incident_id, actor["organization_id"],
                     "通告一经送达即产生处置义务，撤回不免除回执义务", now),
                )
                connection.execute(
                    "INSERT INTO risk_incident_versions(incident_id,version,sanitized_summary,"
                    "summary_hash,content_hash,category,proposed_level,revision_note,"
                    "created_by_actor_id,organization_id,created_at) "
                    "VALUES(?,1,?,?,?,?,?,'',?,?,?)",
                    (incident_id, summary, summary_hash, stored_content_hash, category,
                     proposed_level, actor_id, actor["organization_id"], now),
                )
                advisories = []
                for organization_id in recipients:
                    advisory = self._emit_advisory(
                        connection, incident_id=incident_id, version=1,
                        organization_id=organization_id, kind="advisory",
                        status="delivered", after_withdrawal=False,
                    )
                    advisories.append({"organization_id": organization_id,
                                       "advisory_id": advisory.advisory_id,
                                       "sequence_number": advisory.sequence_number})
                append_event(connection, actor_id=actor_id, action="risk_incident.submitted",
                             resource_type="risk_incident", resource_id=incident_id,
                             detail={"version": 1, "category": category,
                                     "proposed_level": proposed_level,
                                     "summary_hash": summary_hash,
                                     "content_hash": stored_content_hash,
                                     "recipients": recipients},
                             occurred_at=now)
                return "risk_incident", incident_id, {"incident_id": incident_id, "version": 1,
                                                       "advisories": advisories}

            return self._idempotent(connection, request_id=request_id,
                                    action="submit_risk_incident", payload=payload, create=create)

    def revise_incident(self, *, request_id: str, actor_id: str, incident_id: str,
                        sanitized_summary: str, category: str, proposed_level: str,
                        revision_note: str) -> WriteReceipt:
        payload = {"actor_id": actor_id, "incident_id": incident_id,
                   "sanitized_summary": sanitized_summary, "category": category,
                   "proposed_level": proposed_level, "revision_note": revision_note}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require_role(actor, SUBMIT_ROLES)
            incident = self._incident(connection, incident_id)
            if actor["role"] != "admin" and actor["organization_id"] != incident["origin_organization_id"]:
                raise PermissionDenied("只有发起机构可以修订事件")
            if incident["status"] != "active":
                raise ConflictError("事件已撤回，不能再修订")
            summary = self._text(sanitized_summary, "sanitized_summary", 2000)
            category = self._text(category, "category", 80)
            if not is_allowed_risk_level(proposed_level):
                raise ValidationError("proposed_level 不在允许的统一等级内")
            note = self._text(revision_note, "revision_note", 500)
            new_version = int(incident["current_version"]) + 1
            summary_hash = digest(summary)
            stored_content_hash = digest(summary)
            now = self._now()

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute(
                    "INSERT INTO risk_incident_versions(incident_id,version,sanitized_summary,"
                    "summary_hash,content_hash,category,proposed_level,revision_note,"
                    "created_by_actor_id,organization_id,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (incident_id, new_version, summary, summary_hash, stored_content_hash,
                     category, proposed_level, note, actor_id, actor["organization_id"], now),
                )
                # 旧通告标记为被取代，但其处置/回执义务仍然保留在不可变流中。
                connection.execute(
                    "UPDATE risk_advisories SET status='superseded' "
                    "WHERE incident_id=? AND status='delivered'", (incident_id,))
                advisories = []
                for organization_id in self._recipients(connection, incident_id):
                    advisory = self._emit_advisory(
                        connection, incident_id=incident_id, version=new_version,
                        organization_id=organization_id, kind="revision",
                        status="delivered", after_withdrawal=False,
                    )
                    advisories.append({"organization_id": organization_id,
                                       "advisory_id": advisory.advisory_id,
                                       "sequence_number": advisory.sequence_number})
                connection.execute(
                    "UPDATE risk_incidents SET current_version=?, agreed_level=NULL, "
                    "level_locked_at=NULL WHERE incident_id=?",
                    (new_version, incident_id),
                )
                append_event(connection, actor_id=actor_id, action="risk_incident.revised",
                             resource_type="risk_incident", resource_id=incident_id,
                             detail={"version": new_version, "category": category,
                                     "proposed_level": proposed_level,
                                     "summary_hash": summary_hash,
                                     "revision_note": note},
                             occurred_at=now)
                return "risk_incident", incident_id, {"incident_id": incident_id,
                                                       "version": new_version,
                                                       "advisories": advisories}

            return self._idempotent(connection, request_id=request_id,
                                    action="revise_risk_incident", payload=payload, create=create)

    def withdraw_incident(self, *, request_id: str, actor_id: str, incident_id: str,
                          reason: str = "") -> WriteReceipt:
        payload = {"actor_id": actor_id, "incident_id": incident_id, "reason": reason}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require_role(actor, SUBMIT_ROLES)
            incident = self._incident(connection, incident_id)
            if actor["role"] != "admin" and actor["organization_id"] != incident["origin_organization_id"]:
                raise PermissionDenied("只有发起机构可以撤回事件")
            if incident["status"] != "active":
                raise ConflictError("事件已经撤回")
            reason = str(reason or "").strip()
            if len(reason) > 300:
                raise ValidationError("reason 不能超过 300 个字符")
            now = self._now()

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute(
                    "UPDATE risk_incidents SET status='withdrawn', withdrawn_at=?, "
                    "withdrawn_by_actor_id=?, withdraw_reason=? WHERE incident_id=?",
                    (now, actor_id, reason, incident_id),
                )
                connection.execute(
                    "UPDATE risk_advisories SET status='withdrawn' "
                    "WHERE incident_id=? AND status='delivered'", (incident_id,))
                # 撤回本身是一条带处置义务的通告：接收方仍须逐条回执确认。
                advisories = []
                for organization_id in self._recipients(connection, incident["incident_id"]):
                    advisory = self._emit_advisory(
                        connection, incident_id=incident_id,
                        version=int(incident["current_version"]),
                        organization_id=organization_id, kind="withdrawal",
                        status="withdrawn", after_withdrawal=True,
                    )
                    advisories.append({"organization_id": organization_id,
                                       "advisory_id": advisory.advisory_id,
                                       "sequence_number": advisory.sequence_number})
                append_event(connection, actor_id=actor_id, action="risk_incident.withdrawn",
                             resource_type="risk_incident", resource_id=incident_id,
                             detail={"version": incident["current_version"],
                                     "reason": reason,
                                     "obligation_retained": True,
                                     "recipient_count": len(advisories)},
                             occurred_at=now)
                return "risk_incident", incident_id, {"incident_id": incident_id,
                                                       "status": "withdrawn",
                                                       "advisories": advisories}

            return self._idempotent(connection, request_id=request_id,
                                    action="withdraw_risk_incident", payload=payload, create=create)

    # ------------------------------------------------------------------ 编号映射与等级协商

    def map_local_reference(self, *, request_id: str, actor_id: str, incident_id: str,
                            local_number: str, local_label: str, version: int | None = None) -> WriteReceipt:
        payload = {"actor_id": actor_id, "incident_id": incident_id,
                   "local_number": local_number, "local_label": local_label, "version": version}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require_role(actor, SUBMIT_ROLES)
            incident = self._incident(connection, incident_id)
            self._require_participant(connection, incident, actor)
            version = int(version) if version is not None else int(incident["current_version"])
            if version < 1 or version > int(incident["current_version"]):
                raise ValidationError("version 超出事件已有版本范围")
            local_number = self._text(local_number, "local_number", 120)
            local_label = self._text(local_label, "local_label", 120)
            now = self._now()

            def create() -> tuple[str, str, dict[str, Any]]:
                existing = connection.execute(
                    "SELECT * FROM risk_local_references WHERE incident_id=? AND organization_id=? AND version=?",
                    (incident_id, actor["organization_id"], version),
                ).fetchone()
                if existing:
                    if existing["local_number"] != local_number or existing["local_label"] != local_label:
                        raise ConflictError("该机构在此版本上的本地编号映射已经存在且内容不同")
                    return "risk_local_reference", existing["reference_id"], {
                        "reference_id": existing["reference_id"]}
                reference_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO risk_local_references(reference_id,incident_id,version,"
                    "organization_id,local_number,local_label,mapped_by_actor_id,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (reference_id, incident_id, version, actor["organization_id"],
                     local_number, local_label, actor_id, now),
                )
                append_event(connection, actor_id=actor_id, action="risk_local_reference.mapped",
                             resource_type="risk_incident", resource_id=incident_id,
                             detail={"version": version, "organization_id": actor["organization_id"],
                                     "local_number": local_number, "local_label": local_label},
                             occurred_at=now)
                return "risk_local_reference", reference_id, {"reference_id": reference_id}

            return self._idempotent(connection, request_id=request_id,
                                    action="map_local_reference", payload=payload, create=create)

    def propose_level(self, *, request_id: str, actor_id: str, incident_id: str,
                      proposed_level: str, note: str = "", version: int | None = None) -> WriteReceipt:
        payload = {"actor_id": actor_id, "incident_id": incident_id,
                   "proposed_level": proposed_level, "note": note, "version": version}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require_role(actor, SUBMIT_ROLES)
            incident = self._incident(connection, incident_id)
            self._require_participant(connection, incident, actor)
            if incident["status"] != "active":
                raise ConflictError("事件已撤回，不能再协商等级")
            version = int(version) if version is not None else int(incident["current_version"])
            if version != int(incident["current_version"]):
                raise ConflictError("只能在当前版本上协商等级，请先处理最新修订")
            if not is_allowed_risk_level(proposed_level):
                raise ValidationError("proposed_level 不在允许的统一等级内")
            note = str(note or "").strip()
            if len(note) > 500:
                raise ValidationError("note 不能超过 500 个字符")
            now = self._now()

            def create() -> tuple[str, str, dict[str, Any]]:
                row = connection.execute(
                    "SELECT COALESCE(MAX(sequence_in_version),0)+1 AS next FROM risk_level_proposals "
                    "WHERE incident_id=? AND version=? AND organization_id=?",
                    (incident_id, version, actor["organization_id"]),
                ).fetchone()
                sequence_in_version = int(row["next"])
                proposal_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO risk_level_proposals(proposal_id,incident_id,version,"
                    "organization_id,proposed_level,note,sequence_in_version,"
                    "proposed_by_actor_id,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (proposal_id, incident_id, version, actor["organization_id"],
                     proposed_level, note, sequence_in_version, actor_id, now),
                )
                append_event(connection, actor_id=actor_id, action="risk_level.proposed",
                             resource_type="risk_incident", resource_id=incident_id,
                             detail={"version": version, "organization_id": actor["organization_id"],
                                     "proposed_level": proposed_level,
                                     "sequence_in_version": sequence_in_version, "note": note},
                             occurred_at=now)
                locked = self._maybe_lock_level(connection, incident, version)
                return "risk_level_proposal", proposal_id, {"proposal_id": proposal_id,
                                                             "version": version,
                                                             "agreed_level": locked}

            return self._idempotent(connection, request_id=request_id,
                                    action="propose_risk_level", payload=payload, create=create)

    # ------------------------------------------------------------------ 回执（确认）

    def acknowledge_advisory(self, *, request_id: str, actor_id: str,
                             advisory_id: str) -> WriteReceipt:
        payload = {"actor_id": actor_id, "advisory_id": advisory_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require_role(actor, CONFIRM_ROLES)
            advisory_row = connection.execute(
                "SELECT * FROM risk_advisories WHERE advisory_id=?", (advisory_id,)
            ).fetchone()
            if advisory_row is None:
                raise NotFoundError("通告不存在")
            incident = self._incident(connection, advisory_row["incident_id"])
            self._require_recipient(connection, incident, actor)
            if actor["role"] != "admin" and advisory_row["target_organization_id"] != actor["organization_id"]:
                raise PermissionDenied("只能代表本机构确认通告")
            now = self._now()

            def create() -> tuple[str, str, dict[str, Any]]:
                duplicate = connection.execute(
                    "SELECT receipt_id FROM risk_receipts WHERE advisory_id=?", (advisory_id,)
                ).fetchone()
                if duplicate:
                    raise ConflictError("该通告已经完成回执")
                # 强制按事件内的顺序补齐：上一序号未回执前，不得回执后续通告。
                acked_row = connection.execute(
                    "SELECT COALESCE(MAX(a.ordinal),0) AS acked FROM risk_advisories a "
                    "JOIN risk_receipts r ON r.advisory_id=a.advisory_id "
                    "WHERE a.incident_id=? AND a.target_organization_id=?",
                    (advisory_row["incident_id"], advisory_row["target_organization_id"]),
                ).fetchone()
                if int(acked_row["acked"]) != int(advisory_row["ordinal"]) - 1:
                    raise ConflictError("存在更早的通告尚未回执，请按顺序补齐后再确认")
                receipt_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO risk_receipts(receipt_id,advisory_id,incident_id,version,"
                    "organization_id,acknowledged_at,acknowledged_by_actor_id) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (receipt_id, advisory_id, advisory_row["incident_id"],
                     advisory_row["version"], advisory_row["target_organization_id"],
                     now, actor_id),
                )
                append_event(connection, actor_id=actor_id, action="risk_advisory.acknowledged",
                             resource_type="risk_advisory", resource_id=advisory_id,
                             detail={"incident_id": advisory_row["incident_id"],
                                     "version": advisory_row["version"],
                                     "ordinal": advisory_row["ordinal"],
                                     "kind": advisory_row["kind"],
                                     "after_withdrawal": bool(advisory_row["after_withdrawal"]),
                                     "organization_id": advisory_row["target_organization_id"]},
                             occurred_at=now)
                response = {"receipt_id": receipt_id, "advisory_id": advisory_id,
                            "incident_id": advisory_row["incident_id"],
                            "version": advisory_row["version"],
                            "after_withdrawal": bool(advisory_row["after_withdrawal"])}
                return "risk_receipt", receipt_id, response

            return self._idempotent(connection, request_id=request_id,
                                    action="acknowledge_risk_advisory", payload=payload, create=create)

    # ------------------------------------------------------------------ 离线补齐与查询

    def pull_pending(self, actor_id: str, *, organization_id: str | None = None,
                     after_sequence: int = 0, limit: int = 100) -> dict[str, Any]:
        """按机构 outbox 的单调顺序返回待办；离线期间积压的通告在重连后依次补齐。"""

        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            self._require_role(actor, VIEW_ROLES)
            target_org = organization_id or actor["organization_id"]
            if target_org != actor["organization_id"] and actor["role"] != "admin":
                raise PermissionDenied("只能拉取本机构的待办通告")
            if not isinstance(after_sequence, int) or after_sequence < 0:
                raise ValidationError("after_sequence 必须是非负整数")
            if not isinstance(limit, int) or not 1 <= limit <= 200:
                raise ValidationError("limit 必须在 1 到 200 之间")
            items: list[DeliveryItem] = []
            rows = connection.execute(
                "SELECT o.sequence_number, o.incident_id, o.advisory_id, o.version, o.kind, "
                "o.after_withdrawal, o.created_at, a.status AS current_status, "
                "r.receipt_id IS NOT NULL AS acked FROM risk_outbox o "
                "JOIN risk_advisories a ON a.advisory_id=o.advisory_id "
                "LEFT JOIN risk_receipts r ON r.advisory_id=o.advisory_id "
                "WHERE o.organization_id=? AND o.sequence_number>? "
                "ORDER BY o.sequence_number ASC LIMIT ?",
                (target_org, after_sequence, limit),
            ).fetchall()
            for row in rows:
                items.append(DeliveryItem(
                    row["sequence_number"], row["incident_id"], row["advisory_id"],
                    row["version"], row["kind"], row["current_status"],
                    bool(row["after_withdrawal"]), bool(row["acked"]), row["created_at"],
                ))
            if rows:
                connection.execute(
                    "INSERT INTO risk_delivery_cursors(organization_id,last_sequence) VALUES(?,?) "
                    "ON CONFLICT(organization_id) DO UPDATE SET last_sequence=excluded.last_sequence",
                    (target_org, max(int(row["sequence_number"]) for row in rows)),
                )
            return {
                "organization_id": target_org,
                "items": [item.__dict__ for item in items],
                "next_after_sequence": items[-1].sequence_number if items else after_sequence,
                "has_more": len(items) == limit,
            }

    def get_incident(self, actor_id: str, incident_id: str) -> dict[str, Any]:
        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            self._require_role(actor, VIEW_ROLES)
            incident = self._incident(connection, incident_id)
            self._require_participant(connection, incident, actor)
            versions = [
                IncidentVersion(row["version"], row["sanitized_summary"], row["summary_hash"],
                                row["content_hash"], row["category"], row["proposed_level"],
                                row["revision_note"], row["created_by_actor_id"],
                                row["organization_id"], row["created_at"]).__dict__
                for row in connection.execute(
                    "SELECT * FROM risk_incident_versions WHERE incident_id=? ORDER BY version",
                    (incident_id,))
            ]
            references = [
                LocalReference(row["reference_id"], row["incident_id"], row["version"],
                               row["organization_id"], row["local_number"], row["local_label"],
                               row["mapped_by_actor_id"], row["created_at"]).__dict__
                for row in connection.execute(
                    "SELECT * FROM risk_local_references WHERE incident_id=? "
                    "ORDER BY version, organization_id", (incident_id,))
            ]
            proposals = [
                LevelProposal(row["proposal_id"], row["incident_id"], row["version"],
                              row["organization_id"], row["proposed_level"], row["note"],
                              row["proposed_by_actor_id"], row["created_at"]).__dict__
                for row in connection.execute(
                    "SELECT * FROM risk_level_proposals WHERE incident_id=? "
                    "ORDER BY version, sequence_in_version", (incident_id,))
            ]
            stances = self._latest_stances(connection, incident, int(incident["current_version"]))
            result = {
                "incident_id": incident["incident_id"],
                "current_version": incident["current_version"],
                "status": incident["status"],
                "origin_organization_id": incident["origin_organization_id"],
                "agreed_level": incident["agreed_level"],
                "level_locked_at": incident["level_locked_at"],
                "withdrawn_at": incident["withdrawn_at"],
                "withdraw_reason": incident["withdraw_reason"],
                "participant_organizations": self._participants(connection, incident),
                "recipient_organizations": self._recipients(connection, incident["incident_id"]),
                "current_stances": stances,
                "versions": versions,
                "local_references": references,
                "level_proposals": proposals,
            }
            viewer_org = actor["organization_id"]
            is_recipient = viewer_org in self._recipients(connection, incident_id)
            if is_recipient or actor["role"] == "admin":
                result["my_advisories"] = [
                    self._advisory_dict(row)
                    for row in connection.execute(
                        "SELECT * FROM risk_advisories WHERE incident_id=? "
                        "AND target_organization_id=? ORDER BY ordinal",
                        (incident_id, viewer_org))
                ]
            return result

    @staticmethod
    def _advisory_dict(row) -> dict[str, Any]:
        return {
            "advisory_id": row["advisory_id"],
            "incident_id": row["incident_id"],
            "version": row["version"],
            "target_organization_id": row["target_organization_id"],
            "ordinal": row["ordinal"],
            "kind": row["kind"],
            "status": row["status"],
            "after_withdrawal": bool(row["after_withdrawal"]),
            "sequence_number": row["sequence_number"],
            "created_at": row["created_at"],
        }

    def receipt_status(self, actor_id: str, incident_id: str) -> dict[str, Any]:
        """展示各接收机构的处置义务完成情况，包括撤回后仍待回执的通告。"""

        with self.database.transaction() as connection:
            actor = self._actor(connection, actor_id)
            self._require_role(actor, VIEW_ROLES)
            incident = self._incident(connection, incident_id)
            self._require_participant(connection, incident, actor)
            organizations = []
            completed_count = 0
            for organization_id in self._recipients(connection, incident["incident_id"]):
                rows = connection.execute(
                    "SELECT a.ordinal, a.version, a.kind, a.status, a.after_withdrawal, "
                    "a.advisory_id, r.receipt_id IS NOT NULL AS acked, r.acknowledged_at "
                    "FROM risk_advisories a LEFT JOIN risk_receipts r ON r.advisory_id=a.advisory_id "
                    "WHERE a.incident_id=? AND a.target_organization_id=? ORDER BY a.ordinal",
                    (incident_id, organization_id),
                ).fetchall()
                pending = [{
                    "ordinal": row["ordinal"],
                    "version": row["version"],
                    "kind": row["kind"],
                    "status": row["status"],
                    "after_withdrawal": bool(row["after_withdrawal"]),
                } for row in rows if not row["acked"]]
                acked_count = sum(1 for row in rows if row["acked"])
                if not pending:
                    completed_count += 1
                organizations.append({
                    "organization_id": organization_id,
                    "total_obligations": len(rows),
                    "acknowledged": acked_count,
                    "completed": not pending,
                    "pending": pending,
                })
            return {
                "incident_id": incident_id,
                "status": incident["status"],
                "recipient_count": len(organizations),
                "completed_count": completed_count,
                "organizations": organizations,
            }
