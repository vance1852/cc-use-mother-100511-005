"""运行基础服务与跨机构风险沟通的离线端到端验收。"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .clock import FixedClock
from .risk import RiskCommunicationService
from .service import DomainService
from .storage import Database


def run() -> dict[str, object]:
    """执行登记链与跨机构风险沟通链并返回结果。"""

    with tempfile.TemporaryDirectory() as directory:
        database = Database(Path(directory) / "acceptance.sqlite3")
        clock = FixedClock(datetime(2026, 10, 6, 8, 0, tzinfo=timezone.utc))
        service = DomainService(database, clock)
        risk = RiskCommunicationService(database, clock)

        # ---- 基础登记链 ----
        service.register_organization(request_id="req-org", actor_id="bootstrap",
                                      organization_id="org-001", name="示范科研机构")
        service.register_actor(request_id="req-admin", actor_id="bootstrap", new_actor_id="admin-001",
                               display_name="系统管理员", role="admin", organization_id="org-001")
        service.register_actor(request_id="req-operator", actor_id="admin-001", new_actor_id="operator-001",
                               display_name="项目负责人", role="operator", organization_id="org-001")
        service.register_site(request_id="req-site", actor_id="operator-001", site_id="site-001",
                              organization_id="org-001", name="一号创新节点", timezone_name="Asia/Shanghai")
        first = service.record_domain_data(request_id="req-data", actor_id="operator-001", site_id="site-001",
                                           category="institution_profile", external_key="record-001",
                                           data={"name": "基础资料", "enabled": True})
        replay = service.record_domain_data(request_id="req-data", actor_id="operator-001", site_id="site-001",
                                            category="institution_profile", external_key="record-001",
                                            data={"name": "基础资料", "enabled": True})

        # ---- 跨机构风险沟通链 ----
        service.register_organization(request_id="req-org-b", actor_id="admin-001",
                                      organization_id="org-002", name="联合评估机构乙")
        service.register_organization(request_id="req-org-c", actor_id="admin-001",
                                      organization_id="org-003", name="联合评估机构丙")
        service.register_actor(request_id="req-op-b", actor_id="admin-001", new_actor_id="op-b",
                               display_name="乙提交人", role="operator", organization_id="org-002")
        service.register_actor(request_id="req-rv-b", actor_id="admin-001", new_actor_id="rv-b",
                               display_name="乙确认人", role="reviewer", organization_id="org-002")
        service.register_actor(request_id="req-op-c", actor_id="admin-001", new_actor_id="op-c",
                               display_name="丙提交人", role="operator", organization_id="org-003")
        service.register_actor(request_id="req-rv-c", actor_id="admin-001", new_actor_id="rv-c",
                               display_name="丙确认人", role="reviewer", organization_id="org-003")

        # 机构甲提交脱敏事件（只给摘要与内容指纹，不给原始敏感内容），统一等级 high，通告乙、丙。
        risk.submit_incident(
            request_id="req-risk", actor_id="operator-001", incident_id="risk-001",
            sanitized_summary="某模型在受限场景产生越权建议（摘要已脱敏）",
            category="model_output", proposed_level="high",
            recipient_organizations=["org-002", "org-003"])
        # 各方把自己的本地编号与本地敏感级别映射到同一事件：甲已隔离，乙原当作普通提醒。
        risk.map_local_reference(request_id="req-map-a", actor_id="operator-001",
                                 incident_id="risk-001", local_number="JIA-ISO-2026-17",
                                 local_label="隔离")
        risk.map_local_reference(request_id="req-map-b", actor_id="op-b",
                                 incident_id="risk-001", local_number="YI-NOTE-7781",
                                 local_label="普通提醒")
        # 协商统一等级：乙先误判 medium，改判 high；丙主张 high；甲版本提案 high => 全员一致定格。
        risk.propose_level(request_id="req-lvl-b1", actor_id="op-b", incident_id="risk-001",
                           proposed_level="medium", note="初判仅需关注")
        risk.propose_level(request_id="req-lvl-b2", actor_id="op-b", incident_id="risk-001",
                           proposed_level="high", note="复核后确认需隔离")
        risk.propose_level(request_id="req-lvl-c", actor_id="op-c", incident_id="risk-001",
                           proposed_level="high", note="同意统一高级")
        agreed_before = risk.get_incident("operator-001", "risk-001")["agreed_level"]

        # 事件修订：生成不可变 v2，旧通告被取代，统一等级重新协商。
        risk.revise_incident(request_id="req-risk-rev", actor_id="operator-001",
                             incident_id="risk-001",
                             sanitized_summary="某模型越权建议，影响范围已补充（摘要已脱敏）",
                             category="model_output", proposed_level="high",
                             revision_note="补充受影响场景范围")
        risk.propose_level(request_id="req-lvl-b-v2", actor_id="op-b", incident_id="risk-001",
                           proposed_level="high", note="v2 维持高级")
        risk.propose_level(request_id="req-lvl-c-v2", actor_id="op-c", incident_id="risk-001",
                           proposed_level="high", note="v2 同意")
        agreed_after = risk.get_incident("operator-001", "risk-001")["agreed_level"]

        # 乙在 v2 发布期间离线；重连后按顺序补齐 v1、v2 两条并逐条回执。
        backlog_b = risk.pull_pending("rv-b", after_sequence=0)["items"]
        for item in backlog_b:
            risk.acknowledge_advisory(request_id=f"req-ack-b-{item['sequence_number']}",
                                      actor_id="rv-b", advisory_id=item["advisory_id"])

        # 撤回：不抹除义务，乙、丙仍须对撤回通告回执。
        risk.withdraw_incident(request_id="req-risk-wd", actor_id="operator-001",
                               incident_id="risk-001", reason="确认源数据标注错误")
        withdrawal_b = next(item for item in risk.pull_pending("rv-b", after_sequence=2)["items"]
                            if item["kind"] == "withdrawal")
        risk.acknowledge_advisory(request_id="req-ack-b-wd", actor_id="rv-b",
                                  advisory_id=withdrawal_b["advisory_id"])
        backlog_c = risk.pull_pending("rv-c", after_sequence=0)["items"]
        for item in backlog_c:
            risk.acknowledge_advisory(request_id=f"req-ack-c-{item['sequence_number']}",
                                      actor_id="rv-c", advisory_id=item["advisory_id"])
        status = risk.receipt_status("operator-001", "risk-001")

        valid, event_count = service.verify_audit()
        records = service.list_domain_data("site-001")
        result = {"status": "ok", "records": len(records), "audit_events": event_count,
                  "audit_valid": valid, "first_replayed": first.replayed,
                  "second_replayed": replay.replayed,
                  "risk_versions": risk.get_incident("operator-001", "risk-001")["current_version"],
                  "risk_agreed_before_revision": agreed_before,
                  "risk_agreed_after_revision": agreed_after,
                  "risk_backlog_b_sequence": [item["sequence_number"] for item in backlog_b],
                  "risk_withdrawal_obligation_acked": withdrawal_b["after_withdrawal"],
                  "risk_completed_organizations": status["completed_count"],
                  "risk_recipient_count": status["recipient_count"],
                  "risk_final_status": status["status"]}
        database.close()
        return result


def main() -> int:
    """打印验收结果并设置退出码。"""

    result = run()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "ok" and result["audit_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
