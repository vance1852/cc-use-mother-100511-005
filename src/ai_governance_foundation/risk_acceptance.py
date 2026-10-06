"""运行跨机构风险沟通的离线端到端验收。

场景对应联合安全评估中的真实分歧：机构甲已隔离风险，机构乙仍按普通提醒处理。
验收覆盖编号映射、等级协商、修订追溯、撤回保留义务、离线待办按序补齐与回执统计。
"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .clock import FixedClock
from .risk_service import RiskService
from .service import DomainService
from .storage import Database


def run() -> dict[str, object]:
    """执行完整跨机构沟通链并返回结果。"""

    with tempfile.TemporaryDirectory() as directory:
        database = Database(Path(directory) / "risk_acceptance.sqlite3")
        base = datetime(2026, 10, 6, 8, 0, tzinfo=timezone.utc)
        service = DomainService(database, FixedClock(base))
        risk = RiskService(database, FixedClock(base))

        # 建档：甲（已采取隔离措施）、乙（误判为普通提醒）
        service.register_organization(request_id="org-jia", actor_id="bootstrap",
                                      organization_id="jia", name="机构甲")
        service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="admin-jia",
                               display_name="甲管理员", role="admin", organization_id="jia")
        service.register_organization(request_id="org-yi", actor_id="admin-jia",
                                      organization_id="yi", name="机构乙")
        service.register_actor(request_id="actor-jia", actor_id="admin-jia", new_actor_id="op-jia",
                               display_name="甲联络员", role="operator", organization_id="jia")
        service.register_actor(request_id="actor-yi", actor_id="admin-jia", new_actor_id="op-yi",
                               display_name="乙联络员", role="operator", organization_id="yi")
        for request_id, target, capability in (
            ("cap-jia-submit", "op-jia", "risk:submit"),
            ("cap-jia-view", "op-jia", "risk:view"),
            ("cap-jia-confirm", "op-jia", "risk:confirm"),
            ("cap-yi-submit", "op-yi", "risk:submit"),
            ("cap-yi-view", "op-yi", "risk:view"),
            ("cap-yi-confirm", "op-yi", "risk:confirm"),
        ):
            risk.grant_capability(request_id=request_id, actor_id="admin-jia",
                                  target_actor_id=target, capability=capability)

        # 甲提交事件摘要（原文只在参与边界内可见），双方各自挂本地编号
        submitted = risk.submit_risk_event(
            request_id="submit-1", actor_id="op-jia",
            summary="联合评估批次七出现对抗样本投毒迹象，影响模型风控模块",
            proposed_level="high", recipient_organizations=["yi"],
            origin_local_reference="JIA-ISO-2026-0117")
        event_id = submitted.resource_id
        risk.map_local_reference(request_id="map-yi", actor_id="op-yi", event_id=event_id,
                                 local_reference="YI-NOTICE-8842")

        # 乙最初按普通提醒处理，统一等级未能达成
        risk.propose_level(request_id="level-jia-1", actor_id="op-jia", event_id=event_id,
                           revision=1, proposed_level="high", rationale="已隔离受影响节点")
        risk.propose_level(request_id="level-yi-1", actor_id="op-yi", event_id=event_id,
                           revision=1, proposed_level="info", rationale="暂按普通提醒观察")
        before = risk.communication_status("op-jia", event_id)

        # 协商：乙复核甲提供的摘要后改判 high，意见一致，统一等级定稿并生成处置义务
        risk.propose_level(request_id="level-yi-2", actor_id="op-yi", event_id=event_id,
                           revision=1, proposed_level="high", rationale="复核确认，启动隔离")
        agreed = risk.communication_status("op-jia", event_id)
        obligations = risk.list_obligations("op-yi")

        # 乙离线期间：甲发布修订、随后撤回通报；消息全部进入乙的有序待办
        risk.revise_risk_event(request_id="revise-2", actor_id="op-jia", event_id=event_id,
                               change_note="补充影响范围", proposed_level="high",
                               summary="联合评估批次七、八出现对抗样本投毒迹象，影响风控与审计模块")
        withdrawn = risk.withdraw_event(request_id="withdraw-1", actor_id="op-jia",
                                        event_id=event_id, reason="源头误报，停止后续通报")
        offline_pending = risk.list_pending("op-yi")

        # 乙重新连接：按序看到待办，直接确认最新修订，历史回执自动补齐
        receipt = risk.acknowledge_revision("op-yi", event_id, 2, note="离线补齐，已按序接收")
        after_reconnect = risk.communication_status("op-jia", event_id)

        # 撤回不抹除处置义务，乙仍须履行
        obligations_after_withdraw = risk.list_obligations("op-yi")
        discharge = risk.discharge_obligation("op-yi", obligations_after_withdraw[0]["obligation_id"],
                                              note="隔离核查已闭环")
        final_view = risk.get_risk_event("op-yi", event_id)
        audit_valid, audit_events = service.verify_audit()

        result = {
            "status": "ok",
            "event_id": event_id,
            "level_before_negotiation": before["agreed_level"],
            "agreed_level": agreed["agreed_level"],
            "obligations_created": len(obligations),
            "offline_queue": [item.kind for item in offline_pending],
            "withdrawn": withdrawn.resource_id == event_id
                and final_view.status == "withdrawn",
            "receipt_revisions": next(
                item["acked_revisions"] for item in after_reconnect["organizations"]
                if item["organization_id"] == "yi"),
            "pending_receipt_orgs": after_reconnect["organizations_pending_receipt"],
            "obligations_survive_withdrawal": len(obligations_after_withdraw) == 1
                and obligations_after_withdraw[0]["status"] == "open",
            "obligation_discharged": discharge["status"] == "discharged",
            "revisions_preserved": len(final_view.revisions),
            "audit_valid": audit_valid,
            "audit_events": audit_events,
        }
        database.close()
        return result


def main() -> int:
    """打印验收结果并设置退出码。"""

    result = run()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "ok" and result["audit_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
