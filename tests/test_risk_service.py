import unittest
from datetime import datetime, timezone

from ai_governance_foundation.clock import FixedClock
from ai_governance_foundation.errors import (
    ConflictError,
    NotFoundError,
    PermissionDenied,
    ValidationError,
)
from ai_governance_foundation.risk_service import RiskService
from ai_governance_foundation.service import DomainService
from ai_governance_foundation.storage import Database


class RiskServiceTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        clock = FixedClock(datetime(2026, 10, 6, 8, 0, tzinfo=timezone.utc))
        self.service = DomainService(self.database, clock)
        self.risk = RiskService(self.database, clock)
        self.service.register_organization(request_id="org1", actor_id="bootstrap",
                                           organization_id="o1", name="机构甲")
        self.service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="a1",
                                    display_name="甲管理员", role="admin", organization_id="o1")
        self.service.register_organization(request_id="org2", actor_id="a1",
                                           organization_id="o2", name="机构乙")
        self.service.register_organization(request_id="org3", actor_id="a1",
                                           organization_id="o3", name="机构丙")
        for request_id, actor, name, org in (
            ("reg-op1", "op1", "甲操作员", "o1"),
            ("reg-op2", "op2", "乙操作员", "o2"),
            ("reg-op3", "op3", "丙操作员", "o3"),
        ):
            self.service.register_actor(request_id=request_id, actor_id="a1", new_actor_id=actor,
                                        display_name=name, role="operator", organization_id=org)
        for target, caps in (
            ("op1", ("risk:submit", "risk:view", "risk:confirm")),
            ("op2", ("risk:submit", "risk:view", "risk:confirm")),
            ("op3", ("risk:submit", "risk:view", "risk:confirm")),
        ):
            for index, cap in enumerate(caps):
                self.risk.grant_capability(request_id=f"grant-{target}-{index}", actor_id="a1",
                                           target_actor_id=target, capability=cap)

    def tearDown(self):
        self.database.close()

    def _submit(self, request_id="evt1", level="high"):
        return self.risk.submit_risk_event(
            request_id=request_id, actor_id="op1",
            summary="模型输出异常，疑似训练数据投毒，影响联合评估批次七",
            proposed_level=level,
            recipient_organizations=["o2", "o3"],
            origin_local_reference="JIA-RISK-2026-1001",
        )

    def test_submit_requires_capability(self):
        with self.assertRaises(PermissionDenied):
            self.risk.submit_risk_event(
                request_id="blocked", actor_id="a1", summary="无授权提交",
                proposed_level="high", recipient_organizations=["o2"])

    def test_submit_enqueues_for_each_recipient_in_order(self):
        receipt = self._submit()
        event_id = receipt.resource_id
        pending_o2 = self.risk.list_pending("op2")
        self.assertEqual(["submitted"], [item.kind for item in pending_o2])
        self.assertEqual(1, pending_o2[0].revision)
        pending_o3 = self.risk.list_pending("op3")
        self.assertEqual(event_id, pending_o3[0].event_id)
        self.assertEqual(1, pending_o3[0].seq)

    def test_non_participant_cannot_view_plaintext_summary(self):
        event_id = self._submit().resource_id
        # 给 o2 人员查看是可以看到原文的
        view = self.risk.get_risk_event("op2", event_id)
        self.assertIn("训练数据投毒", view.latest_summary)
        # 其他未参与机构即使有 view 权限也看不到
        self.service.register_organization(request_id="org4", actor_id="a1",
                                           organization_id="o4", name="机构丁")
        self.service.register_actor(request_id="op4", actor_id="a1", new_actor_id="op4",
                                    display_name="丁操作员", role="operator", organization_id="o4")
        self.risk.grant_capability(request_id="grant-op4", actor_id="a1",
                                   target_actor_id="op4", capability="risk:view")
        with self.assertRaises(PermissionDenied):
            self.risk.get_risk_event("op4", event_id)

    def test_local_mappings_align_different_numbering(self):
        event_id = self._submit().resource_id
        self.risk.map_local_reference(request_id="map-o2", actor_id="op2",
                                      event_id=event_id, local_reference="YI-ALERT-7788")
        status = self.risk.communication_status("op1", event_id)
        references = {row["organization_id"]: row["local_reference"]
                      for row in status["organizations"]}
        self.assertEqual("JIA-RISK-2026-1001", references["o1"])
        self.assertEqual("YI-ALERT-7788", references["o2"])
        self.assertIsNone(references["o3"])
        # 同一本地编号不能映射到两个事件
        second = self.risk.submit_risk_event(
            request_id="evt2", actor_id="op1", summary="第二个风险事件",
            proposed_level="low", recipient_organizations=["o2"])
        with self.assertRaises(ConflictError):
            self.risk.map_local_reference(request_id="map-dup", actor_id="op2",
                                          event_id=second.resource_id,
                                          local_reference="YI-ALERT-7788")

    def test_unanimous_proposals_set_agreed_level_and_create_obligations(self):
        event_id = self._submit(level="high").resource_id
        # 起初丙机构误判为普通提醒
        self.risk.propose_level(request_id="lv-o2", actor_id="op2", event_id=event_id,
                                revision=1, proposed_level="high", rationale="与甲一致，需要隔离")
        self.risk.propose_level(request_id="lv-o3-low", actor_id="op3", event_id=event_id,
                                revision=1, proposed_level="info", rationale="暂按普通提醒")
        view = self.risk.get_risk_event("op1", event_id)
        self.assertIsNone(view.agreed_level)
        obligations = self.risk.list_obligations("op2")
        self.assertEqual([], obligations)
        # 丙机构复核后调整为 high，三家意见一致，统一等级定稿
        self.risk.propose_level(request_id="lv-o3-high", actor_id="op3", event_id=event_id,
                                revision=1, proposed_level="high", rationale="复核确认需要隔离")
        view = self.risk.get_risk_event("op1", event_id)
        self.assertEqual("high", view.agreed_level)
        obligations = self.risk.list_obligations("op2")
        self.assertEqual(1, len(obligations))
        self.assertEqual("open", obligations[0]["status"])
        self.assertEqual("high", obligations[0]["required_level"])
        # 定稿后不能再改票
        with self.assertRaises(ConflictError):
            self.risk.propose_level(request_id="lv-o3-critical", actor_id="op3",
                                    event_id=event_id, revision=1,
                                    proposed_level="critical", rationale="升级")

    def test_revisions_are_traceable_and_reset_negotiation(self):
        event_id = self._submit().resource_id
        self.risk.propose_level(request_id="lv1-o2", actor_id="op2", event_id=event_id,
                                revision=1, proposed_level="high", rationale="一致")
        self.risk.propose_level(request_id="lv1-o3", actor_id="op3", event_id=event_id,
                                revision=1, proposed_level="high", rationale="一致")
        self.assertEqual("high", self.risk.get_risk_event("op1", event_id).agreed_level)
        receipt = self.risk.revise_risk_event(
            request_id="rev2", actor_id="op1", event_id=event_id,
            change_note="补充受影响系统范围", summary="修订后的摘要：影响扩大到批次八")
        self.assertEqual(f"{event_id}:2", receipt.resource_id)
        self.assertEqual(2, self.risk.get_risk_event("op1", event_id).current_revision)
        view = self.risk.get_risk_event("op2", event_id)
        self.assertIsNone(view.agreed_level)
        self.assertEqual(2, len(view.revisions))
        self.assertEqual("首次提交", view.revisions[0].change_note)
        self.assertIn("批次八", view.revisions[1].summary)
        # 两版摘要值不同，历史不可变
        self.assertNotEqual(view.revisions[0].content_hash, view.revisions[1].content_hash)
        pending = self.risk.list_pending("op2")
        self.assertEqual(["submitted", "level_agreed", "revised"],
                         [item.kind for item in pending])

    def test_ack_backfills_earlier_revisions_in_order(self):
        event_id = self._submit().resource_id
        self.risk.revise_risk_event(request_id="rev2", actor_id="op1", event_id=event_id,
                                    change_note="补充", summary="第二版摘要")
        # 接收方离线，重连后直接确认第二版
        receipt = self.risk.acknowledge_revision("op2", event_id, 2, note="已按序接收")
        self.assertEqual(2, receipt.revision)
        status = self.risk.communication_status("op1", event_id)
        o2 = next(row for row in status["organizations"] if row["organization_id"] == "o2")
        self.assertEqual([1, 2], o2["acked_revisions"])
        self.assertTrue(o2["receipt_complete"])
        self.assertEqual([], o2["pending_deliveries"])
        # 丙机构尚未回执
        self.assertIn("o3", status["organizations_pending_receipt"])
        self.assertNotIn("o2", status["organizations_pending_receipt"])

    def test_withdrawal_preserves_obligations(self):
        event_id = self._submit().resource_id
        self.risk.propose_level(request_id="lv-o2", actor_id="op2", event_id=event_id,
                                revision=1, proposed_level="high", rationale="一致")
        self.risk.propose_level(request_id="lv-o3", actor_id="op3", event_id=event_id,
                                revision=1, proposed_level="high", rationale="一致")
        obligations = self.risk.list_obligations("op2")
        self.assertEqual(1, len(obligations))
        result = self.risk.withdraw_event(request_id="wd1", actor_id="op1",
                                          event_id=event_id, reason="误报，撤销通报")
        self.assertFalse(result.replayed)
        self.assertEqual("withdrawn", self.risk.get_risk_event("op1", event_id).status)
        # 处置义务仍然存在且可以履行
        obligations = self.risk.list_obligations("op2")
        self.assertEqual(1, len(obligations))
        self.assertEqual("open", obligations[0]["status"])
        discharged = self.risk.discharge_obligation("op2", obligations[0]["obligation_id"],
                                                    note="已完成隔离核查")
        self.assertEqual("discharged", discharged["status"])
        # 撤回通知进入离线队列，历史修订仍可追溯
        pending = self.risk.list_pending("op3")
        self.assertEqual("withdrawn", pending[-1].kind)
        self.assertEqual(1, len(self.risk.get_risk_event("op1", event_id).revisions))

    def test_withdraw_then_revise_rejected(self):
        event_id = self._submit().resource_id
        self.risk.withdraw_event(request_id="wd", actor_id="op1", event_id=event_id,
                                 reason="误报")
        with self.assertRaises(ConflictError):
            self.risk.revise_risk_event(request_id="rev2", actor_id="op1",
                                        event_id=event_id, change_note="撤回后修订")

    def test_capabilities_are_distinct(self):
        event_id = self._submit().resource_id
        # 没有 confirm 权限的查看者不能回执，也不能主张等级
        self.service.register_actor(request_id="viewer", actor_id="a1", new_actor_id="v1",
                                    display_name="只读员", role="reviewer", organization_id="o1")
        self.risk.grant_capability(request_id="grant-v1", actor_id="a1",
                                   target_actor_id="v1", capability="risk:view")
        with self.assertRaises(PermissionDenied):
            self.risk.acknowledge_revision("v1", event_id, 1)
        with self.assertRaises(PermissionDenied):
            self.risk.propose_level(request_id="v1-level", actor_id="v1", event_id=event_id,
                                    revision=1, proposed_level="low", rationale="越权")
        # 只有 confirm 权限的接收方可以回执，但不能发起事件
        self.service.register_actor(request_id="confirmer", actor_id="a1", new_actor_id="c2",
                                    display_name="乙确认员", role="operator", organization_id="o2")
        self.risk.grant_capability(request_id="grant-c2", actor_id="a1",
                                   target_actor_id="c2", capability="risk:confirm")
        with self.assertRaises(PermissionDenied):
            self.risk.get_risk_event("c2", event_id)
        receipt = self.risk.acknowledge_revision("c2", event_id, 1)
        self.assertEqual(1, receipt.revision)
        with self.assertRaises(PermissionDenied):
            self.risk.submit_risk_event(
                request_id="c2-submit", actor_id="c2", summary="越权",
                proposed_level="low", recipient_organizations=["o1"])

    def test_idempotent_replays(self):
        first = self._submit(request_id="same")
        second = self._submit(request_id="same")
        self.assertFalse(first.replayed)
        self.assertTrue(second.replayed)
        self.assertEqual(first.resource_id, second.resource_id)
        # 接收方队列没有重复投递
        self.assertEqual(1, len(self.risk.list_pending("op2")))
        with self.assertRaises(ConflictError):
            self.risk.submit_risk_event(
                request_id="same", actor_id="op1", summary="不同内容",
                proposed_level="high", recipient_organizations=["o2", "o3"])

    def test_acknowledging_unknown_revision_is_not_found(self):
        event_id = self._submit().resource_id
        with self.assertRaises(NotFoundError):
            self.risk.acknowledge_revision("op2", event_id, 9)

    def test_originator_cannot_ack_own_event(self):
        event_id = self._submit().resource_id
        with self.assertRaises(PermissionDenied):
            self.risk.acknowledge_revision("op1", event_id, 1)

    def test_audit_chain_remains_valid_and_excludes_plaintext(self):
        event_id = self._submit().resource_id
        self.risk.revise_risk_event(request_id="rev2", actor_id="op1", event_id=event_id,
                                    change_note="敏感的内部处置说明", summary="第二版")
        self.risk.withdraw_event(request_id="wd", actor_id="op1", event_id=event_id,
                                 reason="敏感撤回原因")
        valid, count = self.service.verify_audit()
        self.assertTrue(valid)
        self.assertGreater(count, 0)
        events = self.service.audit_events()
        serialized = str(events)
        self.assertNotIn("训练数据投毒", serialized)
        self.assertNotIn("敏感的内部处置说明", serialized)
        self.assertNotIn("敏感撤回原因", serialized)


if __name__ == "__main__":
    unittest.main()
