import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ai_governance_foundation.clock import FixedClock
from ai_governance_foundation.errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from ai_governance_foundation.risk import RiskCommunicationService
from ai_governance_foundation.service import DomainService
from ai_governance_foundation.storage import Database


class RiskServiceTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        clock = FixedClock(datetime(2026, 10, 6, tzinfo=timezone.utc))
        self.service = DomainService(self.database, clock)
        self.risk = RiskCommunicationService(self.database, clock)
        self.service.register_organization(request_id="org1", actor_id="bootstrap",
                                           organization_id="o1", name="机构一")
        self.service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="a1",
                                    display_name="管理员", role="admin", organization_id="o1")
        for oid, name in (("o2", "机构二"), ("o3", "机构三"), ("o4", "机构四")):
            self.service.register_organization(request_id=f"org-{oid}", actor_id="a1",
                                               organization_id=oid, name=name)
        for aid, role, oid in (("op1", "operator", "o1"), ("op2", "operator", "o2"),
                               ("op3", "operator", "o3"), ("op4", "operator", "o4"),
                               ("rv2", "reviewer", "o2"), ("rv3", "reviewer", "o3"),
                               ("au1", "auditor", "o1")):
            self.service.register_actor(request_id=f"actor-{aid}", actor_id="a1",
                                        new_actor_id=aid, display_name=aid, role=role,
                                        organization_id=oid)
        self.risk.submit_incident(
            request_id="inc1", actor_id="op1", incident_id="inc-1",
            sanitized_summary="某模型输出风险（已脱敏）", category="model_output",
            proposed_level="high", recipient_organizations=["o2", "o3"])

    def tearDown(self):
        self.database.close()

    def _advisory_for(self, reviewer="rv2", kind="advisory"):
        items = self.risk.pull_pending(reviewer)["items"]
        return next(item["advisory_id"] for item in items if item["kind"] == kind)

    # ------------------------------------------------------------ 脱敏与数据最小化

    def test_summary_is_stored_but_only_hashes_enter_audit_detail(self):
        events = self.service.audit_events()
        submitted = next(e for e in events if e["action"] == "risk_incident.submitted")
        self.assertNotIn("某模型输出风险", str(submitted["detail"]))
        self.assertEqual(64, len(submitted["detail"]["summary_hash"]))

    def test_sanitized_summary_must_be_nonempty(self):
        with self.assertRaises(ValidationError):
            self.risk.submit_incident(
                request_id="bad1", actor_id="op1", incident_id="inc-x",
                sanitized_summary="  ", category="c", proposed_level="low",
                recipient_organizations=["o2"])

    def test_invalid_level_rejected(self):
        with self.assertRaises(ValidationError):
            self.risk.submit_incident(
                request_id="bad2", actor_id="op1", incident_id="inc-y",
                sanitized_summary="摘要", category="c", proposed_level="urgent-red",
                recipient_organizations=["o2"])

    def test_content_hash_must_be_sha256_hex(self):
        with self.assertRaises(ValidationError):
            self.risk.submit_incident(
                request_id="bad3", actor_id="op1", incident_id="inc-z",
                sanitized_summary="摘要", category="c", proposed_level="low",
                recipient_organizations=["o2"], content_hash="not-a-hash")

    # ------------------------------------------------------------ 权限三分：提交/查看/确认

    def test_reviewer_cannot_submit(self):
        with self.assertRaises(PermissionDenied):
            self.risk.submit_incident(
                request_id="p1", actor_id="rv2", incident_id="inc-r",
                sanitized_summary="摘要", category="c", proposed_level="low",
                recipient_organizations=["o1"])

    def test_operator_cannot_acknowledge(self):
        advisory_id = self._advisory_for()
        with self.assertRaises(PermissionDenied):
            self.risk.acknowledge_advisory(request_id="p2", actor_id="op2",
                                           advisory_id=advisory_id)

    def test_auditor_has_no_business_view(self):
        with self.assertRaises(PermissionDenied):
            self.risk.get_incident("au1", "inc-1")

    def test_non_participant_gets_not_found(self):
        with self.assertRaises(NotFoundError):
            self.risk.get_incident("op4", "inc-1")

    def test_reviewer_can_view_but_not_revise(self):
        detail = self.risk.get_incident("rv2", "inc-1")
        self.assertEqual("inc-1", detail["incident_id"])
        with self.assertRaises(PermissionDenied):
            self.risk.revise_incident(
                request_id="p3", actor_id="rv2", incident_id="inc-1",
                sanitized_summary="新摘要", category="c", proposed_level="high",
                revision_note="尝试修订")

    # ------------------------------------------------------------ 本地编号映射

    def test_local_references_coexist_with_divergent_numbers_and_labels(self):
        self.risk.map_local_reference(request_id="m1", actor_id="op1", incident_id="inc-1",
                                     local_number="O1-RISK-001", local_label="隔离")
        self.risk.map_local_reference(request_id="m2", actor_id="op2", incident_id="inc-1",
                                     local_number="O2-NOTE-77", local_label="普通提醒")
        detail = self.risk.get_incident("op1", "inc-1")
        mapped = {(r["organization_id"], r["local_number"], r["local_label"])
                  for r in detail["local_references"]}
        self.assertIn(("o1", "O1-RISK-001", "隔离"), mapped)
        self.assertIn(("o2", "O2-NOTE-77", "普通提醒"), mapped)

    def test_conflicting_mapping_rejected(self):
        self.risk.map_local_reference(request_id="m3", actor_id="op2", incident_id="inc-1",
                                     local_number="N-1", local_label="低")
        with self.assertRaises(ConflictError):
            self.risk.map_local_reference(request_id="m4", actor_id="op2", incident_id="inc-1",
                                         local_number="N-2", local_label="高")

    # ------------------------------------------------------------ 统一等级协商

    def test_level_locks_only_when_all_participants_agree(self):
        self.risk.propose_level(request_id="l2a", actor_id="op2", incident_id="inc-1",
                                proposed_level="high")
        self.assertIsNone(self.risk.get_incident("op1", "inc-1")["agreed_level"])
        self.risk.propose_level(request_id="l3a", actor_id="op3", incident_id="inc-1",
                                proposed_level="medium")
        self.assertIsNone(self.risk.get_incident("op1", "inc-1")["agreed_level"])
        self.risk.propose_level(request_id="l3b", actor_id="op3", incident_id="inc-1",
                                proposed_level="high")
        detail = self.risk.get_incident("op1", "inc-1")
        self.assertEqual("high", detail["agreed_level"])

    def test_changed_stance_is_append_only_history(self):
        self.risk.propose_level(request_id="l2", actor_id="op2", incident_id="inc-1",
                                proposed_level="low")
        self.risk.propose_level(request_id="l2b", actor_id="op2", incident_id="inc-1",
                                proposed_level="high")
        detail = self.risk.get_incident("op1", "inc-1")
        stances = [p for p in detail["level_proposals"] if p["organization_id"] == "o2"]
        self.assertEqual(["low", "high"], [p["proposed_level"] for p in stances])

    # ------------------------------------------------------------ 修订可追溯

    def test_revision_creates_immutable_version_and_resets_agreement(self):
        self.risk.propose_level(request_id="l2", actor_id="op2", incident_id="inc-1",
                                proposed_level="high")
        self.risk.propose_level(request_id="l3", actor_id="op3", incident_id="inc-1",
                                proposed_level="high")
        self.assertEqual("high", self.risk.get_incident("op1", "inc-1")["agreed_level"])
        self.risk.revise_incident(
            request_id="rev1", actor_id="op1", incident_id="inc-1",
            sanitized_summary="修订后的脱敏摘要", category="model_output",
            proposed_level="medium", revision_note="补充影响范围")
        detail = self.risk.get_incident("op1", "inc-1")
        self.assertEqual(2, detail["current_version"])
        self.assertIsNone(detail["agreed_level"])
        self.assertEqual([1, 2], [v["version"] for v in detail["versions"]])
        self.assertEqual("某模型输出风险（已脱敏）", detail["versions"][0]["sanitized_summary"])

    def test_non_origin_organization_cannot_revise(self):
        with self.assertRaises(PermissionDenied):
            self.risk.revise_incident(
                request_id="revX", actor_id="op2", incident_id="inc-1",
                sanitized_summary="摘要", category="c", proposed_level="low",
                revision_note="越权修订")

    # ------------------------------------------------------------ 撤回不抹除义务

    def test_withdrawal_keeps_obligation_and_requires_receipt(self):
        first = self._advisory_for("rv2")
        self.risk.acknowledge_advisory(request_id="a1", actor_id="rv2", advisory_id=first)
        self.risk.revise_incident(
            request_id="wrev", actor_id="op1", incident_id="inc-1",
            sanitized_summary="修订摘要", category="model_output", proposed_level="high",
            revision_note="撤回前的修订")
        self.risk.withdraw_incident(request_id="w1", actor_id="op1",
                                    incident_id="inc-1", reason="误报撤销")
        backlog = self.risk.pull_pending("rv2", after_sequence=1)["items"]
        by_kind = {item["kind"]: item for item in backlog}
        withdrawal = by_kind["withdrawal"]
        self.assertTrue(withdrawal["after_withdrawal"])
        # 拉取到的待办反映通告当前状态：撤回后修订通告也被标记为 withdrawn。
        self.assertEqual("withdrawn", by_kind["revision"]["status"])
        status = self.risk.receipt_status("op1", "inc-1")
        o2 = next(o for o in status["organizations"] if o["organization_id"] == "o2")
        self.assertFalse(o2["completed"])
        # 按序先回执修订，再回执撤回；撤回通告的义务不因其状态而消失。
        self.risk.acknowledge_advisory(request_id="a2", actor_id="rv2",
                                       advisory_id=by_kind["revision"]["advisory_id"])
        self.risk.acknowledge_advisory(request_id="a3", actor_id="rv2",
                                       advisory_id=withdrawal["advisory_id"])
        status = self.risk.receipt_status("op1", "inc-1")
        o2 = next(o for o in status["organizations"] if o["organization_id"] == "o2")
        self.assertTrue(o2["completed"])

    def test_double_withdraw_rejected(self):
        self.risk.withdraw_incident(request_id="w2", actor_id="op1", incident_id="inc-1")
        with self.assertRaises(ConflictError):
            self.risk.withdraw_incident(request_id="w3", actor_id="op1", incident_id="inc-1")

    def test_no_revision_after_withdrawal(self):
        self.risk.withdraw_incident(request_id="w4", actor_id="op1", incident_id="inc-1")
        with self.assertRaises(ConflictError):
            self.risk.revise_incident(
                request_id="w5", actor_id="op1", incident_id="inc-1",
                sanitized_summary="摘要", category="c", proposed_level="low",
                revision_note="撤回后修订")

    # ------------------------------------------------------------ 离线顺序补齐

    def test_offline_backlog_is_redelivered_in_sequence(self):
        self.risk.revise_incident(
            request_id="rev2", actor_id="op1", incident_id="inc-1",
            sanitized_summary="修订摘要", category="model_output", proposed_level="high",
            revision_note="范围更新")
        backlog = self.risk.pull_pending("rv2", after_sequence=0, limit=10)["items"]
        self.assertEqual([(1, "advisory"), (2, "revision")],
                         [(i["sequence_number"], i["kind"]) for i in backlog])

    def test_acknowledgement_enforces_per_incident_order(self):
        self.risk.revise_incident(
            request_id="rev3", actor_id="op1", incident_id="inc-1",
            sanitized_summary="修订摘要", category="model_output", proposed_level="high",
            revision_note="范围更新")
        items = self.risk.pull_pending("rv3")["items"]
        revision = next(i for i in items if i["kind"] == "revision")["advisory_id"]
        with self.assertRaises(ConflictError):
            self.risk.acknowledge_advisory(request_id="o1", actor_id="rv3",
                                           advisory_id=revision)

    def test_duplicate_acknowledgement_replays(self):
        advisory_id = self._advisory_for()
        first = self.risk.acknowledge_advisory(request_id="dup1", actor_id="rv2",
                                               advisory_id=advisory_id)
        second = self.risk.acknowledge_advisory(request_id="dup1", actor_id="rv2",
                                                advisory_id=advisory_id)
        self.assertFalse(first.replayed)
        self.assertTrue(second.replayed)

    # ------------------------------------------------------------ 回执状态展示

    def test_receipt_status_lists_incomplete_organizations(self):
        status = self.risk.receipt_status("op1", "inc-1")
        self.assertEqual(2, status["recipient_count"])
        self.assertEqual(0, status["completed_count"])
        pending_orgs = {o["organization_id"] for o in status["organizations"] if not o["completed"]}
        self.assertEqual({"o2", "o3"}, pending_orgs)
        self.risk.acknowledge_advisory(request_id="s1", actor_id="rv2",
                                       advisory_id=self._advisory_for("rv2"))
        self.risk.acknowledge_advisory(request_id="s2", actor_id="rv3",
                                       advisory_id=self._advisory_for("rv3"))
        status = self.risk.receipt_status("op1", "inc-1")
        self.assertEqual(2, status["completed_count"])

    # ------------------------------------------------------------ 审计链

    def test_audit_chain_covers_risk_lifecycle(self):
        self.risk.map_local_reference(request_id="q1", actor_id="op2", incident_id="inc-1",
                                     local_number="N-9", local_label="低")
        self.risk.propose_level(request_id="q2", actor_id="op2", incident_id="inc-1",
                                proposed_level="high")
        valid, count = self.service.verify_audit()
        self.assertTrue(valid)
        actions = {e["action"] for e in self.service.audit_events()}
        self.assertIn("risk_incident.submitted", actions)
        self.assertIn("risk_local_reference.mapped", actions)
        self.assertIn("risk_level.proposed", actions)


    # ------------------------------------------------------------ 重启持久化

    def test_pending_obligations_survive_restart_in_order(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "risk.sqlite3"

            def bootstrap():
                database = Database(path)
                service = DomainService(database, FixedClock(datetime(2026, 10, 6, tzinfo=timezone.utc)))
                return database, service, RiskCommunicationService(database, service.clock)

            database, service, risk = bootstrap()
            service.register_organization(request_id="o1", actor_id="bootstrap",
                                           organization_id="o1", name="机构一")
            service.register_actor(request_id="a1", actor_id="bootstrap", new_actor_id="a1",
                                   display_name="管理员", role="admin", organization_id="o1")
            service.register_organization(request_id="o2", actor_id="a1",
                                           organization_id="o2", name="机构二")
            service.register_actor(request_id="op1", actor_id="a1", new_actor_id="op1",
                                   display_name="op1", role="operator", organization_id="o1")
            service.register_actor(request_id="rv2", actor_id="a1", new_actor_id="rv2",
                                   display_name="rv2", role="reviewer", organization_id="o2")
            risk.submit_incident(request_id="i1", actor_id="op1", incident_id="inc-persist",
                                 sanitized_summary="脱敏摘要", category="model_output",
                                 proposed_level="high", recipient_organizations=["o2"])
            risk.revise_incident(request_id="r1", actor_id="op1", incident_id="inc-persist",
                                 sanitized_summary="修订摘要", category="model_output",
                                 proposed_level="high", revision_note="更新范围")
            database.close()

            # 接收方全程离线，服务重启后按顺序拿到两条待办。
            database2, service2, risk2 = bootstrap()
            backlog = risk2.pull_pending("rv2")["items"]
            self.assertEqual([(1, "advisory"), (2, "revision")],
                             [(i["sequence_number"], i["kind"]) for i in backlog])
            self.assertTrue(backlog[0]["acknowledged"] is False)
            valid, _ = service2.verify_audit()
            self.assertTrue(valid)
            database2.close()


if __name__ == "__main__":
    unittest.main()
