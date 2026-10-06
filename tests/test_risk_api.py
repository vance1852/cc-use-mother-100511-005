import unittest

from ai_governance_foundation.api import route
from ai_governance_foundation.risk_service import RiskService
from ai_governance_foundation.service import DomainService
from ai_governance_foundation.storage import Database


class RiskApiTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.service = DomainService(self.database)
        self.risk = RiskService(self.database)
        self.service.register_organization(request_id="org1", actor_id="bootstrap",
                                           organization_id="o1", name="机构甲")
        self.service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="a1",
                                    display_name="管理员", role="admin", organization_id="o1")
        self.service.register_organization(request_id="org2", actor_id="a1",
                                           organization_id="o2", name="机构乙")
        self.service.register_actor(request_id="op1", actor_id="a1", new_actor_id="op1",
                                    display_name="甲操作员", role="operator", organization_id="o1")
        self.service.register_actor(request_id="op2", actor_id="a1", new_actor_id="op2",
                                    display_name="乙操作员", role="operator", organization_id="o2")
        for target in ("op1", "op2"):
            for cap in ("risk:submit", "risk:view", "risk:confirm"):
                self.risk.grant_capability(request_id=f"g-{target}-{cap}", actor_id="a1",
                                           target_actor_id=target, capability=cap)

    def tearDown(self):
        self.database.close()

    def _route(self, method, path, body=None, actor="op1"):
        return route(self.service, method, path, body or {},
                     {"X-Actor-Id": actor}, risk_service=self.risk)

    def test_full_risk_flow_over_http(self):
        status, payload = self._route("POST", "/risk/events", {
            "request_id": "evt1",
            "summary": "联合评估发现投毒迹象",
            "proposed_level": "high",
            "recipient_organizations": ["o2"],
        })
        self.assertEqual(201, status)
        event_id = payload["resource_id"]

        status, payload = self._route("GET", f"/risk/events/{event_id}", actor="op2")
        self.assertEqual(200, status)
        self.assertEqual("联合评估发现投毒迹象", payload["latest_summary"])
        self.assertEqual(1, payload["current_revision"])

        status, payload = self._route("POST", "/risk/level-proposals", {
            "request_id": "lv1", "event_id": event_id, "revision": 1,
            "proposed_level": "high", "rationale": "甲已隔离",
        }, actor="op1")
        self.assertEqual(201, status)
        status, payload = self._route("POST", "/risk/level-proposals", {
            "request_id": "lv2", "event_id": event_id, "revision": 1,
            "proposed_level": "high", "rationale": "乙复核一致",
        }, actor="op2")
        self.assertEqual(201, status)
        self.assertEqual("high", payload["agreed_level"])

        status, payload = self._route("GET", f"/risk/events/{event_id}/status", actor="op1")
        self.assertEqual(200, status)
        self.assertEqual("high", payload["agreed_level"])
        self.assertIn("o2", payload["organizations_pending_receipt"])

        status, payload = self._route("POST", "/risk/receipts", {
            "event_id": event_id, "revision": 1,
        }, actor="op2")
        self.assertEqual(200, status)
        self.assertEqual(1, payload["revision"])

        status, payload = self._route("GET", f"/risk/events/{event_id}/status", actor="op1")
        self.assertEqual([], payload["organizations_pending_receipt"])

    def test_missing_actor_is_rejected(self):
        status, payload = route(self.service, "GET", "/risk/pending", {},
                                risk_service=self.risk)
        self.assertEqual(404, status)

    def test_view_permission_required(self):
        status, payload = self._route("GET", "/risk/pending", actor="a1")
        self.assertEqual(403, status)
        self.assertEqual("permission_denied", payload["error"])

    def test_pending_endpoint_lists_offline_queue(self):
        status, payload = self._route("POST", "/risk/events", {
            "request_id": "evt1", "summary": "离线队列测试", "proposed_level": "low",
            "recipient_organizations": ["o2"],
        })
        event_id = payload["resource_id"]
        status, payload = self._route("GET", "/risk/pending", actor="op2")
        self.assertEqual(200, status)
        self.assertEqual([{"seq": 1, "event_id": event_id, "kind": "submitted",
                           "revision": 1, "enqueued_at": payload["items"][0]["enqueued_at"]}],
                         payload["items"])

    def test_withdrawal_keeps_obligation_visible(self):
        status, payload = self._route("POST", "/risk/events", {
            "request_id": "evt1", "summary": "撤回不抹除义务", "proposed_level": "high",
            "recipient_organizations": ["o2"],
        })
        event_id = payload["resource_id"]
        self._route("POST", "/risk/level-proposals", {
            "request_id": "lv1", "event_id": event_id, "revision": 1,
            "proposed_level": "high", "rationale": "x",
        }, actor="op1")
        self._route("POST", "/risk/level-proposals", {
            "request_id": "lv2", "event_id": event_id, "revision": 1,
            "proposed_level": "high", "rationale": "x",
        }, actor="op2")
        status, payload = self._route("GET", "/risk/obligations", actor="op2")
        self.assertEqual(1, len(payload["items"]))
        obligation_id = payload["items"][0]["obligation_id"]
        status, payload = self._route("POST", "/risk/withdrawals", {
            "request_id": "wd1", "event_id": event_id, "reason": "误报",
        }, actor="op1")
        self.assertEqual(201, status)
        status, payload = self._route("GET", "/risk/obligations", actor="op2")
        self.assertEqual(1, len(payload["items"]))
        self.assertEqual("open", payload["items"][0]["status"])
        status, payload = self._route("POST", "/risk/obligations/discharge", {
            "obligation_id": obligation_id,
        }, actor="op2")
        self.assertEqual(200, status)
        self.assertEqual("discharged", payload["status"])

    def test_unknown_risk_route_is_404(self):
        status, payload = self._route("GET", "/risk/nope", actor="op1")
        self.assertEqual(404, status)
        self.assertEqual("route_not_found", payload["error"])


if __name__ == "__main__":
    unittest.main()
