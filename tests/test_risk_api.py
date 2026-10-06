import unittest

from ai_governance_foundation.api import route
from ai_governance_foundation.service import DomainService
from ai_governance_foundation.storage import Database


HEADERS = {actor: {"X-Actor-Id": actor} for actor in
           ("a1", "op1", "op2", "op3", "rv2", "rv3", "au1", "op4")}


class RiskApiTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.service = DomainService(self.database)

        def call(method, path, body=None, actor="a1"):
            headers = {"X-Actor-Id": actor} if actor else {}
            return route(self.service, method, path, body, headers)

        self.call = call
        call("POST", "/organizations", {"request_id": "org1", "organization_id": "o1", "name": "机构一"}, "bootstrap")
        call("POST", "/actors", {"request_id": "admin", "new_actor_id": "a1", "display_name": "管理员",
                                 "role": "admin", "organization_id": "o1"}, "bootstrap")
        for oid, name in (("o2", "机构二"), ("o3", "机构三"), ("o4", "机构四")):
            call("POST", "/organizations", {"request_id": f"org-{oid}", "organization_id": oid, "name": name})
        for aid, role, oid in (("op1", "operator", "o1"), ("op2", "operator", "o2"),
                               ("op3", "operator", "o3"), ("op4", "operator", "o4"),
                               ("rv2", "reviewer", "o2"), ("rv3", "reviewer", "o3"),
                               ("au1", "auditor", "o1")):
            call("POST", "/actors", {"request_id": f"actor-{aid}", "new_actor_id": aid,
                                     "display_name": aid, "role": role, "organization_id": oid})

    def tearDown(self):
        self.database.close()

    def _submit(self, request_id="inc1", actor="op1", incident_id="inc-1", extra=None):
        body = {"request_id": request_id, "incident_id": incident_id,
                "sanitized_summary": "脱敏摘要", "category": "model_output",
                "proposed_level": "high", "recipient_organizations": ["o2", "o3"]}
        if extra:
            body.update(extra)
        return self.call("POST", "/risk/incidents", body, actor)

    def test_submit_and_get_incident(self):
        status, payload = self._submit()
        self.assertEqual(201, status)
        self.assertEqual("inc-1", payload["resource_id"])
        status, detail = self.call("GET", "/risk/incidents/inc-1", None, "rv2")
        self.assertEqual(200, status)
        self.assertEqual(1, detail["current_version"])

    def test_raw_sensitive_content_is_rejected_at_boundary(self):
        for field in ("raw_content", "original_content", "sensitive_content"):
            status, payload = self._submit(request_id=f"leak-{field}",
                                           incident_id=f"inc-{field}", extra={field: "机密原文"})
            self.assertEqual(400, status, field)
            self.assertEqual("validation_error", payload["error"], field)

    def test_submit_requires_submit_permission(self):
        status, payload = self._submit(request_id="p1", actor="rv2", incident_id="inc-p")
        self.assertEqual(403, status)
        self.assertEqual("permission_denied", payload["error"])

    def test_acknowledge_requires_confirm_permission(self):
        self._submit()
        status, pending = self.call("GET", "/risk/pending", None, "rv2")
        advisory_id = pending["items"][0]["advisory_id"]
        status, payload = self.call(
            "POST", f"/risk/advisories/{advisory_id}/acknowledgements",
            {"request_id": "a1", "advisory_id": advisory_id}, "op2")
        self.assertEqual(403, status)
        status, payload = self.call(
            "POST", f"/risk/advisories/{advisory_id}/acknowledgements",
            {"request_id": "a2", "advisory_id": advisory_id}, "rv2")
        self.assertEqual(201, status)

    def test_acknowledging_unknown_advisory_returns_404(self):
        self._submit()
        status, payload = self.call(
            "POST", "/risk/advisories/missing/acknowledgements",
            {"request_id": "a0", "advisory_id": "missing"}, "rv2")
        self.assertEqual(404, status)

    def test_pending_backlog_and_receipt_status_end_to_end(self):
        self._submit()
        status, pending = self.call("GET", "/risk/pending?after_sequence=0&limit=10", None, "rv3")
        self.assertEqual(200, status)
        self.assertEqual(1, pending["items"][0]["sequence_number"])
        advisory_id = pending["items"][0]["advisory_id"]
        self.call("POST", f"/risk/advisories/{advisory_id}/acknowledgements",
                  {"request_id": "ack3", "advisory_id": advisory_id}, "rv3")
        status, report = self.call("GET", "/risk/incidents/inc-1/receipt-status", None, "op1")
        self.assertEqual(200, status)
        by_org = {o["organization_id"]: o for o in report["organizations"]}
        self.assertTrue(by_org["o3"]["completed"])
        self.assertFalse(by_org["o2"]["completed"])

    def test_non_participant_cannot_view(self):
        self._submit()
        status, payload = self.call("GET", "/risk/incidents/inc-1", None, "op4")
        self.assertEqual(404, status)

    def test_level_negotiation_and_local_mapping_routes(self):
        self._submit()
        status, _ = self.call("POST", "/risk/incidents/inc-1/local-references",
                              {"request_id": "m1", "local_number": "N-1", "local_label": "低"}, "op2")
        self.assertEqual(201, status)
        status, payload = self.call("POST", "/risk/incidents/inc-1/level-proposals",
                                    {"request_id": "l2", "proposed_level": "high"}, "op2")
        self.assertEqual(201, status)
        self.assertIsNone(payload["agreed_level"])
        status, payload = self.call("POST", "/risk/incidents/inc-1/level-proposals",
                                    {"request_id": "l3", "proposed_level": "high"}, "op3")
        self.assertEqual(201, status)
        self.assertEqual("high", payload["agreed_level"])

    def test_revision_and_withdrawal_routes(self):
        self._submit()
        status, payload = self.call("POST", "/risk/incidents/inc-1/revisions",
                                    {"request_id": "r1", "sanitized_summary": "新摘要",
                                     "category": "model_output", "proposed_level": "high",
                                     "revision_note": "更新"}, "op1")
        self.assertEqual(201, status)
        self.assertEqual("inc-1", payload["resource_id"])
        status, payload = self.call("POST", "/risk/incidents/inc-1/withdrawal",
                                    {"request_id": "w1", "reason": "误报"}, "op1")
        self.assertEqual(201, status)


if __name__ == "__main__":
    unittest.main()
