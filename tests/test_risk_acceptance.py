import unittest

from ai_governance_foundation.risk_acceptance import run


class RiskAcceptanceTest(unittest.TestCase):
    def test_cross_organization_risk_acceptance(self):
        result = run()
        self.assertEqual("ok", result["status"])
        self.assertTrue(result["audit_valid"])
        self.assertIsNone(result["level_before_negotiation"])
        self.assertEqual("high", result["agreed_level"])
        self.assertEqual(1, result["obligations_created"])
        self.assertEqual(["submitted", "level_agreed", "revised", "withdrawn"],
                         result["offline_queue"])
        self.assertEqual([1, 2], result["receipt_revisions"])
        self.assertEqual([], result["pending_receipt_orgs"])
        self.assertTrue(result["obligations_survive_withdrawal"])
        self.assertTrue(result["obligation_discharged"])
        self.assertTrue(result["withdrawn"])
        self.assertEqual(2, result["revisions_preserved"])


if __name__ == "__main__":
    unittest.main()
