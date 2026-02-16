import unittest

from scam_intelligence import AnalysisInput, ScamIntelligenceSystem


class ScamIntelligenceSystemTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.system = ScamIntelligenceSystem()

    def test_detects_high_risk_scam(self) -> None:
        payload = AnalysisInput(
            text=(
                "Urgent! Your account is suspended. Share OTP immediately and "
                "send gift cards to unlock."
            ),
            urls=["http://secure-login-account-alert.xyz/verify-now"],
            phones=["+1234567"],
        )
        result = self.system.analyze(payload)
        self.assertEqual(result.verdict, "likely_scam")
        self.assertGreaterEqual(result.final_score, 0.5)

    def test_detects_low_risk_legitimate_message(self) -> None:
        payload = AnalysisInput(
            text="Hello team, agenda for tomorrow's engineering sync is attached.",
            urls=["https://intranet.company.com/wiki"],
            emails=["manager@company.com"],
        )
        result = self.system.analyze(payload)
        self.assertEqual(result.verdict, "likely_legitimate")
        self.assertLess(result.final_score, 0.5)


if __name__ == "__main__":
    unittest.main()
