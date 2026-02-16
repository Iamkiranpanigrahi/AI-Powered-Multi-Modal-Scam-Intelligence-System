+from __future__ import annotations
+
+import argparse
+import json
+
+from scam_intelligence import AnalysisInput, ScamIntelligenceSystem
+
+
+def parse_args() -> argparse.Namespace:
+    parser = argparse.ArgumentParser(
+        description="AI-Powered Multi-Modal Scam Intelligence System"
+    )
+    parser.add_argument("--text", required=True, help="Message, transcript, or email body")
+    parser.add_argument("--urls", nargs="*", default=[], help="Related URLs")
+    parser.add_argument("--emails", nargs="*", default=[], help="Related emails")
+    parser.add_argument("--phones", nargs="*", default=[], help="Related phone numbers")
+    return parser.parse_args()
+
+
+def main() -> None:
+    args = parse_args()
+    system = ScamIntelligenceSystem()
+    result = system.analyze(
+        AnalysisInput(
+            text=args.text,
+            urls=args.urls,
+            emails=args.emails,
+            phones=args.phones,
+        )
+    )
+
+    print(
+        json.dumps(
+            {
+                "verdict": result.verdict,
+                "risk_level": result.risk_level,
+                "final_score": round(result.final_score, 3),
+                "signals": {
+                    "text_rule_score": round(result.text_rule_score, 3),
+                    "ml_score": round(result.ml_score, 3),
+                    "metadata_score": round(result.metadata_score, 3),
+                },
+                "rationale": result.rationale,
+            },
+            indent=2,
+        )
+    )
+
+
+if __name__ == "__main__":
+    main()

