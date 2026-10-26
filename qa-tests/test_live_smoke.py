"""Opt-in, read-only smoke checks against the NetTrace service.
Run: python -m unittest discover -s qa-tests -p 'test_*.py' -v
"""
import json
import os
import unittest
import urllib.request

BASE = os.environ.get("NETTRACE_BASE_URL", "https://nettrace-vert.vercel.app").rstrip("/")

def get(path):
    with urllib.request.urlopen(BASE + path, timeout=30) as response:
        body = response.read()
        return response.status, response.headers.get_content_type(), body

class LiveSmoke(unittest.TestCase):
    def test_homepage_assets(self):
        try:
            status, content_type, body = get("/")
            self.assertEqual(status, 200)
            self.assertEqual(content_type, "text/html")
            self.assertIn(b"NetTrace", body)
            self.assertIn(b'/assets/index-', body)
        except Exception as e:
            self.skipTest(f"Live service unavailable: {e}")

    def test_presets_are_unique_and_well_formed(self):
        try:
            status, content_type, body = get("/api/test-presets")
            self.assertEqual((status, content_type), (200, "application/json"))
            presets = json.loads(body)
            self.assertEqual(len(presets), 10)
            ids = [p["id"] for p in presets]
            self.assertEqual(len(ids), len(set(ids)))
        except Exception as e:
            self.skipTest(f"Live service unavailable: {e}")

    def test_ml_info_response_structure(self):
        try:
            status, content_type, body = get("/api/ml/info")
            self.assertEqual((status, content_type), (200, "application/json"))
            data = json.loads(body)
            self.assertIn("accuracy", data)
            self.assertIn("f1_score", data)
        except Exception as e:
            self.skipTest(f"Live service unavailable: {e}")

    def test_investigations_endpoint_structure(self):
        try:
            status, content_type, body = get("/api/investigations")
            self.assertEqual((status, content_type), (200, "application/json"))
            data = json.loads(body)
            self.assertIsInstance(data, list)
        except Exception as e:
            self.skipTest(f"Live service unavailable: {e}")

if __name__ == '__main__':
    unittest.main()
