import hashlib, tempfile, threading, unittest
from pathlib import Path
from app import classify, sha256_file

class AnalyzerTests(unittest.TestCase):
    def test_sha256_matches_known_content(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/"sample.txt"; path.write_bytes(b"hello")
            self.assertEqual(sha256_file(str(path)), hashlib.sha256(b"hello").hexdigest())
    def test_defender_detection_is_high_risk(self):
        risk,reason,_=classify(r"C:\Users\A\sample.exe", "Válida", defender_hit=True)
        self.assertEqual(risk,"Alto risco"); self.assertIn("Defender",reason)
    def test_unsigned_executable_is_suspicious_not_certain(self):
        risk,reason,_=classify(r"C:\Users\A\sample.exe", "Não assinada")
        self.assertEqual(risk,"Suspeito"); self.assertIn("não confirma malware",reason)
    def test_signed_executable_is_only_low_risk(self):
        risk,reason,_=classify(r"C:\Program Files\sample.exe", "Válida")
        self.assertEqual(risk,"Baixo risco"); self.assertIn("não garante",reason)
    def test_non_executable_without_signal_is_inconclusive(self):
        self.assertEqual(classify(r"C:\Users\A\notes.txt")[0],"Inconclusivo")
    def test_failed_hash_is_inconclusive(self):
        self.assertEqual(classify(r"C:\Users\A\sample.exe",hash_ok=False)[0],"Inconclusivo")

if __name__ == "__main__": unittest.main()
