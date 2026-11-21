"""Real synthetic subprocesses: no sockets, model calls or third-party probes."""
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest

from reede_client import MAX_VERIFIER_BYTES, ReedeError, _capture_verifier


class VerifierResourceTests(unittest.TestCase):
    def run_python(self, code, *, timeout=2):
        return _capture_verifier([sys.executable, "-c", code], timeout=timeout)

    def test_large_stderr_is_discarded_without_deadlock_or_diagnostics_leak(self):
        code, data = self.run_python(
            "import sys;sys.stderr.write('private diagnostic'*300000);"
            "sys.stdout.write('{\"schema\":\"reede-verification-v1\",\"authentic\":true}')"
        )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(data)["authentic"], True)
        self.assertNotIn(b"private", data)

    def test_stdout_flood_is_refused_at_the_cap(self):
        started = time.monotonic()
        with self.assertRaises(ReedeError) as error:
            self.run_python(f"import sys;sys.stdout.buffer.write(b'x'*{MAX_VERIFIER_BYTES * 8})")
        self.assertEqual(error.exception.code, "verifier_output_too_large")
        self.assertLess(time.monotonic() - started, 2)

    def test_trickle_stdout_cannot_extend_the_deadline(self):
        started = time.monotonic()
        with self.assertRaises(ReedeError) as error:
            self.run_python(
                "import sys,time\nwhile True:\n sys.stdout.write('x');sys.stdout.flush();time.sleep(.01)",
                timeout=.1,
            )
        self.assertEqual(error.exception.code, "verifier_timeout")
        self.assertLess(time.monotonic() - started, 1.5)

    def test_closed_stdout_does_not_disable_process_deadline(self):
        started = time.monotonic()
        with self.assertRaises(ReedeError) as error:
            self.run_python("import os,time;os.close(1);time.sleep(10)", timeout=.1)
        self.assertEqual(error.exception.code, "verifier_timeout")
        self.assertLess(time.monotonic() - started, 1.5)

    def test_invalid_process_arguments_do_not_consume_verifier_capacity(self):
        for _ in range(6):
            with self.assertRaises(ReedeError) as error:
                _capture_verifier(["invalid\0binary"])
            self.assertEqual(error.exception.code, "verifier_unavailable")
        code, data = self.run_python("print('still available')")
        self.assertEqual(code, 0)
        self.assertEqual(data.strip(), b"still available")

    @unittest.skipUnless(os.name == "posix", "synthetic descendant cleanup uses POSIX signals")
    def test_inherited_stdout_readers_keep_capacity_until_descendants_close(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_files = [Path(directory) / str(index) for index in range(4)]
            try:
                for pid_file in pid_files:
                    code = (
                        "import subprocess,sys,time;"
                        "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(10)']);"
                        f"open({str(pid_file)!r},'w').write(str(child.pid));"
                        "time.sleep(10)"
                    )
                    with self.assertRaises(ReedeError) as error:
                        self.run_python(code, timeout=.5)
                    self.assertEqual(error.exception.code, "verifier_timeout")
                    self.assertTrue(pid_file.exists(), "descendant fixture did not start")
                with self.assertRaises(ReedeError) as error:
                    self.run_python("print('must not launch')")
                self.assertEqual(error.exception.code, "verifier_busy")
            finally:
                for pid_file in pid_files:
                    if pid_file.exists():
                        try:
                            os.kill(int(pid_file.read_text()), signal.SIGTERM)
                        except ProcessLookupError:
                            pass
            # Reader EOF asynchronously restores capacity; do not leave fixture children/readers.
            deadline = time.monotonic() + 2
            while True:
                try:
                    code, data = self.run_python("print('capacity restored')")
                    break
                except ReedeError as error:
                    if error.code != "verifier_busy" or time.monotonic() >= deadline:
                        raise
                    time.sleep(.01)
            self.assertEqual(code, 0)
            self.assertEqual(data.strip(), b"capacity restored")

    def test_output_at_the_exact_limit_is_allowed(self):
        code, data = self.run_python(f"import sys;sys.stdout.buffer.write(b'x'*{MAX_VERIFIER_BYTES})")
        self.assertEqual(code, 0)
        self.assertEqual(len(data), MAX_VERIFIER_BYTES)


if __name__ == "__main__":
    unittest.main()
