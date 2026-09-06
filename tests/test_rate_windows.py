import contextlib
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import codexpick_cli as cli


def window(minutes, used=0):
    return {"windowDurationMins": minutes, "usedPercent": used, "resetsAt": 1700000000}


def result(name, primary=None, secondary=None):
    return cli.ProbeResult(
        cli.Candidate(name, Path(f"auth-{name}.json")),
        account={"account": {"planType": "pro"}},
        rate_limits={"rateLimits": {"primary": primary, "secondary": secondary}},
    )


def table(results):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        cli.print_table(results, None)
    lines = output.getvalue().splitlines()
    headers = re.split(r"\s{2,}", lines[0].strip())
    return [dict(zip(headers, re.split(r"\s{2,}", line.strip()))) for line in lines[2:]]


class RateWindowTests(unittest.TestCase):
    def test_weekly_only_primary_is_not_five_hour(self):
        row = table([result("primary_account", window(10080, 25))])[0]
        self.assertEqual(row["5h used"], "-")
        self.assertEqual(row["5h reset"], "-")
        self.assertEqual(row["weekly used"], "25%")
        self.assertEqual(row["weekly reset"], cli.fmt_reset(window(10080)))
        self.assertEqual(row["status"], "ok")

    def test_mixed_accounts_keep_usage_and_reset_in_matching_columns(self):
        rows = table([result("primary_account", window(10080, 25)),
                      result("backup_account", window(300, 10), window(10080, 20))])
        self.assertEqual(rows[1]["5h used"], "10%")
        self.assertEqual(rows[1]["weekly used"], "20%")
        self.assertEqual(rows[1]["5h reset"], cli.fmt_reset(window(300)))

    def test_slot_order_does_not_define_duration(self):
        row = table([result("reversed", window(10080, 22), window(300, 33))])[0]
        self.assertEqual(row["5h used"], "33%")
        self.assertEqual(row["weekly used"], "22%")

    def test_missing_windows_are_unknown_not_zero(self):
        row = table([result("missing")])[0]
        self.assertEqual(row["5h used"], "-")
        self.assertEqual(row["weekly used"], "-")

    def test_unknown_and_other_durations_are_not_mislabeled_or_dropped(self):
        row = table([result("other", window(60, 100), {"usedPercent": 12})])[0]
        self.assertEqual(row["1h used"], "100%")
        self.assertEqual(row["secondary (duration unknown) used"], "12%")
        self.assertEqual(row["5h used"], "-")
        self.assertEqual(row["status"], "1h quota spent")

    def test_exhaustion_with_weekly_only_primary(self):
        primary_account = result("primary_account", window(10080, 100))
        backup_account = result("backup_account", window(300, 0), window(10080, 0))
        self.assertEqual(primary_account.blocked_reason, "weekly quota spent")
        self.assertFalse(primary_account.usable)
        self.assertTrue(backup_account.usable)

    def test_selection_falls_back_and_returns_to_primary_when_quota_resets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("a-pro", "b-plus"):
                (root / f"auth-{name}.json").write_text(
                    json.dumps({"tokens": {"account_id": name}})
                )
            for used, expected in ((100, "b-plus"), (0, "a-pro")):
                with self.subTest(weekly_used=used):
                    def probe(candidate, *args):
                        response = result(candidate.name, window(10080, used))
                        if candidate.name == "b-plus":
                            response = result(candidate.name, window(300), window(10080))
                        response.candidate = candidate
                        return response

                    output = io.StringIO()
                    with mock.patch.object(sys, "argv", ["codexpick", "--no-update-check", "--home", directory, "--check-only"]), \
                         mock.patch.object(cli, "probe_candidate", side_effect=probe), \
                         contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                        self.assertEqual(cli.main(), 0)
                    self.assertIn(f"Selected: {expected}", output.getvalue())
                    self.assertFalse((root / "auth.json").exists())

    def test_invalid_duration_does_not_assume_five_hours(self):
        for duration in (None, 0, -1, True, "300"):
            with self.subTest(duration=duration):
                row = table([result("unknown", window(duration, 100))])[0]
                self.assertEqual(row["5h used"], "-")
                self.assertEqual(row["primary (duration unknown) used"], "100%")
                self.assertEqual(row["status"], "primary (duration unknown) quota spent")

    def test_five_hour_exhaustion_still_blocks(self):
        self.assertEqual(result("backup_account", window(300, 100)).blocked_reason, "5h quota spent")

    def test_same_duration_windows_are_both_retained(self):
        row = table([result("duplicate", window(300, 10), window(300, 100))])[0]
        self.assertEqual(row["5h used"], "10%")
        self.assertEqual(row["5h (secondary) used"], "100%")
        self.assertEqual(row["status"], "5h (secondary) quota spent")
