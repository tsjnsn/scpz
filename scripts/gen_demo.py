#!/usr/bin/env python3
"""Generate demo.txt by running real scpz commands and capturing their output.

Usage::

    python scripts/gen_demo.py

Runs from a temporary directory so every command sees plain filenames
(not absolute paths) in its output.  ANSI colour codes are stripped so
the result is clean plain text.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCPZ = str(REPO_ROOT / ".venv" / "bin" / "scpz")

# ── Input data ────────────────────────────────────────────────────────────────

POLICY_JSON: dict = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyIAMUserMgmt",
            "Effect": "Deny",
            "Action": [
                "iam:CreateUser",
                "iam:DeleteUser",
                "iam:UpdateUser",
                "iam:CreateAccessKey",
                "iam:DeleteAccessKey",
                "iam:UpdateAccessKey",
            ],
            "Resource": "*",
        },
        {
            "Sid": "DenyIAMRoleMgmt",
            "Effect": "Deny",
            "Action": [
                "iam:CreateRole",
                "iam:DeleteRole",
                "iam:UpdateRole",
                "iam:AttachRolePolicy",
                "iam:DetachRolePolicy",
                "iam:PutRolePolicy",
                "iam:DeleteRolePolicy",
            ],
            "Resource": "*",
        },
        {
            "Sid": "AlsoNoDeleteRole",
            "Effect": "Deny",
            "Action": ["iam:DeleteRole", "iam:DeleteRolePolicy"],
            "Resource": "*",
        },
        {
            "Sid": "DenyGuardDutyTampering",
            "Effect": "Deny",
            "Action": [
                "guardduty:DeleteDetector",
                "guardduty:DeleteMembers",
                "guardduty:DeleteFilter",
                "guardduty:DeleteIPSet",
                "guardduty:UpdateDetector",
                "guardduty:DisassociateMembers",
                "guardduty:DisassociateFromMasterAccount",
            ],
            "Resource": "*",
        },
        {
            "Sid": "DenyConfigTampering",
            "Effect": "Deny",
            "Action": [
                "config:DeleteConfigurationRecorder",
                "config:DeleteDeliveryChannel",
                "config:DeleteRetentionConfiguration",
                "config:StopConfigurationRecorder",
            ],
            "Resource": "*",
        },
        {
            "Sid": "DenyCloudTrailTampering",
            "Effect": "Deny",
            "Action": [
                "cloudtrail:StopLogging",
                "cloudtrail:DeleteTrail",
                "cloudtrail:UpdateTrail",
                "cloudtrail:PutEventSelectors",
            ],
            "Resource": "*",
        },
    ],
}

MAX_SCPZ_YAML = """\
apiVersion: scpz.io/v1alpha1
kind: OptimizerConfig
metadata:
  name: max
spec:
  optimizer:
    statementMerge:
      sidOnMerge: drop
    actionCompress:
      mode: aggressive
    redundancyEliminate:
      enabled: true
"""

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _run(cmd: list[str], cwd: Path) -> str:
    env = {**os.environ, "NO_COLOR": "1", "PYTHONUNBUFFERED": "1"}
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=cwd,
        env=env,
    )
    return _ANSI_RE.sub("", result.stdout).rstrip()


def _scpz(args: str, cwd: Path) -> str:
    return _run([SCPZ] + args.split(), cwd=cwd)


def main() -> None:
    with tempfile.TemporaryDirectory() as _tmp:
        tmp = Path(_tmp)

        bloated_src = REPO_ROOT / "examples" / "bloated_deny.json"

        # Files for the max-settings demo (policy.json + scpz.yaml)
        max_dir = tmp / "max"
        max_dir.mkdir()
        (max_dir / "policy.json").write_text(
            json.dumps(POLICY_JSON, indent=2), encoding="utf-8"
        )
        (max_dir / "scpz.yaml").write_text(MAX_SCPZ_YAML, encoding="utf-8")

        # No-config directory (policy.json only, no scpz.yaml)
        noconf_dir = tmp / "noconf"
        noconf_dir.mkdir()
        shutil.copy(max_dir / "policy.json", noconf_dir / "policy.json")

        sections: list[str] = []

        # ── Install / version / help ─────────────────────────────────
        sections += [
            "$ pip install scpz",
            "...",
            "",
            "$ scpz --version",
            _scpz("--version", tmp),
            "",
            "$ scpz --help",
            "",
            _scpz("--help", tmp),
            "",
        ]

        # ── bloated_deny.json demo ───────────────────────────────────
        def fresh_bloated() -> Path:
            dst = tmp / "bloated_deny.json"
            shutil.copy(bloated_src, dst)
            return dst

        fresh_bloated()

        sections += [
            "$ scpz validate bloated_deny.json",
            _scpz("validate bloated_deny.json", tmp),
            "",
            "$ scpz optimize-cmd bloated_deny.json --summary-only",
            _scpz("optimize-cmd bloated_deny.json --summary-only", tmp),
            "",
        ]

        fresh_bloated()
        sections += [
            "$ scpz optimize-cmd bloated_deny.json --dry-run",
            _scpz("optimize-cmd bloated_deny.json --dry-run", tmp),
            "",
        ]

        fresh_bloated()
        sections += [
            "$ scpz optimize-cmd bloated_deny.json",
            _scpz("optimize-cmd bloated_deny.json", tmp),
            "",
        ]

        # ── Max optimization section ─────────────────────────────────
        rule = "─" * 80
        sections += [
            rule,
            "Max optimization (scpz.yaml)",
            rule,
            "",
            "# scpz.yaml controls optimization settings. Three knobs beyond defaults:",
            "#",
            "#   actionCompress.mode: aggressive   — wildcard at verb level (iam:Delete*)",
            "#                                       instead of sub-verb only (iam:DeleteRole*)",
            "#   statementMerge.sidOnMerge: drop   — omit Sid on merged statements (fewest bytes)",
            "#   redundancyEliminate.enabled: true — remove statements subsumed by others",
            "",
            "$ cat scpz.yaml",
            MAX_SCPZ_YAML.rstrip(),
            "",
            "# Input: 6 statements written by a human, split by intent.",
            '# One is a duplicate ("AlsoNoDeleteRole" repeats actions already in "DenyIAMRoleMgmt").',
            "",
            "$ scpz optimize-cmd policy.json --summary-only   # default settings, no scpz.yaml",
            _scpz("optimize-cmd policy.json --summary-only", noconf_dir),
            "",
            "$ scpz optimize-cmd policy.json --summary-only   # with scpz.yaml (max settings)",
            _scpz("optimize-cmd policy.json --summary-only", max_dir),
            "",
            "$ scpz optimize-cmd policy.json --dry-run        # full diff, max settings",
            _scpz("optimize-cmd policy.json --dry-run", max_dir),
        ]

        demo = REPO_ROOT / "demo.txt"
        demo.write_text("\n".join(sections) + "\n", encoding="utf-8")
        print(f"Wrote {demo}")


if __name__ == "__main__":
    main()
