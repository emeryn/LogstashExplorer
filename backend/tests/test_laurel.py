import json
import os
import shutil
import stat
import subprocess
import types

import pytest
from fastapi import HTTPException

from app import parsers
from app.api import workspace
from app.core.config import get_settings
from app.services import laurel

RAW = (
    "type=SYSCALL msg=audit(1791375352.583:4583): arch=c000003e syscall=59 success=yes exit=0 a0=5612a0 a1=5612b0 "
    "a2=5612c0 a3=0 items=1 ppid=3001 pid=3005 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 "
    'tty=pts0 ses=3 comm="useradd" exe="/usr/sbin/useradd" subj=unconfined key="identity"\r\n'
    'type=EXECVE msg=audit(1791375352.583:4583): argc=3 a0="useradd" a1="-m" a2=6261636B20646F6F72\r\n'
    'type=PATH msg=audit(1791375352.583:4583): item=0 name="/usr/sbin/useradd" inode=1316211 dev=fd:01 '
    "mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0\r\n"
    "type=EOE msg=audit(1791375352.583:4583): \r\n"
    "type=USER_LOGIN msg=audit(1791375363.591:4591): pid=3110 uid=0 auid=4294967295 ses=4294967295 "
    'subj=unconfined msg=\'op=login acct="oracle" exe="/usr/sbin/sshd" hostname=? addr=198.51.100.7 '
    "terminal=sshd res=failed'"
)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (RAW, True),
        ("node=srv-web01 " + RAW, True),
        ("noise\n" + RAW, True),
        ('{"ID":"1791375352.583:4583","SYSCALL":{}}', False),
        ("Oct  7 13:35:32 srv sshd[2240]: Failed password for oracle", False),
    ],
)
def test_raw_auditd_detection(text, expected):
    assert laurel.looks_like_raw_auditd(text) is expected


def test_conversion_keeps_json_only_and_drops_local_enrichment(monkeypatch):
    seen = {}

    def fake_run(argv, **kwargs):
        config = argv[2]
        seen["mode"] = stat.S_IMODE(os.stat(config).st_mode)
        with open(config, encoding="utf-8") as f:
            seen["config"] = f.read()
        seen["input"] = kwargs["input"]
        stdout = "\n".join(
            [
                "2026-10-10T11:00:00Z INFO  [laurel] Started laurel",
                '{"ID":"1.000:1","SYSCALL":{"pid":1,"UID_GROUPS":["app"]},"EXECVE":{"ARGV":["id"]}}',
                "2026-10-10T11:00:00Z ERROR [laurel] Error cannot parse body: garbage",
                '{"ID":"2.000:2","USER_LOGIN":{"msg":{"res":"failed"}}}',
                '{"ID":"3.000:3","USER_LOGIN":{"msg":{"res":"success"}}}',
            ]
        )
        return subprocess.CompletedProcess(argv, 0, stdout.encode(), b"")

    monkeypatch.setattr(laurel.shutil, "which", lambda name: "/usr/local/bin/laurel")
    monkeypatch.setattr(laurel.subprocess, "run", fake_run)
    text, count, truncated, errors = laurel.to_json_lines(RAW, max_events=2)

    events = [json.loads(line) for line in text.splitlines()]
    assert count == 2 and truncated and errors == 1
    assert events[0] == {"ID": "1.000:1", "SYSCALL": {"pid": 1}, "EXECVE": {"ARGV": ["id"]}}
    assert seen["mode"] == 0o600 or os.name == "nt"
    assert b"\r" not in seen["input"] and seen["input"].endswith(b"\n")
    for host_enrichment in ("pid = false", "spawned-by = false", "user-db = false", 'file = "-"', 'file = ""'):
        assert host_enrichment in seen["config"]


def test_conversion_reports_a_failing_binary(monkeypatch):
    monkeypatch.setattr(laurel.shutil, "which", lambda name: "/usr/local/bin/laurel")
    monkeypatch.setattr(laurel.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 1, b"", b""))
    with pytest.raises(laurel.LaurelError):
        laurel.to_json_lines(RAW, 10)


async def test_endpoint_without_laurel(monkeypatch):
    monkeypatch.setattr(laurel, "available", lambda: False)
    principal = types.SimpleNamespace(user=types.SimpleNamespace(id=1, username="u"))
    with pytest.raises(HTTPException) as exc:
        await workspace.pipeline_laurel(workspace.LaurelIn(input=RAW), None, principal=principal, db=None)
    assert exc.value.status_code == 503


@pytest.mark.skipif(not shutil.which(get_settings().laurel_bin), reason="LAUREL binary not installed")
def test_real_laurel_output_matches_the_library_parser():
    text, count, truncated, errors = laurel.to_json_lines(RAW, 100)
    assert (count, truncated, errors) == (2, False, 0)
    first, second = (json.loads(line) for line in text.splitlines())
    assert first["EXECVE"]["ARGV"] == ["useradd", "-m", "back door"]
    assert first["SYSCALL"]["SYSCALL"] == "execve" and "UID_GROUPS" not in first["SYSCALL"]
    assert second["USER_LOGIN"]["msg"]["addr"] == "198.51.100.7"
    assert parsers.detect(text, "lines")[0]["id"] == "auditd-laurel"
