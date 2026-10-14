import json
import os
import subprocess

import pytest

from pingo.config import generate_key
from pingo.desktop import Desktop
from pingo.permissions import private_directory

pytestmark = pytest.mark.skipif(os.name != "nt", reason="native Windows ACL checks")


def acl(path):
    from pingo.windows import powershell

    return json.loads(
        powershell(
            "$a=Get-Acl -LiteralPath $p.path; "
            "@{protected=$a.AreAccessRulesProtected; "
            "sids=@($a.Access | ForEach-Object {"
            "$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value"
            "})} | ConvertTo-Json -Compress",
            {"path": str(path)},
        )
    )


def test_existing_public_directory_grants_are_replaced(tmp_path):
    directory = tmp_path / "private"
    directory.mkdir()
    subprocess.run(
        ["icacls", str(directory), "/grant", "*S-1-1-0:(OI)(CI)R"],
        check=True,
        capture_output=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    assert "S-1-1-0" in acl(directory)["sids"]
    private_directory(directory)
    secured = acl(directory)
    assert secured["protected"] and "S-1-1-0" not in secured["sids"]
    assert len(secured["sids"]) == 3


def test_key_does_not_inherit_public_parent_permissions(tmp_path):
    subprocess.run(
        ["icacls", str(tmp_path), "/grant", "*S-1-1-0:(OI)(CI)R"],
        check=True,
        capture_output=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    key = tmp_path / "peer.key"
    generate_key(key)
    secured = acl(key)
    assert secured["protected"] and "S-1-1-0" not in secured["sids"]
    assert len(secured["sids"]) == 3 and len(key.read_bytes()) == 32


def test_desktop_repairs_existing_app_owned_key_permissions(tmp_path):
    directory = tmp_path / "keys"
    directory.mkdir()
    key = directory / ("0" * 32 + ".key")
    key.write_bytes(bytes(range(32)))
    subprocess.run(
        ["icacls", str(key), "/grant", "*S-1-1-0:R"],
        check=True,
        capture_output=True,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    assert "S-1-1-0" in acl(key)["sids"]
    Desktop(tmp_path)
    assert "S-1-1-0" not in acl(key)["sids"]
