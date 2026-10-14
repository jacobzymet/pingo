"""Runtime license notices shared by native PyInstaller builds."""

import sys
import sysconfig
from importlib.metadata import distribution
from pathlib import Path

from packaging.requirements import Requirement


def assets(root):
    files = [(str(root / "src/pingo/ui"), "pingo/ui")]
    for path in (root / "licenses").glob("*.txt"):
        files.append((str(path), "licenses"))
    candidates = [
        Path(sys.base_prefix) / "LICENSE.txt",
        Path(sysconfig.get_path("stdlib")) / "LICENSE.txt",
    ]
    python_license = next((path for path in candidates if path.is_file()), None)
    if python_license is None:
        raise RuntimeError("Python's LICENSE.txt must be available for a release build")
    files.append((str(python_license), "licenses/python"))
    pending, seen = ["noiseprotocol", "cryptography", "pywebview", "pyinstaller"], set()
    while pending:
        metadata = distribution(pending.pop())
        name = metadata.metadata["Name"]
        if name in seen:
            continue
        seen.add(name)
        for entry in metadata.files or ():
            if entry.name.lower().startswith(("license", "copying", "notice")):
                # Keep vendored notices separate even when their basenames are identical.
                directory = "licenses/" + name + "/" + str(entry.parent).replace("\\", "/")
                files.append((str(metadata.locate_file(entry)), directory))
        for dependency in metadata.requires or ():
            requirement = Requirement(dependency)
            if requirement.marker is None or requirement.marker.evaluate({"extra": ""}):
                pending.append(requirement.name)
    return files
