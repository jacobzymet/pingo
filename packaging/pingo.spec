# Build a windowed app and a hidden console worker in one portable directory.
from pathlib import Path
from importlib.metadata import distribution
import sys

root = Path(SPECPATH).parent
assets = [
    (str(root / "src/pingo/ui"), "pingo/ui"),
    (str(root / "licenses/noiseprotocol-LICENSE.txt"), "licenses"),
    (str(root / "licenses/proxy-tools-LICENSE.txt"), "licenses/proxy-tools"),
    (str(Path(sys.base_prefix) / "LICENSE.txt"), "licenses/python"),
]
for dependency in (
    "pywebview", "pythonnet", "clr-loader", "bottle", "typing-extensions",
    "cffi", "pycparser", "cryptography", "noiseprotocol", "pyinstaller",
):
    metadata = distribution(dependency)
    for entry in metadata.files or ():
        if entry.name.lower().startswith(("license", "copying", "notice")):
            assets.append((str(metadata.locate_file(entry)), "licenses/" + dependency))
gui = Analysis(
    [str(root / "packaging/desktop_entry.py")], pathex=[str(root / "src")],
    datas=assets, hiddenimports=["webview.platforms.edgechromium"],
    excludes=["PyQt5", "PyQt6", "PySide2", "PySide6", "tkinter"],
)
worker = Analysis(
    [str(root / "packaging/worker_entry.py")], pathex=[str(root / "src")],
)
app = EXE(PYZ(gui.pure), gui.scripts, [], exclude_binaries=True,
          name="Pingo", console=False)
engine = EXE(PYZ(worker.pure), worker.scripts, [], exclude_binaries=True,
             name="Pingo-worker", console=True)
bundle = COLLECT(app, engine, gui.binaries, gui.datas, worker.binaries, worker.datas,
                 name="Pingo")
