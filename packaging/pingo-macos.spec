import runpy
from pathlib import Path

root = Path(SPECPATH).parent
assets = runpy.run_path(str(root / "packaging/common.py"))["assets"](root)
gui = Analysis(
    [str(root / "packaging/desktop_entry.py")], pathex=[str(root / "src")],
    datas=assets, hiddenimports=["webview.platforms.cocoa"],
    excludes=["PyQt5", "PyQt6", "PySide2", "PySide6", "tkinter", "webview.platforms.edgechromium"],
)
worker = Analysis([str(root / "packaging/worker_entry.py")], pathex=[str(root / "src")])
app = EXE(PYZ(gui.pure), gui.scripts, [], exclude_binaries=True, name="Pingo", console=False)
engine = EXE(PYZ(worker.pure), worker.scripts, [], exclude_binaries=True,
             name="Pingo-worker", console=True)
bundle = COLLECT(app, engine, gui.binaries, gui.datas, worker.binaries, worker.datas, name="Pingo")
application = BUNDLE(
    bundle, name="Pingo.app", bundle_identifier="io.github.jacobzymet.pingo",
    info_plist={"NSHighResolutionCapable": True, "LSMinimumSystemVersion": "12.0"},
)
