a = Analysis(
    ['syncICGF.py'],
    pathex=[],
    binaries=[],
    datas=[('icon.png', '.')],
    hiddenimports=['schedule'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyinstaller --onefile --windowed --name SyncICGFront --add-data "icon.png;." --hidden-import win32timezone --hidden-import win32crypt --hidden-import schedule --hidden-import pymssql --hidden-import pystray --hidden-import PIL syncICGF.py