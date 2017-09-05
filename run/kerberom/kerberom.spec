# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <jean-christophe.delaunay (at) synacktiv.com> wrote this file.  As long as you
# retain this notice you can do whatever you want with this stuff. If we meet
# some day, and you think this stuff is worth it, you can buy me a beer in
# return.   Fist0urs
# ----------------------------------------------------------------------------

# -*- mode: python -*-

import sys, string, random

sys.path.append("./modules")

def random_key():
    charset = string.printable
    return ''.join(random.choice(charset) for _ in range(16))

def random_name(name_length = 1):
    charset = string.ascii_lowercase
    return ''.join(random.choice(charset) for _ in range(name_length))

block_cipher = pyi_crypto.PyiBlockCipher(key = random_key())

a = Analysis(['kerberom.py', 'kerberom.spec'],
             pathex=['ABSOLUTE_PATH_TO_KERBEROM_FOLDER'],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=["pywin", "pywin.debugger", "pywin.debugger.dbgcon",
                       "pywin.dialogs", "pywin.dialogs.list", "Tkconstants",
                       "Tkinter", "tcl", "Carbon", "Carbon.Files", "email",
                       "email.utils", "_scproxy", "urllib.parse", "winreg",
                       "queue", "extend.ExtendedOperationsRoot",
                       "backports.ssl_match_hostname", "future.types.newstr",
                       "gssapi", "unittest", "xml", "xml.parsers.expat",
                       "w9xpopen.exe", "wx", "org", "EasyDialogs", "termios",
                       "pwd", "fcntl", "readline", "org.python", "backports",
                       "vms_lib", "'java.lang'", "java", "'xml.parsers'",
                       "'Carbon.File'", "MacOS", "macresource", "gestalt",
                       "_dummy_threading", "SOCKS", "rourl2path", "'dbm.ndbm'",
                       "gdbm", "'dbm.gnu'", "'dbm.dumb'", "bsddb3", "_pybsddb",
                       "dbm", "_sysconfigdata", "grp", "'test.support'", "_datetime",
                       "reprlib.recursive_repr", "_thread.get_ident", "riscosenviron",
                       "riscospath", "riscos", "ce", "_emx_link", "os2", "posix",
                       "resource"],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)

pyz = PYZ(a.pure, a.zipped_data,
          cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='kerberom', # or random_name(6)
          debug=False,
          icon=None,
          strip=False,
          upx=False,
          console=True )
