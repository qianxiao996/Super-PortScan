# -*- mode: python ; coding: utf-8 -*-

block_cipher = None


a = Analysis(['Super-PortScan.py'],
             pathex=['D:\\code\\Python37\\obj\\Super-PortScan'],
             binaries=[],
             datas=[],
             hiddenimports=['scapy','eventlet.hubs.epolls', 'dns.asyncresolver','dns.versioned','eventlet.hubs.kqueue', 'eventlet.hubs.selects', 'dns', 'dns.dnssec','dns.asyncbackend','dns.asyncquery','dns.e164', 'dns.hash', 'dns.namedict', 'dns.tsigkeyring', 'dns.update', 'dns.version', 'dns.zone'],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='Super-PortScan',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=True , icon='logo.ico')
