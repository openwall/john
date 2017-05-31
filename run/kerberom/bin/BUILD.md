Compilation was successful on an x64 architecture with the following dependencies:

- Python: 2.7.13 (x86)
- PyInstaller: 3.2.1 (x86)
- Microsoft Visual C++ Compiler for Python 2.7 (https://www.microsoft.com/en-us/download/details.aspx?id=44266)
- pywin32
- pyasn1==0.2.3
- ldap3==2.2.4
- pyopenssl
- pycrypto

Please let me know if some dependencies are missing.

Before compiling with PyInstaller, please make sure to replace 'ABSOLUTE_PATH_TO_KERBEROM_FOLDER' in 'kerberom.spec'.

For example, if your kerberom folder location follows this scheme:

```
C:\
--> Python27\
--> Users\
    --> Foo\
        --> Desktop\
            --> kerberom\
                --> modules\
                --> kerberom.py
                --> kerberom.spec
                --> INSTALL.md
```

ABSOLUTE_PATH_TO_KERBEROM_FOLDER will be 'C:\\\\Users\\\\Foo\\\\Desktop\\\\kerberom'

Compilation command will be:

cmd> C:\Python27\Scripts\pyinstaller.exe "C:\Users\Foo\Desktop\kerberom\kerberom.spec"
