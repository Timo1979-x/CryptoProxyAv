@echo off
@REM "c:\Program Files (x86)\Windows Kits\10\Debuggers\x86\windbg.exe" -c "g" d:\work\contact\CryptoService_avest\CryptoService_41.exe

@REM "c:\Program Files (x86)\Windows Kits\10\Debuggers\x86\windbg.exe" -c "$$<D:\work\vs\CryptoProxyAv\reverse-engineering\avpass.dbg; $$<D:\work\vs\CryptoProxyAv\reverse-engineering\advapi32.dbg; $$<D:\work\vs\CryptoProxyAv\reverse-engineering\crypt32.dbg" "c:\Program Files (x86)\Avest\AvPCM_nces\AvCmUt4.exe" -s "%~f0"  -m -m1 -M -T
"c:\Program Files (x86)\Windows Kits\10\Debuggers\x86\windbg.exe" -c "$$<D:\work\vs\CryptoProxyAv\reverse-engineering\avpass.dbg; $$<D:\work\vs\CryptoProxyAv\reverse-engineering\crypt32.dbg; .echo ---------; g;" "c:\Program Files (x86)\Avest\AvPCM_nces\AvCmUt4.exe" -s "%~f0"  -m -m1 -M -T

@REM "c:\Program Files (x86)\Avest\AvPCM_nces\AvCmUt4.exe" -s "D:\work\vs\CryptoProxyAv\reverse-engineering\debug.bat" -m -m1 -M -T
