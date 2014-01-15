:: Copyright (c) 2013-2014, Intel Corporation
::
:: Redistribution and use in source and binary forms, with or without
:: modification, are permitted provided that the following conditions are met:
::
::  * Redistributions of source code must retain the above copyright notice,
::    this list of conditions and the following disclaimer.
::  * Redistributions in binary form must reproduce the above copyright notice,
::    this list of conditions and the following disclaimer in the documentation
::    and/or other materials provided with the distribution.
::  * Neither the name of Intel Corporation nor the names of its contributors
::    may be used to endorse or promote products derived from this software
::    without specific prior written permission.
::
:: THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
:: AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
:: IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
:: ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
:: LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
:: CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
:: SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
:: INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
:: CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
:: ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
:: POSSIBILITY OF SUCH DAMAGE.


:: This script executes ptt tests and compares the output of tools, like
:: ptxed or ptdump, with the expected output from the ptt testfile.

@echo off


:: **** check whether pttc, ptdump, ptxed and yasm are available
for %%i in (pttc.exe,ptdump.exe,ptxed.exe,yasm.exe) do (
	if "%%~$PATH:i" == "" (
		echo error: couldn't find "%%i"
		goto :eof
	)
)

:: **** do all the processing
for %%i in (%*) do call :do_work %%i

goto :eof



:do_work
setlocal

echo processing: %1

:: **** try to figure out org offset
set org=
findstr /m "org" %~dpn1.ptt >NUL
if %ERRORLEVEL% == 0 (
	for /f "tokens=2" %%i in ('findstr /R "org 0x" %~dpn1.ptt') do set org=%%i
) else (
	echo error: %1: org directive not found in test file!
	goto :error
)

:: **** run pttc, ptdump and ptxed
pttc %1 >NUL
if %ERRORLEVEL% neq 0 (
	echo error: pttc failed with %1
	goto :error
)
ptdump --lastip --fixed-offset-width %~dpn1.pt > %~dpn1-ptdump.out
ptxed --pt %~dpn1.pt --raw %~dpn1.bin:%org% --no-inst > %~dpn1-ptxed.out

:: **** compare outcomes to expected outputs
:: **** only keep .diff files and print the filename
:: **** if there actually were differences
fc /T /L /A /N %~dpn1-ptdump.exp %~dpn1-ptdump.out > %~dpn1-ptdump.diff
if %ERRORLEVEL% == 0 (
	del %~dpn1-ptdump.diff
) else (
	echo %~dpn1-ptdump.diff
)
fc /T /L /A /N %~dpn1-ptxed.exp %~dpn1-ptxed.out > %~dpn1-ptxed.diff
if %ERRORLEVEL% == 0 (
	del %~dpn1-ptxed.diff
) else (
	else %~dpn1-ptxed.diff
)

:: **** clean up all intermediate files
del %~dpn1.pt %~dpn1.bin %~dpn1.lst %~dpn1*.exp %~dpn1*.out

:error
endlocal
goto :eof