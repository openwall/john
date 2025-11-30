@echo off
title Crack ZIP (ZipCrypto) with John the Ripper
setlocal ENABLEDELAYEDEXPANSION

cd /d "%~dp0"

echo ============================================================
echo  START OF SCRIPT  crack_zip.bat
echo ============================================================
echo Current working directory:
echo   %cd%
echo.

rem --- CHECK FOR john.exe AND zip2john.exe ---------------------

if not exist "john.exe" (
    echo ERROR: "john.exe" was not found in this directory.
    echo Please place this BAT file in the same directory as john.exe and zip2john.exe.
    goto END
)

if not exist "zip2john.exe" (
    echo ERROR: "zip2john.exe" was not found in this directory.
    echo Please place this BAT file in the same directory as john.exe and zip2john.exe.
    goto END
)

echo Environment OK: john.exe and zip2john.exe found.
echo.

rem --- ZIP FILE SELECTION ---------------------------------------

set /p CONFIRM="Have you copied the target ZIP file into THIS directory? (Y/N): "
if /I not "%CONFIRM%"=="Y" (
    echo Operation cancelled by user.
    goto END
)

echo.
echo Enter the ZIP filename (without ".zip")
echo Example: if the file is PHOTOS.ZIP, type: PHOTOS
echo.
set /p ZIPNAME="Filename: "

if "%ZIPNAME%"=="" (
    echo No filename entered. Exiting...
    goto END
)

set "ZIPFILE=%ZIPNAME%"
if /I not "%ZIPFILE:~-4%"==".zip" set "ZIPFILE=%ZIPFILE%.zip"

echo.
echo Target file: "%ZIPFILE%"
if not exist "%ZIPFILE%" (
    echo ERROR: File "%ZIPFILE%" not found in:
    echo        %cd%
    goto END
)

rem --- CLEAN PREVIOUS RUN ARTIFACTS -----------------------------

if exist hash.txt del /f /q hash.txt
if exist john_run.log del /f /q john_run.log
if exist john.pot del /f /q john.pot

rem --- 1/3: EXTRACT HASH ----------------------------------------

echo.
echo [1/3] Extracting hash with zip2john...
zip2john.exe "%ZIPFILE%" > hash.txt

if not exist hash.txt (
    echo ERROR: hash.txt was not created.
    goto END
)

for %%A in (hash.txt) do set HSIZE=%%~zA
if "!HSIZE!"=="0" (
    echo ERROR: hash.txt is empty. Unsupported format?
    goto END
)

rem --- 2/3: RUN JOHN THE RIPPER ---------------------------------

echo.
echo [2/3] Cracking password with john...
echo (depending on complexity, this may take a while)
echo.

rem Save john's output to a log file and also show it on screen
john.exe --pot=john.pot hash.txt > john_run.log
type john_run.log

rem --- 3/3: FIND AND DISPLAY THE PASSWORD LINE -----------------

echo.
echo [3/3] Reading extracted password...

set "PASS_LINE="

rem Search for the line containing ".zip)" (e.g. "ali (photos.zip)")
for /f "usebackq delims=" %%L in (`findstr /I /C:".zip)" john_run.log`) do (
    set "PASS_LINE=%%L"
    goto FOUND
)

:FOUND
if not defined PASS_LINE (
    echo.
    echo No line containing ".zip)" was found in the log.
    echo John may have failed to crack the password.
    goto END
)

echo.
echo ===============================================
echo  PASSWORD FOUND FOR "%ZIPFILE%"
echo  (line from john):
echo      %PASS_LINE%
echo ===============================================
echo.
echo The password is the text BEFORE the parenthesis.
echo Example from the line:
echo      ali (asdf.zip)
echo The password would be: ali
echo.

:END
echo.
echo END OF SCRIPT. Press any key to close this window...
pause >nul
endlocal
