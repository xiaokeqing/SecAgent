@echo off
REM ============================================================
REM SecAgent security PoC for Windows (curl.exe is built into Win10/11)
REM IMPORTANT: run this from the project root (the folder that contains pom.xml)
REM   open that folder in Explorer, type "cmd" in the address bar, Enter
REM Start the app first: http://localhost:9900
REM ============================================================
setlocal
set BASE=http://localhost:9900
set CURL=curl.exe

REM create a clean english-named temp file to avoid non-ASCII path issues
echo this is a normal security knowledge note for testing. > test.md

echo [0] Health check (expect JSON with "status":"ok")
%CURL% -s %BASE%/api/health
echo.
echo.

echo [1] Normal upload (expect 200 success)
%CURL% -s -X POST %BASE%/api/upload -F "file=@test.md;filename=test.md"
echo.
echo.

echo [2] Path traversal via filename (FIXED: expect 400 invalid filename)
%CURL% -s -X POST %BASE%/api/upload -F "file=@test.md;filename=../../../../../../Windows/Temp/poc.txt"
echo.
echo.

echo [3] Path traversal via encoded separators (FIXED: expect 400)
%CURL% -s -X POST %BASE%/api/upload -F "file=@test.md;filename=..%%2f..%%2fpoc.txt"
echo.
echo.

echo [4] Disallowed extension (FIXED: expect 400)
%CURL% -s -X POST %BASE%/api/upload -F "file=@test.md;filename=shell.jsp"
echo.
echo.

echo [5] Sensitive content (cloud AccessKey) in document (FIXED: expect 422)
echo LTAI5t7abcdefghijklmnop > secret-demo.md
%CURL% -s -X POST %BASE%/api/upload -F "file=@secret-demo.md;filename=secret-demo.md"
echo.
del secret-demo.md 2>nul

echo.
echo [6] Optional auth demo (only if app.auth.enabled=true):
echo     no token  -^> expect 401 on protected endpoints
echo     %CURL% -s -H "X-API-Token: secagent-demo-token" %BASE%/api/health
echo.

del test.md 2>nul
echo Done.
endlocal
