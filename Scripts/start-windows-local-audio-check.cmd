@echo off
setlocal EnableExtensions DisableDelayedExpansion
rem Package this file as Start-Check.cmd beside the complete bin directory.
pushd "%~dp0"
if errorlevel 1 goto directory_unavailable

for %%F in (Skybridge.WinClient.ContractTests.exe Skybridge.WinClient.ContractTests.dll Skybridge.WinClient.ContractTests.deps.json Skybridge.WinClient.ContractTests.runtimeconfig.json hostfxr.dll hostpolicy.dll coreclr.dll System.Private.CoreLib.dll) do if not exist "bin\%%F" (
    echo Missing required file: bin\%%F
    goto incomplete_bundle
)

".\bin\Skybridge.WinClient.ContractTests.exe" --native-local-audio-check "%~dp0Results"
set "check_exit=%ERRORLEVEL%"
echo.
echo Native qualification exit code: %check_exit%
if not "%check_exit%"=="0" echo The check did not complete successfully. Keep the error shown above.
echo If a report was written, the program printed its exact path above.
echo This is not an account or phone connection test.
if exist "Results\" start "" explorer.exe "%~dp0Results"
pause
popd
exit /b %check_exit%

:incomplete_bundle
echo.
echo Audio testing has NOT started. No audio report was created by this attempt.
echo Close this window. In File Explorer, select the ZIP and choose Extract all.
echo Open the extracted folder, then double-click Start-Check.cmd beside bin.
echo If you already extracted all files, keep this message and return to the chat.
pause
popd
exit /b 3

:directory_unavailable
echo The extracted check folder could not be opened. Audio testing has NOT started.
echo Keep this message and return to the chat.
pause
exit /b 3
