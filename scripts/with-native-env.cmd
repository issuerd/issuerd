@echo off
rem Run a command with MSVC build tools (and native perl, when present) on PATH.
rem
rem Required on Windows when building crates with C dependencies - currently
rem the vendored OpenSSL that webauthn-rs-core needs. OpenSSL's
rem Configure rejects Git Bash's MSYS perl; a native Windows perl is expected
rem at tools\strawberry-perl (portable edition, gitignored - see AGENTS.md),
rem but any native perl already on PATH works too.
rem
rem Usage (from Git Bash):  cmd.exe //c scripts\with-native-env.cmd cargo test --workspace
setlocal
set "REPO_ROOT=%~dp0.."
set "STRAWBERRY=%REPO_ROOT%\tools\strawberry-perl"
if exist "%STRAWBERRY%\perl\bin\perl.exe" (
    set "PATH=%STRAWBERRY%\perl\bin;%PATH%"
)
if not defined VCVARS64 set "VCVARS64=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS64%" (
    echo with-native-env: vcvars64.bat not found at "%VCVARS64%" 1>&2
    echo Set VCVARS64 to your Visual Studio installation's vcvars64.bat path. 1>&2
    exit /b 1
)
call "%VCVARS64%" >NUL
%*
