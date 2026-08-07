@echo off
@setlocal enabledelayedexpansion

call :build || call :error
exit /b

:error
    set "exit_code=%ERRORLEVEL%"
    echo Build failed (Exit code: %exit_code%)
exit /b %exit_code%

:build
    msbuild .\cryptopp\cryptlib.vcxproj /t:build /p:Configuration=Release;Platform="x64" || exit /b !ERRORLEVEL!
    chcp 65001
    msbuild .\shalo-archiver.sln /t:build /p:Configuration=Release || exit /b !ERRORLEVEL!
    cd shaloa-gui-frontend
    call npm ci || (set "exit_code=!ERRORLEVEL!" & cd .. & exit /b !exit_code!)
    call npm run build:win || (set "exit_code=!ERRORLEVEL!" & cd .. & exit /b !exit_code!)
    cd ..
    echo Build success
exit /b
