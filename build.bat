@echo off
@setlocal

call :build || call :error
exit /b

:error
    echo Build failed (Exit code: %ERRORLEVEL%)
exit /b

:build
    msbuild .\cryptopp\cryptlib.vcxproj /t:build /p:Configuration=Release;Platform="x64" || exit /b !ERRORLEVEL!
    msbuild .\shalo-archiver.sln /t:build /p:Configuration=Release || exit /b !ERRORLEVEL!
    cd shaloa-gui-frontend
    call npm ci || cd .. && exit /b !ERRORLEVEL!
    call npm run build:win || cd .. && exit /b !ERRORLEVEL!
    cd ..
    echo Build success
exit /b
