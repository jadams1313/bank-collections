@echo off
setlocal enabledelayedexpansion

echo ========================================
echo   Finance Tracker Deployment Script
echo ========================================
echo.

:: -------- CONFIGURATION --------
:: Update this path if Qt is installed elsewhere
set "QTDIR=C:\Qt\6.7.0\mingw_64"
set "BUILD_DIR=build"
set "DEPLOY_DIR=deploy"

:: Ensure Qt tools are on PATH
set "PATH=%QTDIR%\bin;%PATH%"

:: -------- CLEAN PREVIOUS BUILD --------
echo Cleaning previous build...
if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
if exist "%DEPLOY_DIR%" rmdir /s /q "%DEPLOY_DIR%"
echo Done.
echo.

:: -------- CREATE BUILD DIRECTORY --------
echo Creating build directory...
mkdir "%BUILD_DIR%"
cd "%BUILD_DIR%" || goto error

:: -------- CONFIGURE PROJECT --------
echo Configuring with CMake...
cmake -G "MinGW Makefiles" ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DCMAKE_PREFIX_PATH="%QTDIR%" ^
    ..
if errorlevel 1 goto error

:: -------- BUILD APPLICATION --------
echo Building application...
cmake --build . --config Release -j4
if errorlevel 1 goto error
cd ..

:: -------- CREATE DEPLOY DIRECTORY --------
echo Creating deploy directory...
mkdir "%DEPLOY_DIR%"
echo.

:: -------- COPY EXECUTABLE --------
echo Copying executable...
if exist "%BUILD_DIR%\FinanceTracker.exe" (
    copy "%BUILD_DIR%\FinanceTracker.exe" "%DEPLOY_DIR%\" >nul
) else (
    echo ERROR: FinanceTracker.exe not found in build directory!
    goto error
)
echo.

:: -------- DEPLOY QT DEPENDENCIES --------
echo Deploying Qt dependencies...
cd "%DEPLOY_DIR%"
if exist "%QTDIR%\bin\windeployqt.exe" (
    "%QTDIR%\bin\windeployqt.exe" --release --qmldir .. FinanceTracker.exe
) else (
    echo ERROR: windeployqt.exe not found in %QTDIR%\bin
    goto error
)
if errorlevel 1 (
    echo Warning: windeployqt failed!
)
cd ..
echo.

:: -------- DEPLOY SQLITE DLL --------
echo Checking for SQLite3...
if exist "%QTDIR%\bin\libsqlite3-0.dll" (
    copy "%QTDIR%\bin\libsqlite3-0.dll" "%DEPLOY_DIR%\" >nul
    echo Copied SQLite DLL.
) else (
    echo SQLite DLL not found (may be statically linked).
)
echo.

:: -------- SUCCESS --------
echo ========================================
echo Deployment complete!
echo Location: %CD%\%DEPLOY_DIR%
echo ========================================
echo Run FinanceTracker.exe to test.
echo.
pause
goto end

:error
echo.
echo ========================================
echo ERROR: Deployment failed!
echo ========================================
pause

:end
endlocal