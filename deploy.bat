@echo off
echo ========================================
echo Finance Tracker Deployment Script
echo ========================================

:: Set Qt path (adjust to your Qt installation)
set QTDIR=C:\Qt\6.7.0\mingw_64
set PATH=%QTDIR%\bin;%PATH%

:: Clean previous build
echo Cleaning previous build...
rmdir /s /q build 2>nul
rmdir /s /q deploy 2>nul

:: Create build directory
echo Creating build directory...
mkdir build
cd build

:: Configure
echo Configuring with CMake...
cmake -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=%QTDIR% ..
if errorlevel 1 goto error

:: Build
echo Building application...
cmake --build . -j4
if errorlevel 1 goto error

:: Create deploy directory
cd ..
mkdir deploy

:: Copy executable
echo Copying executable...
copy build\FinanceTracker.exe deploy\
if errorlevel 1 goto error

:: Deploy Qt dependencies
echo Deploying Qt dependencies...
cd deploy
windeployqt --sql FinanceTracker.exe
if errorlevel 1 (
    echo Warning: windeployqt failed, trying with full path
    %QTDIR%\bin\windeployqt.exe FinanceTracker.exe
)

echo.
echo ========================================
echo Deployment complete!
echo Location: %CD%
echo ========================================
echo.
echo Run FinanceTracker.exe to test

pause
goto end

:error
echo.
echo ========================================
echo ERROR: Deployment failed!
echo ========================================
pause

:end