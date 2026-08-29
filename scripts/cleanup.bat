@echo off
setlocal

echo ==================================================
echo Sentinel Verify - Environment Cleanup
echo ==================================================
echo.
echo This script will reset local temporary environment files:
echo - Virtual Environment (venv)
echo - Local Configuration (.env)
echo - SQLite Database (sentinel.db)
echo - Application Logs
echo.
set /p confirm="Are you sure you want to proceed? (Y/N): "

if /i "%confirm%" neq "Y" (
    echo Cleanup cancelled.
    pause
    exit /b 0
)

pushd "%~dp0.."
set "ROOT_DIR=%CD%"
set "BACKEND_DIR=%ROOT_DIR%\backend"
popd

echo.
echo [1/4] Removing virtual environment...
if exist "%BACKEND_DIR%\venv" (
    rmdir /s /q "%BACKEND_DIR%\venv"
    echo Done.
) else (
    echo Virtual environment not found. Skipping.
)

echo [2/4] Removing local configuration (.env)...
if exist "%BACKEND_DIR%\.env" (
    del /f /q "%BACKEND_DIR%\.env"
    echo Done.
) else (
    echo .env file not found. Skipping.
)

echo [3/4] Removing SQLite database...
if exist "%BACKEND_DIR%\sentinel.db" (
    del /f /q "%BACKEND_DIR%\sentinel.db"
    echo Done.
) else (
    echo Database file not found. Skipping.
)

echo [4/4] Removing application logs...
if exist "%BACKEND_DIR%\logs" (
    rmdir /s /q "%BACKEND_DIR%\logs"
    echo Done.
) else (
    echo Logs folder not found. Skipping.
)

echo.
echo ==================================================
echo Cleanup complete! Your environment has been reset.
echo ==================================================
pause
exit /b 0
