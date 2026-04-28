@echo off
setlocal

echo ==================================================
echo Sentinel Verify - Environment Cleanup
echo ==================================================
echo.
echo This script will remove all local environment files:
echo - Virtual Environment (venv)
echo - Local Configuration (.env)
echo - SQLite Database
echo - Database Migrations
echo - Application Logs
echo - Trained Model Artifacts
echo.
set /p confirm="Are you sure you want to proceed? (Y/N): "

if /i "%confirm%" neq "Y" (
    echo Cleanup cancelled.
    pause
    exit /b 0
)

echo.
echo [1/6] Removing virtual environment...
if exist ..\backend\venv (
    rmdir /s /q ..\backend\venv
    echo Done.
) else (
    echo Virtual environment not found. Skipping.
)

echo [2/6] Removing local configuration (.env)...
if exist ..\backend\.env (
    del /f /q ..\backend\.env
    echo Done.
) else (
    echo .env file not found. Skipping.
)

echo [3/6] Removing SQLite database...
if exist ..\backend\sentinel.db (
    del /f /q ..\backend\sentinel.db
    echo Done.
) else (
    echo Database file not found. Skipping.
)

echo [4/6] Removing database migrations...
if exist ..\backend\migrations (
    rmdir /s /q ..\backend\migrations
    echo Done.
) else (
    echo Migrations folder not found. Skipping.
)

echo [5/6] Removing application logs...
if exist ..\backend\logs (
    rmdir /s /q ..\backend\logs
    echo Done.
) else (
    echo Logs folder not found. Skipping.
)

echo [6/6] Removing trained model artifacts...
if exist ..\ai_models\trained (
    del /f /q ..\ai_models\trained\*.pkl
    echo Done.
) else (
    echo Models folder not found. Skipping.
)

echo.
echo ==================================================
echo Cleanup complete! Your environment has been reset.
echo ==================================================
pause
