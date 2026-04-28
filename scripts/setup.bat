@echo off
setlocal EnableDelayedExpansion

echo ==================================================
echo Sentinel Verify - Automated Setup ^& Launch
echo ==================================================
echo.

cd ..\backend

echo [1/11] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH. Please install Python 3.9+ first.
    pause
    exit /b 1
)

echo [2/11] Checking pip installation...
python -m pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] pip is not installed.
    pause
    exit /b 1
)

echo [3/11] Setting up virtual environment...
if not exist venv (
    python -m venv venv
    echo Virtual environment created.
) else (
    echo Virtual environment already exists. Skipping creation.
)

echo [4/11] Activating virtual environment and upgrading pip...
call venv\Scripts\activate
python -m pip install --upgrade pip >nul 2>&1

echo [5/11] Installing/Updating dependencies (this may take a few minutes)...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies. Check your internet connection.
    pause
    exit /b 1
)

echo [6/11] Downloading required NLP resources...
python -m nltk.downloader punkt stopwords wordnet
python -m spacy download en_core_web_sm
if %errorlevel% neq 0 (
    echo [WARNING] Some NLP resources failed to download. Some features may not work.
)

echo [7/11] Preparing configuration...
if not exist .env (
    echo SECRET_KEY=super-secret-key-change-in-production > .env
    echo JWT_SECRET_KEY=jwt-secret-key-change-in-production >> .env
    echo DATABASE_URL=sqlite:///sentinel.db >> .env
    echo Created .env file.
) else (
    echo Configuration already exists.
)

echo [8/11] Preparing file structure...
if not exist logs mkdir logs
if not exist ..\ai_models\trained mkdir ..\ai_models\trained

echo [9/11] Initializing Database...
python -c "from app import create_app, db; app = create_app(); app.app_context().push(); db.create_all()"

echo [10/11] Running Database Migrations...
set FLASK_APP=run.py
if not exist migrations (
    flask db init
)
flask db migrate -m "Auto migration"
flask db upgrade

echo [11/11] Starting Application Services...
echo.
echo ==================================================
echo Starting Backend Server on http://127.0.0.1:5000
start "Sentinel Verify - Backend API" cmd /k "call venv\Scripts\activate && python run.py"

cd ..\frontend
echo Starting Frontend Server on http://127.0.0.1:8000
start "Sentinel Verify - Frontend UI" cmd /k "python -m http.server 8000"

echo ==================================================
echo Setup and launch complete!
echo.
echo Opening the application in your default web browser...
timeout /t 3 >nul
start http://127.0.0.1:8000

echo.
echo You may safely close this installation window.
echo The Backend and Frontend are running in separate terminal windows.
pause
exit /b 0
