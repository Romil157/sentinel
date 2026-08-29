@echo off
setlocal EnableDelayedExpansion

echo ==================================================
echo Sentinel Verify - Automated Setup ^& Launch
echo ==================================================
echo.

pushd "%~dp0.."
set "ROOT_DIR=%CD%"
set "BACKEND_DIR=%ROOT_DIR%\backend"
set "FRONTEND_DIR=%ROOT_DIR%\frontend"
popd

cd /d "%BACKEND_DIR%"

echo [1/10] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH. Please install Python 3.9+ first.
    pause
    exit /b 1
)

echo [2/10] Checking pip installation...
python -m pip --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] pip is not installed.
    pause
    exit /b 1
)

echo [3/10] Setting up virtual environment...
if not exist venv (
    python -m venv venv
    echo Virtual environment created.
) else (
    echo Virtual environment already exists.
)

echo [4/10] Activating virtual environment and updating pip...
call venv\Scripts\activate
python -m pip install --upgrade pip >nul 2>&1

echo [5/10] Installing dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [WARNING] Some dependencies encountered issues. Attempting core initialization...
)

echo [6/10] Initializing NLP resources...
python -m nltk.downloader punkt punkt_tab stopwords wordnet >nul 2>&1
python -m spacy download en_core_web_sm >nul 2>&1

echo [7/10] Preparing configuration and environment...
if not exist .env (
    echo SECRET_KEY=sentinel-verify-dev-secret-key > .env
    echo JWT_SECRET_KEY=sentinel-verify-jwt-secret-key >> .env
    echo DATABASE_URL=sqlite:///sentinel.db >> .env
    echo FLASK_CONFIG=dev >> .env
    echo Created default .env configuration.
) else (
    echo Existing .env configuration loaded.
)

if not exist logs mkdir logs
if not exist "%ROOT_DIR%\ai_models" mkdir "%ROOT_DIR%\ai_models"
if not exist "%ROOT_DIR%\ai_models\trained" mkdir "%ROOT_DIR%\ai_models\trained"

echo [8/10] Initializing database tables...
python -c "from app import create_app, db; app = create_app(); app.app_context().push(); db.create_all()" >nul 2>&1

echo [9/10] Starting Backend API Server (Port 5000)...
start "Sentinel Verify - Backend API" /D "%BACKEND_DIR%" cmd /k "call venv\Scripts\activate && python run.py"

echo [10/10] Starting Frontend UI Server (Port 8000)...
start "Sentinel Verify - Frontend UI" /D "%FRONTEND_DIR%" cmd /k "python -m http.server 8000"

echo.
echo ==================================================
echo Setup and launch complete!
echo.
echo Backend API : http://127.0.0.1:5000/api/v1/health
echo Frontend UI : http://127.0.0.1:8000
echo ==================================================
echo.
echo Launching Sentinel Verify in your default browser...
timeout /t 3 >nul
start http://127.0.0.1:8000

echo.
echo You may safely close this setup window.
pause
exit /b 0
