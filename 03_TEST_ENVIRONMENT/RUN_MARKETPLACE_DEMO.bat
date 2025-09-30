@echo off
echo ===============================================
echo   TICKETZERO AI - ZOHO MARKETPLACE DEMO
echo ===============================================
echo.
echo Starting the complete marketplace-ready demo...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found! Please install Python 3.8+
    echo Download from: https://python.org
    pause
    exit /b 1
)

REM Check if Ollama is running
echo Checking Ollama connection...
curl -s http://localhost:11434/api/tags >nul 2>&1
if errorlevel 1 (
    echo WARNING: Ollama not running or not accessible
    echo Please start Ollama with: ollama serve
    echo Or install from: https://ollama.ai
    echo.
    echo Demo will continue with fallback analysis...
    echo.
)

REM Install required packages
echo Installing Python dependencies...
pip install flask flask-cors requests colorama python-dotenv >nul 2>&1

REM Create logs directory
if not exist "logs" mkdir logs

echo.
echo ===============================================
echo   STARTING TICKETZERO AI MARKETPLACE API
echo ===============================================
echo.
echo API will be available at: http://localhost:5000
echo.
echo Available endpoints:
echo   • /api/health - Health check
echo   • /api/analyze-ticket - Ticket analysis
echo   • /api/execute-resolution - Execute fixes
echo   • /api/metrics - Performance metrics
echo   • /webhooks/ticket-created - New ticket webhook
echo.
echo Zoho Marketplace Integration:
echo   • Plugin ready for submission
echo   • OWASP security compliant
echo   • Full API documentation included
echo.
echo Press Ctrl+C to stop the server
echo ===============================================
echo.

REM Start the marketplace API server
python marketplace\zoho\api\zoho_integration.py

pause