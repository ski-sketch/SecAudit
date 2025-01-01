@echo off
setlocal

:: Set environment variables
set LOGSTASH_HOST=logstash
set LOGSTASH_PORT=5000

:: Check if the encryption key is set
if "%ENCRYPTION_KEY%"=="" (
  echo Error: ENCRYPTION_KEY environment variable is not set.
  exit /b 1
)

:: Run the Log.Analyzer.py script using a relative path
python "%~dp0Log.Analyzer.py"
if %errorlevel% neq 0 (
  echo Error: Failed to run Log.Analyzer.py
  exit /b %errorlevel%
)

endlocal