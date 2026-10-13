@echo off
cd /d "%~dp0"
if not exist frontend\dist\index.html (
  echo Building the UI...
  pushd frontend
  call npm install || exit /b 1
  call npm run build || exit /b 1
  popd
)
python -m pip install -q -r backend\requirements.txt
cd backend
python app.py
