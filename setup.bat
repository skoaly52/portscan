@echo off
chcp 65001 > nul
echo.
echo [PortScan] Installing required packages...
echo.

python -m pip install --upgrade pip
python -m pip install sv-ttk

echo.
echo [PortScan] Installation complete!
echo [PortScan] Starting the tool...
echo.

timeout /t 2 /nobreak > nul
python portscan.py

pause
