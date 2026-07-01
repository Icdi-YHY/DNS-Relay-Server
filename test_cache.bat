@echo off
start /B .\dnsrelay.exe -dd 10.3.9.5 dnsrelay.txt > server_log.txt 2>&1
timeout /t 2 /nobreak > nul
nslookup www.baidu.com 127.0.0.1 > query1.txt 2>&1
timeout /t 1 /nobreak > nul
nslookup www.baidu.com 127.0.0.1 > query2.txt 2>&1
taskkill /f /im dnsrelay.exe > nul 2>&1
timeout /t 1 /nobreak > nul
echo ===== SERVER LOG =====
type server_log.txt
echo.
type query1.txt
echo.
type query2.txt
