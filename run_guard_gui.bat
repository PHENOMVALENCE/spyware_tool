@echo off
title Browser Data Guard
python "%~dp0browser_data_guard_gui.py"
if errorlevel 1 pause
