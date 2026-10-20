@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

set PYTHON_EXE=C:\Users\juanp\AppData\Local\Programs\Python\Python311\python.exe
set CHAIN_SCRIPT=F:\repository-compiler\evolution\recursive_bootstrap_loop.py
set PID_FILE=F:\repository-compiler-generations\recursive_chain.pid
set STATUS_FILE=F:\repository-compiler-generations\recursive_chain_status.json
set LINEAGE_FILE=F:\repository-compiler-generations\lineage_tree.json

set STATUS_SCRIPT=F:\repository-compiler\evolution\status_dashboard.py

if "%1"=="" goto help
if "%1"=="help" goto help
if "%1"=="status" goto status
if "%1"=="watch" goto watch
if "%1"=="step" goto step
if "%1"=="start" goto start
if "%1"=="stop" goto stop
if "%1"=="run" goto run
if "%1"=="lineage" goto lineage

:help
echo ===============================================================================
echo   AETHERMIND RECURSIVE COMPILER EVOLVER (CLI)
echo ===============================================================================
echo   Ciclo Autogeno: A geracao N muta, prova via Z3 SMT, autocompila a geracao N+1,
echo   e a geracao N+1 assume o controle do ciclo posterior recursivamente.
echo.
echo   Comandos:
echo     evolver.cmd status        - Exibe o status ao vivo e o feed das ultimas mutacoes
echo     evolver.cmd watch         - Modo continuo ao vivo (atualiza a cada 1.5s na tela)
echo     evolver.cmd step          - Executa 1 ciclo recursivo completo (N compila N+1)
echo     evolver.cmd run --steps N - Executa N ciclos recursivos em cadeia
echo     evolver.cmd start         - Dispara a cadeia recursiva continua em background
echo     evolver.cmd stop          - Para a cadeia recursiva em background
echo     evolver.cmd lineage       - Exibe a arvore genealogica de todas as geracoes
echo ===============================================================================
goto end

:status
shift
set ARGS=
:loop_status
if "%1"=="" goto run_status
set ARGS=%ARGS% %1
shift
goto loop_status
:run_status
"%PYTHON_EXE%" "%STATUS_SCRIPT%" %ARGS%
goto end

:watch
shift
set ARGS=
:loop_watch
if "%1"=="" goto run_watch
set ARGS=%ARGS% %1
shift
goto loop_watch
:run_watch
"%PYTHON_EXE%" "%STATUS_SCRIPT%" --watch %ARGS%
goto end

:step
echo [EVOLVER] Executando 1 ciclo recursivo: Geracao N muta, autocompila Geracao N+1 e promove...
"%PYTHON_EXE%" "%CHAIN_SCRIPT%" --steps 1 --interval 0
goto end

:lineage
if exist "%LINEAGE_FILE%" (
    type "%LINEAGE_FILE%"
) else (
    echo [EVOLVER] Nenhuma linhagem gravada ainda. Execute: evolver.cmd step
)
goto end

:run
shift
set ARGS=
for /f "tokens=1* delims= " %%a in ("%*") do set ARGS=%%b
"%PYTHON_EXE%" "%CHAIN_SCRIPT%" !ARGS!
goto end

:start
if exist "%PID_FILE%" (
    set /p CURR_PID=<"%PID_FILE%"
    echo [EVOLVER] A cadeia recursiva ja esta ativa sob PID !CURR_PID!.
    echo Status: evolver.cmd status
    echo Parar:  evolver.cmd stop
    goto end
)
echo [EVOLVER] Iniciando Cadeia de Auto-Compilacao Recursiva Continua em background...
powershell -NoProfile -Command "Start-Process -FilePath '%PYTHON_EXE%' -ArgumentList '-u F:\repository-compiler\evolution\recursive_bootstrap_loop.py --continuous --interval 2.0' -RedirectStandardOutput 'F:\repository-compiler-generations\chain_live.log' -RedirectStandardError 'F:\repository-compiler-generations\chain_live_err.log' -WindowStyle Hidden"
ping 127.0.0.1 -n 2 >nul
if exist "%PID_FILE%" (
    set /p NEW_PID=<"%PID_FILE%"
    echo [EVOLVER] Cadeia iniciada com sucesso sob PID !NEW_PID!.
    echo Log continuo em: F:\repository-compiler-generations\chain_live.log
    echo Para verificar geracao ativa: evolver.cmd status
) else (
    echo [EVOLVER] Processo disparado. Verifique status com: evolver.cmd status
)
goto end

:stop
if not exist "%PID_FILE%" (
    echo [EVOLVER] Nenhuma cadeia recursiva ativa encontrada.
    goto end
)
set /p TARGET_PID=<"%PID_FILE%"
echo [EVOLVER] Encerrando cadeia recursiva com PID !TARGET_PID!...
taskkill /F /PID !TARGET_PID! >nul 2>&1
if exist "%PID_FILE%" del /f /q "%PID_FILE%" >nul 2>&1
echo [EVOLVER] Cadeia recursiva finalizada com sucesso.
goto end

:end
endlocal
