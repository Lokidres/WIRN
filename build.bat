@echo off
REM WIRN Build Script for Windows
REM Advanced Process Spy Tool - Windows Build automation

setlocal enabledelayedexpansion

REM Colors (limited support in Windows cmd)
set "GREEN=[92m"
set "RED=[91m"
set "YELLOW=[93m"
set "BLUE=[94m"
set "NC=[0m"

REM Build configuration
set "BINARY_NAME=wirn.exe"
set "VERSION=dev"
set "BUILD_TIME=%date:~-4,4%-%date:~-10,2%-%date:~-7,2%_%time:~0,2%-%time:~3,2%-%time:~6,2%"
set "BUILD_TIME=%BUILD_TIME: =0%"

echo %BLUE%╔══════════════════════════════════════════════════════════════════════════════╗%NC%
echo %BLUE%║                              WIRN BUILD SCRIPT                            ║%NC%
echo %BLUE%║                        Advanced Process Spy Tool                          ║%NC%
echo %BLUE%╚══════════════════════════════════════════════════════════════════════════════╝%NC%
echo.

REM Check if Go is installed
where go >nul 2>nul
if %errorlevel% neq 0 (
    echo %RED%[ERROR]%NC% Go is not installed or not in PATH
    exit /b 1
)

for /f "tokens=3" %%i in ('go version') do set "GO_VERSION=%%i"
echo %GREEN%[INFO]%NC% Go version: %GO_VERSION%

REM Clean previous builds
echo %GREEN%[INFO]%NC% Cleaning previous builds...
if exist dist rmdir /s /q dist
mkdir dist

REM Download dependencies
echo %GREEN%[INFO]%NC% Downloading dependencies...
go mod download
go mod tidy

REM Run tests
echo %GREEN%[INFO]%NC% Running tests...
go test -v ./...
if %errorlevel% neq 0 (
    echo %RED%[ERROR]%NC% Tests failed
    exit /b 1
)
echo %GREEN%[INFO]%NC% All tests passed

REM Build for Windows
echo %GREEN%[INFO]%NC% Building for Windows...
go build -ldflags "-X main.version=%VERSION% -X main.buildTime=%BUILD_TIME%" -o "%BINARY_NAME%" main.go
if %errorlevel% neq 0 (
    echo %RED%[ERROR]%NC% Build failed
    exit /b 1
)

echo %GREEN%[INFO]%NC% ✓ Built: %BINARY_NAME%

REM Create checksum
echo %GREEN%[INFO]%NC% Creating checksum...
certutil -hashfile "%BINARY_NAME%" SHA256 > "%BINARY_NAME%.sha256"

echo.
echo %GREEN%[INFO]%NC% Build completed successfully!
echo %GREEN%[INFO]%NC% Binary: %BINARY_NAME%
echo %GREEN%[INFO]%NC% Checksum: %BINARY_NAME%.sha256
echo.
echo %YELLOW%Usage examples:%NC%
echo   %BINARY_NAME%
echo   %BINARY_NAME% --stealth
echo   %BINARY_NAME% --log --network
echo   %BINARY_NAME% --help
echo.

pause
