# install-windows.ps1 - Windows installation script for agentsh
#
# Usage:
#   iex ((New-Object System.Net.WebClient).DownloadString('https://get.agentsh.dev/windows'))
#   .\install-windows.ps1 [-Mode <native|wsl2|auto>] [-Version <version>]
#
# Parameters:
#   -Mode      Installation mode: native, wsl2, or auto (default: auto)
#   -Version   Version to install (default: latest)
#   -InstallDir Installation directory (default: $env:LOCALAPPDATA\agentsh)

param(
    [ValidateSet('native', 'wsl2', 'auto')]
    [string]$Mode = 'auto',

    [string]$Version = 'latest',

    [string]$InstallDir = "$env:LOCALAPPDATA\agentsh"
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'  # Faster downloads

$GitHubRepo = "agentsh/agentsh"

# Helper functions for colored output
function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
}

function Write-Err {
    param([string]$Message)
    Write-Host "[ERROR] " -ForegroundColor Red -NoNewline
    Write-Host $Message
}

# Check if running as Administrator
function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check if WSL2 is available
function Test-WSL2 {
    try {
        $wslOutput = wsl --status 2>&1
        if ($LASTEXITCODE -eq 0) {
            $wslString = $wslOutput -join " "
            return ($wslString -match "Default Version: 2" -or $wslString -match "WSL version")
        }
        return $false
    }
    catch {
        return $false
    }
}

# Check if winget is available
function Test-Winget {
    try {
        $null = Get-Command winget -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

# Get the latest version from GitHub
function Get-LatestVersion {
    try {
        $response = Invoke-RestMethod -Uri "https://api.github.com/repos/$GitHubRepo/releases/latest" -Method Get
        return $response.tag_name
    }
    catch {
        Write-Err "Failed to fetch latest version: $_"
        exit 1
    }
}

# Detect system architecture
function Get-SystemArch {
    if ([Environment]::Is64BitOperatingSystem) {
        return "amd64"
    }
    else {
        return "386"
    }
}

# Install WinFsp for filesystem interception
function Install-WinFsp {
    Write-Info "Installing WinFsp..."

    if (Test-Winget) {
        try {
            winget install WinFsp.WinFsp --accept-source-agreements --accept-package-agreements --silent
            Write-Info "WinFsp installed successfully"
            return $true
        }
        catch {
            Write-Warn "Failed to install WinFsp via winget: $_"
        }
    }

    # Fallback: Download directly
    Write-Info "Downloading WinFsp from GitHub..."
    $winfspUrl = "https://github.com/winfsp/winfsp/releases/download/v2.0/winfsp-2.0.23075.msi"
    $msiPath = "$env:TEMP\winfsp.msi"

    try {
        Invoke-WebRequest -Uri $winfspUrl -OutFile $msiPath
        Start-Process msiexec.exe -ArgumentList "/i", $msiPath, "/quiet", "/norestart" -Wait
        Remove-Item $msiPath -Force
        Write-Info "WinFsp installed successfully"
        return $true
    }
    catch {
        Write-Err "Failed to install WinFsp: $_"
        return $false
    }
}

# Install WinDivert for network interception
function Install-WinDivert {
    Write-Info "Installing WinDivert..."

    $windivertUrl = "https://github.com/basil00/Divert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip"
    $zipPath = "$env:TEMP\windivert.zip"
    $extractPath = "$env:ProgramFiles\WinDivert"

    try {
        Invoke-WebRequest -Uri $windivertUrl -OutFile $zipPath
        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
        Remove-Item $zipPath -Force

        # Add to system PATH
        $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
        if ($currentPath -notlike "*WinDivert*") {
            [Environment]::SetEnvironmentVariable("Path", "$currentPath;$extractPath\x64", "Machine")
            Write-Info "Added WinDivert to system PATH"
        }

        Write-Info "WinDivert installed to $extractPath"
        return $true
    }
    catch {
        Write-Err "Failed to install WinDivert: $_"
        return $false
    }
}

# Install WSL2 and Ubuntu
function Install-WSL2 {
    Write-Info "Setting up WSL2..."

    try {
        # Enable WSL2 if not already enabled
        if (-not (Test-WSL2)) {
            Write-Info "Enabling WSL2 feature..."
            wsl --install --no-distribution
            Write-Warn "WSL2 feature enabled. A restart may be required."
        }

        # Install Ubuntu
        Write-Info "Installing Ubuntu distribution..."
        wsl --install -d Ubuntu-24.04

        Write-Info "Waiting for Ubuntu to initialize..."
        Start-Sleep -Seconds 5

        # Install agentsh inside WSL2
        Write-Info "Installing agentsh in WSL2..."
        wsl -d Ubuntu-24.04 -- bash -c 'curl -fsSL https://get.agentsh.dev/linux | bash'

        Write-Info "WSL2 with agentsh installed successfully"
        return $true
    }
    catch {
        Write-Err "Failed to install WSL2: $_"
        return $false
    }
}

# Download and install agentsh native binary
function Install-AgentshNative {
    param([string]$Ver)

    $arch = Get-SystemArch

    if ($Ver -eq "latest") {
        $Ver = Get-LatestVersion
    }

    Write-Info "Installing agentsh $Ver for windows/$arch..."

    $downloadUrl = "https://github.com/$GitHubRepo/releases/download/$Ver/agentsh-windows-$arch.exe"
    $tmpFile = "$env:TEMP\agentsh-$$.exe"

    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tmpFile

        # Create install directory
        if (-not (Test-Path $InstallDir)) {
            New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
        }

        # Move to install directory
        Move-Item -Path $tmpFile -Destination "$InstallDir\agentsh.exe" -Force

        # Add to user PATH
        $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($currentPath -notlike "*agentsh*") {
            [Environment]::SetEnvironmentVariable("Path", "$currentPath;$InstallDir", "User")
            Write-Info "Added $InstallDir to user PATH"
        }

        Write-Info "agentsh installed to $InstallDir\agentsh.exe"
        return $true
    }
    catch {
        Write-Err "Failed to download agentsh: $_"
        return $false
    }
}

# Install envshim helper
function Install-Envshim {
    param([string]$Ver)

    $arch = Get-SystemArch

    if ($Ver -eq "latest") {
        $Ver = Get-LatestVersion
    }

    Write-Info "Installing envshim helper..."

    $downloadUrl = "https://github.com/$GitHubRepo/releases/download/$Ver/envshim-windows-$arch.exe"
    $tmpFile = "$env:TEMP\envshim-$$.exe"

    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tmpFile
        Move-Item -Path $tmpFile -Destination "$InstallDir\envshim.exe" -Force
        Write-Info "envshim installed to $InstallDir\envshim.exe"
        return $true
    }
    catch {
        Write-Warn "envshim not available for this release (optional component)"
        return $false
    }
}

# Verify installation
function Test-Installation {
    # Refresh PATH
    $env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [Environment]::GetEnvironmentVariable("Path", "User")

    if (Get-Command agentsh -ErrorAction SilentlyContinue) {
        Write-Info "Verification successful!"
        try {
            & agentsh version
        }
        catch {
            # Version command might not exist yet
        }
        return $true
    }
    else {
        Write-Warn "agentsh not found in PATH. You may need to restart your terminal."
        return $false
    }
}

# Print post-install instructions
function Write-Instructions {
    param([string]$InstalledMode)

    Write-Host ""
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  agentsh installed successfully!" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""

    switch ($InstalledMode) {
        'native' {
            Write-Host "Run with (as Administrator):"
            Write-Host "  agentsh server"
            Write-Host ""
            Write-Host "Note: Native mode provides partial isolation (55%)."
            Write-Host "      Use WSL2 mode for full security features."
        }
        'wsl2' {
            Write-Host "Run with:"
            Write-Host "  wsl -d Ubuntu-24.04 -- agentsh server"
            Write-Host ""
            Write-Host "Or use the native wrapper:"
            Write-Host "  agentsh server --mode=wsl2"
            Write-Host ""
            Write-Host "Security level: 100% (full Linux isolation)"
        }
    }

    Write-Host ""
    Write-Host "Check status with: agentsh status"
    Write-Host ""
    Write-Host "Configuration:"
    Write-Host "  Default config: $env:APPDATA\agentsh\config.yml"
    Write-Host "  Default policy: $env:APPDATA\agentsh\policy.yml"
    Write-Host ""
    Write-Host "Documentation:"
    Write-Host "  https://github.com/$GitHubRepo"
    Write-Host ""
}

# Main installation flow
function Main {
    Write-Host "agentsh Windows Installer" -ForegroundColor Cyan
    Write-Host "=========================" -ForegroundColor Cyan
    Write-Host ""

    $selectedMode = $Mode

    # Auto-detect mode
    if ($selectedMode -eq 'auto') {
        if (Test-WSL2) {
            $selectedMode = 'wsl2'
            Write-Info "WSL2 detected. Using WSL2 mode for full security."
        }
        else {
            $selectedMode = 'native'
            Write-Info "WSL2 not available. Using native Windows mode."
        }
    }

    Write-Info "Selected mode: $selectedMode"
    Write-Host ""

    # Check admin for native mode prerequisites
    if ($selectedMode -eq 'native') {
        if (-not (Test-Administrator)) {
            Write-Warn "Native mode prerequisites (WinFsp, WinDivert) require Administrator privileges."
            Write-Warn "Run this script as Administrator for full installation."
            Write-Host ""
            Write-Host "Continuing with binary-only installation..."
            Write-Host ""

            # Just install the binary
            if (-not (Install-AgentshNative -Ver $Version)) {
                exit 1
            }
            Install-Envshim -Ver $Version
            Test-Installation
            Write-Instructions -InstalledMode $selectedMode
            return
        }

        # Full native installation
        if (-not (Install-WinFsp)) {
            Write-Warn "WinFsp installation failed. Filesystem interception may not work."
        }

        if (-not (Install-WinDivert)) {
            Write-Warn "WinDivert installation failed. Network interception may not work."
        }

        if (-not (Install-AgentshNative -Ver $Version)) {
            exit 1
        }

        Install-Envshim -Ver $Version
    }
    elseif ($selectedMode -eq 'wsl2') {
        # WSL2 installation
        if (-not (Install-WSL2)) {
            Write-Err "WSL2 installation failed."
            exit 1
        }

        # Also install native wrapper
        if (-not (Install-AgentshNative -Ver $Version)) {
            Write-Warn "Native wrapper installation failed. Use 'wsl' command directly."
        }
        else {
            Install-Envshim -Ver $Version
        }
    }

    Write-Host ""
    Test-Installation
    Write-Instructions -InstalledMode $selectedMode
}

# Run main
Main
