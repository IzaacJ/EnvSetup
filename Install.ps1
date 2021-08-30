param(
    [Parameter(HelpMessage = "Dry run. No actions are executed.")]
    [switch]$Dry = $false,
    [Parameter(HelpMessage = "Test internal functions. No actions are executed.")]
    [switch]$Test = $false,
    [Parameter(HelpMessage = "New Computer name.")]
    [string]$ComputerName = $null,
    [Parameter(HelpMessage = "Skip Computer Name.")]
    [switch]$SkipComputerName = $false,
    [Parameter(HelpMessage = "Skip Power Savings")]
    [switch]$SkipPowerSavings = $false,
    [Parameter(HelpMessage = "Skip `"This PC`" desktop icon.")]
    [switch]$SkipThisPCIcon = $false,
    [Parameter(HelpMessage = "Skip removing UWP apps.")]
    [switch]$SkipRemoveApps = $false,
    [Parameter(HelpMessage = "Skip updating UWP apps.")]
    [switch]$SkipUpdateApps = $false,
    [Parameter(HelpMessage = "Skip enabling Developer Mode.")]
    [switch]$SkipDevMode = $false,
    [Parameter(HelpMessage = "Skip enabling Remote Desktop.")]
    [switch]$SkipRDP = $false,
    [Parameter(HelpMessage = "Skip installing Chocolatey.")]
    [switch]$SkipChoco = $false,
    [Parameter(HelpMessage = "Skip Installing aaps through Chocolatey.")]
    [switch]$SkipChocoApps = $false,
    [Parameter(HelpMessage = "Skip editing Git settings.")]
    [switch]$SkipEditGit = $false,
    [Parameter(HelpMessage = "Skip editing dotnet settings.")]
    [switch]$SkipEditDotNet = $false,
    [Parameter(HelpMessage = "Skip editing File Explorer settings.")]
    [switch]$SkipEditFileExplorer = $false,
    [Parameter(HelpMessage = "Skip editing timezone.")]
    [switch]$SkipEditTimezone = $false,
    [Parameter(HelpMessage = "Skip checking Windows Update.")]
    [switch]$SkipWU = $false
)

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }

$shouldRun = (-not $Dry -and -not $Test)

$Emoji = @{
    "Question" = "`u{2753}"
    "Check"    = "`u{2714}"
    "Cross"    = "`u{274c}"
    "Skipped"  = "`u{2935}"
    "Loading"  = "`u{2699}"
    "Pen"      = "`u{1f58a}"
    "Divider"  = "`u{3030}"
}

$IsRan = @("Init")

function Main() {
    Clear-Host
    Write-Host "`u{1f984} Izaac's Setup Script!"
    Write-Divider
    if ($DebugPreference) {   
        Debugging
    }
    else {
        if ($Dry) {
            Write-Divider
            Write-Host "NOTE THAT THIS IS A DRY RUN! NO ACTIONS WILL BE EXECUTED!"
            Write-Divider
        }

        if ($Test) {
            Testing
        }
        else {
            Edit-ComputerName
            Disable-PowerSavings
            Enable-DesktopThisPC
            Remove-Apps
            Update-Apps
            Enable-DeveloperMode
            Enable-RemoteDesktop
            Install-Chocolatey
            Install-Apps
            Edit-Git
            Edit-DotNet
            Edit-FileExplorer
            Edit-Timezone
            Update-WindowsUpdate

            Completed
        }
    }
}

function Debugging() {     
    Write-Host " `u{1f984} UNICORN POOP `u{1f4a9}"
    Write-Host
    if (-not $Dry -and -not $Test) {
        Write-Header "shouldRun is TRUE" "Question"
        Clear-Header ($shouldRun -eq $true ? "Check" : "Cross")
    }
    elseif (
        ($Dry -and -not $Test) -or
        (-not $Dry -and $Test) -or
        ($Dry -and $Test)) {
        Write-Header "shouldRun is FALSE" "Question"
        Clear-Header ($shouldRun -eq $false ? "Check" : "Cross")
    }
    Write-Host
    Write-Divider
    Write-Host
}

function Testing() {    
    if (-not $Dry -and -not $Test) {
        Write-Header "shouldRun is TRUE" "Question"
        Clear-Header ($shouldRun -eq $true ? "Check" : "Cross")
    }
    elseif (
        ($Dry -and -not $Test) -or
        (-not $Dry -and $Test) -or
        ($Dry -and $Test)) {
        Write-Header "shouldRun is FALSE" "Question"
        Clear-Header ($shouldRun -eq $false ? "Check" : "Cross")
    }

    Write-Header "Neverending..."
    Write-Host

    Write-Header "Neverending pen..." "Pen"
    Write-Host

    Write-Header "Done!"
    Clear-Header

    Write-Header "Done Wave!"
    Clear-Header "Divider"
}

function Confirm-Command($cmdname) {
    return [bool](Get-Command -Name $cmdname -ErrorAction SilentlyContinue)
}
function Write-Header($header, $icon = "Loading") {
    Write-Host " $($Emoji.$icon)  $header" -NoNewline
}
function Clear-Header($icon = "Check") {
    Write-Host "`r $($Emoji.$icon)"
}
function Write-Divider() {
    Write-Host ($Emoji.Divider * ($Host.UI.RawUI.WindowSize.Width / 2))
}

function Edit-ComputerName() {
    Write-Header "Changing Computer Name..."

    if ($SkipComputerName) {
        Clear-Header "Skipped"
        Return
    }
    if ($null -eq $ComputerName -or $ComputerName -eq "") {
        [void][Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic')
        $ComputerName = [Microsoft.VisualBasic.Interaction]::InputBox("New Computer Name:", "Change Computer Name")
        #$ComputerName = Read-Host "Enter New Computer Name"
    }
    Write-Host "   New Computer Name: $ComputerName" -NoNewline
    if ($shouldRun) {
        Rename-Computer -NewName $ComputerName
    }
    $script:IsRan +=  "ComputerName"
    Clear-Header
}

function Disable-PowerSavings() {
    Write-Header "Disable Sleep on AC Power..."

    if ($SkipPowerSavings) {
        Clear-Header "Skipped"
        Return
    }
    if ($shouldRun) {
        Powercfg /Change monitor-timeout-ac 0
        Powercfg /Change standby-timeout-ac 0
    }

    $script:IsRan +=  "PowerSavings"
    Clear-Header
}

function Enable-DesktopThisPC() {
    Write-Header "Add 'This PC' Desktop Icon..."

    if ($SkipThisPCIcon) {
        Clear-Header "Skipped"
        Return
    }
    if ($shouldRun) {
        $thisPCIconRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
        $thisPCRegValname = "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" 
        $item = Get-ItemProperty -Path $thisPCIconRegPath -Name $thisPCRegValname -ErrorAction SilentlyContinue 
        if ($item) { 
            Set-ItemProperty  -Path $thisPCIconRegPath -Name $thisPCRegValname -Value 0  
        } 
        else { 
            New-ItemProperty -Path $thisPCIconRegPath -Name $thisPCRegValname -Value 0 -PropertyType DWORD | Out-Null  
        }
    }

    $script:IsRan +=  "ThisPC"
    Clear-Header
}

function Remove-Apps() {
    Write-Header "Removing unwanted UWP apps..."

    if ($SkipRemoveApps) {
        Clear-Header "Skipped"
        Return
    }
    if ($shouldRun) {
        # To list all appx packages:
        # Get-AppxPackage | Format-Table -Property Name,Version,PackageFullName
        $uwpRubbishApps = @(
            #Unnecessary Windows 10 AppX Apps
            "*Microsoft.BingNews*"
            "*Microsoft.GetHelp*"
            "*Microsoft.Getstarted*"
            "*Microsoft.Messaging*"
            "*Microsoft.Microsoft3DViewer*"
            "*Microsoft.MicrosoftOfficeHub*"
            "*Microsoft.MicrosoftSolitaireCollection*"
            "*Microsoft.NetworkSpeedTest*"
            "*Microsoft.Office.Sway*"
            "*Microsoft.OneConnect*"
            "*Microsoft.People*"
            "*Microsoft.Print3D*"
            "*Microsoft.SkypeApp*"
            "*Microsoft.WindowsAlarms*"
            "*Microsoft.WindowsCamera*"
            "*microsoft.windowscommunicationsapps*"
            "*Microsoft.WindowsFeedbackHub*"
            "*Microsoft.WindowsMaps*"
            "*Microsoft.WindowsSoundRecorder*"
            #"*Microsoft.Xbox.TCUI*"
            #"*Microsoft.XboxApp*"
            #"*Microsoft.XboxGameOverlay*"
            #"*Microsoft.XboxIdentityProvider*"
            #"*Microsoft.XboxSpeechToTextOverlay*"
            "*Microsoft.ZuneMusic*"
            "*Microsoft.ZuneVideo*"

            #Sponsored Windows 10 AppX Apps
            #Add sponsored/featured apps to remove in the "*AppName*" format
            "*EclipseManager*"
            "*ActiproSoftwareLLC*"
            "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
            "*Duolingo-LearnLanguagesforFree*"
            "*PandoraMediaInc*"
            "*CandyCrush*"
            "*Wunderlist*"
            "*Flipboard*"
            "*Twitter*"
            "*Facebook*"
            "*Spotify*"

            #Optional: Typically not removed but you can if you need to for some reason
            #"*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*"
            #"*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*"
            "*Microsoft.BingWeather*"
            "*Microsoft.MSPaint*"
            "*Microsoft.MicrosoftStickyNotes*"
            #"*Microsoft.Windows.Photos*"
            #"*Microsoft.WindowsCalculator*"
            #"*Microsoft.WindowsStore*"

            #Added by Izaac Brånn
            "*Microsoft.Wallet*"
            "*Microsoft.YourPhone*"
        )

        foreach ($App in $uwpRubbishApps) {
            Get-AppxPackage -Name $App | Remove-AppxPackage -ErrorAction SilentlyContinue
            Get-AppxPackage -Name $App -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -Like $App | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        }
    }

    $script:IsRan +=  "RemoveApps"
    Clear-Header
}

function Update-Apps() {
    Write-Header "Starting UWP apps to upgrade..."

    if ($SkipUpdateApps) {
        Clear-Header "Skipped"
        Return
    }
    if ($shouldRun) {
        $namespaceName = "root\cimv2\mdm\dmmap"
        $className = "MDM_EnterpriseModernAppManagement_AppManagement01"
        $wmiObj = Get-WmiObject -Namespace $namespaceName -Class $className
        $result = $wmiObj.UpdateScanMethod()
    }

    $script:IsRan +=  "UpdateApps"
    Clear-Header
}

function Enable-DeveloperMode() {
    Write-Header "Enable Windows 10 Developer Mode..."

    if ($SkipDevMode) {
        Clear-Header "Skipped"
        Return
    }
    if ($shouldRun) {
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /t REG_DWORD /f /v "AllowDevelopmentWithoutDevLicense" /d "1"
    }

    $script:IsRan +=  "DevMode"
    Clear-Header
}

function Enable-RemoteDesktop() {
    Write-Header "Enable Remote Desktop..."

    if ($SkipRDP) {
        Clear-Header "Skipped"
        Return
    }
    if ($shouldRun) {
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\" -Name "fDenyTSConnections" -Value 0
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\" -Name "UserAuthentication" -Value 1
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
    }
    
    $script:IsRan +=  "RDP"
    Clear-Header
}

function Install-Chocolatey() {
    Write-Header "Checking if Chocolatey is installed..."
    
    if ($SkipChoco) {
        Clear-Header "Skipped"
        Return
    }
    if ($shouldRun) {
        $chocoIsInstalled = Confirm-Command -cmdname 'choco'
    }
    Clear-Header
    if ($chocoIsInstalled) {
        Write-Host "    Choco is already installed, skipping installation."
    }
    else {
        Write-Header "Installing Chocolatey for Windows..."
        if ($shouldRun) {
            Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
        }
        Clear-Header
    }
    $script:IsRan +=  "ChocoInstall"
}

function Install-Apps() {
    Write-Header "Installing Applications..."

    $Apps = @(
        "7zip.install",
        "git",
        "microsoft-edge",
        "googlechrome",
        "vlc",
        "dotnetcore-sdk",
        "ffmpeg",
        "wget",
        "openssl.light",
        "vscode",
        "sysinternals",
        "notepadplusplus.install",
        "linqpad",
        "fiddler",
        "postman",
        "nuget.commandline",
        "beyondcompare",
        "filezilla",
        "microsoft-teams.install",
        "motrix",
        "github-desktop",
        "irfanview",
        "nodejs-lts",
        "azure-cli",
        "powershell-core",
        "chocolateygui",
        "obs-studio")

    if ($SkipChocoApps) {
        Clear-Header "Skipped"
        Return
    }
    if ($shouldRun) {
        foreach ($app in $Apps) {
            choco install $app -y
        }
    }

    $script:IsRan +=  "ChocoApps"
    Clear-Header
}

function Edit-Git() {
    Write-Header "Setting up Git for Windows..."

    if ($SkipEditGit) {
        Clear-Header "Skipped"
        Return
    }
    if ($shouldRun) {
        git config --global user.email "edi.wang@outlook.com"
        git config --global user.name "Edi Wang"
        git config --global core.autocrlf true
    }

    $script:IsRan +=  "EditGit"
    Clear-Header
}

function Edit-DotNet() {
    Write-Header "Setting up dotnet for Windows..."

    if ($SkipEditDotNet) {
        Clear-Header "Skipped"
        Return
    }
    if ($shouldRun) {
        [Environment]::SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Development", "Machine")
        [Environment]::SetEnvironmentVariable("DOTNET_PRINT_TELEMETRY_MESSAGE", "false", "Machine")
        [Environment]::SetEnvironmentVariable("DOTNET_CLI_TELEMETRY_OPTOUT", "1", "Machine")
        dotnet tool install --global dotnet-ef
        dotnet tool update --global dotnet-ef
    }

    $script:IsRan +=  "EditDotNet"
    Clear-Header
}

function Edit-FileExplorer() {
    Write-Header "Applying file explorer settings..."

    if ($SkipEditFileExplorer) {
        Clear-Header "Skipped"
        Return
    }
    if ($shouldRun) {
        cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v HideFileExt /t REG_DWORD /d 0 /f"
        cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v AutoCheckSelect /t REG_DWORD /d 0 /f"
        cmd.exe /c "reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v LaunchTo /t REG_DWORD /d 1 /f"
    }

    $script:IsRan +=  "EditFileExplorer"
    Clear-Header
}

function Edit-Timezone() {
    Write-Header "Setting Time zone..."
    
    if ($SkipEditTimezone) {
        Clear-Header "Skipped"
        Return
    }
    if ($shouldRun) {
        Set-TimeZone -Name "China Standard Time"
    }

    $script:IsRan +=  "EditTimezone"
    Clear-Header
}

function WellWhatIsThis() {
    Write-Host "Installing Github.com/microsoft/artifacts-credprovider..." -ForegroundColor Green
    Write-Host "------------------------------------" -ForegroundColor Green
    
    if ($shouldRun) {
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/microsoft/artifacts-credprovider/master/helpers/installcredprovider.ps1'))
    }

    Write-Host "Removing Bluetooth icons..." -ForegroundColor Green
    Write-Host "------------------------------------" -ForegroundColor Green
    
    if ($shouldRun) {
        cmd.exe /c "reg add `"HKCU\Control Panel\Bluetooth`" /v `"Notification Area Icon`" /t REG_DWORD /d 0 /f"
    }
}

function Update-WindowsUpdate() {
    Write-Header "Checking Windows updates..."

    if ($SkipWU) {
        Clear-Header "Skipped"
        Return
    }
    if ($shouldRun) {
        Install-Module -Name PSWindowsUpdate -Force
        Write-Host "Installing updates... (Computer will reboot in minutes...)" -ForegroundColor Green
        Get-WindowsUpdate -AcceptAll -Install -ForceInstall -AutoReboot
    }

    $script:IsRan +=  "WindowsUpdate"
    Clear-Header
}

function Completed() {
    Write-Divider
    $res = @($IsRan | Where-Object -FilterScript { $_ -in @(
                "ComputerName"
                "DevMode"
                "WindowsUpdate"
            ) })
    if ($res.Count -gt 0) {
        Read-Host -Prompt "Setup is done, restart is needed, press [ENTER] to restart computer."
        if ($shouldRun) {
            Restart-Computer
        }
    }
    else {
        Read-Host "Setup is done, and no restart is needed. Press [ENTER] to exit."
        exit
    }
}

Main