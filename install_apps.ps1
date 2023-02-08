Function Start-WinGetUpdate {
    [CmdletBinding()]
    Param (
        [Parameter(
                Mandatory = $false, 
                HelpMessage = 'Decide if you want to skip the WinGet version check, default it set to false'
        )]
        [switch]$SkipVersionCheck = $false
    )

    #Check if script was started as Administrator
    If (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
        Write-Error -Message ('{0} needs admin privileges, exiting now....' -f $MyInvocation.MyCommand)
        break
    }

    #region Static Variables
    # GitHub url for the latest release
    [String]$GitHubUrl = 'https://api.github.com/repos/microsoft/winget-cli/releases/latest'

    # The headers and API version for the GitHub API
    [Hashtable]$GithubHeaders = @{
        'Accept'               = 'application/vnd.github.v3+json'
        'X-GitHub-Api-Version' = '2022-11-28'
    }
    #endregion Static Variables

    #region Collecting some data
    # Checks if WinGet is installed and if it's installed it will collect the current installed version of WinGet
    [version]$CheckWinGet = $(
        Try {
            (Get-AppxPackage -Name Microsoft.DesktopAppInstaller).version
        } Catch {
            $Null
        }
    )

    <## Checking what architecture your running
            # To Install visualcredist use vc_redist.x64.exe /install /quiet /norestart
            # Now we also need to verify that's the latest version and then download and install it if the latest version is not installed
            # When this is added no need to install Microsoft.VCLibs as it's included in the VisualCRedist
    # Don't have the time for it now but this will be added later#>

    $Architecture = $(Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty SystemType)
    Switch ($Architecture) {
        'x64-based PC' {
            [string]$VisualCRedistUrl = 'https://aka.ms/vs/17/release/vc_redist.x64.exe'
            [string]$VCLibsUrl        = 'https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx'
            [string]$Arch             = 'x64'
        }
        'ARM64-based PC' {
            [string]$VisualCRedistUrl = 'https://aka.ms/vs/17/release/vc_redist.arm64.exe'
            [string]$VCLibsUrl        = 'https://aka.ms/Microsoft.VCLibs.arm64.14.00.Desktop.appx'
            [string]$Arch             = 'arm64'
        }
        'x86-based PC' {
            [string]$VisualCRedistUrl = 'https://aka.ms/vs/17/release/vc_redist.x86.exe'
            [string]$VCLibsUrl        = 'https://aka.ms/Microsoft.VCLibs.x86.14.00.Desktop.appx'
            [string]$Arch             = 'x86'
        }
        default {
            Write-Error -Message 'Your running a unsupported architecture, exiting now...'
            break
        }
    }

    # Checking if Microsoft.VCLibs is installed
    $CheckVCLibs = $(
        Get-AppxPackage -Name 'Microsoft.VCLibs.140.00' -AllUsers | 
        Where-Object {$_.Architecture -eq $Arch}
    )
    $VCLibsOutFile = ('{0}\Microsoft.VCLibs.140.00.{1}.appx' -f $env:TEMP, ($Arch))

    # Checking if it's a newer version of WinGet to download and install if the user has used the -SkipVersionCheck switch.
    # If WinGet is not installed this section will still run to install WinGet.
    If ($SkipVersionCheck -eq $false -or $null -eq $CheckWinGet) {
        If ($null -eq $CheckWinGet) {
            Write-Output -InputObject =, 'WinGet is not installed, downloading and installing WinGet...'
        } Else {
            Write-Output -InputObject =, "Checking if it's any newer version of WinGet to download and install..."
        }

        # Collecting information from GitHub regarding latest version of WinGet
        Try {
            If ($PSVersionTable.PSVersion.Major -ge 7) {
                [Object]$GithubInfoRestData = Invoke-RestMethod -Uri $GitHubUrl -Method Get -Headers $GithubHeaders -TimeoutSec 10 -HttpVersion 3.0 | Select-Object -Property assets, tag_name
            } Else {
                [Object]$GithubInfoRestData = Invoke-RestMethod -Uri $GitHubUrl -Method Get -Headers $GithubHeaders -TimeoutSec 10 | Select-Object -Property assets, tag_name
            }
            [string]$latestVersion = $GithubInfoRestData.tag_name.Substring(1)

            [Object]$GitHubInfo = [PSCustomObject]@{
                Tag         = $latestVersion
                DownloadUrl = $GithubInfoRestData.assets | where-object { $_.name -like '*.msixbundle' } | Select-Object -ExpandProperty browser_download_url
                OutFile     = ('{0}\WinGet_{1}.msixbundle' -f $env:TEMP, ($latestVersion))
            }
        } Catch {
            Write-Error -Message @"
    "Message: "$($_.Exception.Message)`n
    "Error Line: "$($_.InvocationInfo.Line)`n
"@
            break
        }

        # Checking if the installed version of WinGet are the same as the latest version of WinGet
        If ([Version]::new($CheckWinGet.Major,$CheckWinGet.Minor,$CheckWinGet.Build) -le $GitHubInfo.Tag) {
            Write-Output -InputObject ('WinGet has a newer version {0}, downloading and installing it...' -f $GitHubInfo.Tag)
            Invoke-WebRequest -UseBasicParsing -Uri $GitHubInfo.DownloadUrl -OutFile $GitHubInfo.OutFile

            Write-Output -InputObject ('Installing version {0} of WinGet...' -f $GitHubInfo.Tag)
            Add-AppxPackage -Path $($GitHubInfo.OutFile)
        } Else {
            Write-OutPut -InputObject ('Your already on the latest version of WinGet {0}, no need to update.' -f ($CheckWinGet))
        }
    }
    #endregion Collecting some data

    #region Installs
    # If Microsoft.VCLibs is not installed it will download and install it
    If ($null -eq $CheckVCLibs) {
        Try {
            Write-Output -InputObject 'Microsoft.VCLibs is not installed, downloading and installing it now...'
            Invoke-WebRequest -UseBasicParsing -Uri $VCLibsUrl -OutFile $VCLibsOutFile

            Add-AppxPackage -Path $VCLibsOutFile
        } Catch {
            Write-Error -Message 'Something went wrong when trying to install Microsoft.VCLibs...'
            Write-Error -Message @"
    "Message: "$($_.Exception.Message)`n
    "Error Line: "$($_.InvocationInfo.Line)`n
"@
            break
        }
    }

    # Starts to check if you have any softwares that needs to be updated
    Write-OutPut -InputObject 'Checks if any software needs to be updated'
    Try {
        WinGet.exe upgrade --all --silent --force --accept-source-agreements --disable-interactivity --include-unknown
        Write-Output -InputObject 'Everything is now completed, you can close this window'
    } Catch {
        Write-Error -Message @"
    "Message: "$($_.Exception.Message)`n
    "Error Line: "$($_.InvocationInfo.Line)`n
"@
    }
    #endregion Installs
}


Function Install-Apps {
    <#
            .SYNOPSIS
            Installs Programs, Modules, Features and settings using Winget and PowerShell
            .DESCRIPTION
            Installs/Configures all options from the .json file
            .PARAMETER All
            Install all Programs, Modules, Features and Settings
            .PARAMETER Apps
            Install all Software
            .PARAMETER Features
            Install all Windows Features
            .PARAMETER MicrosftVCRuntime
            Install all Microsoft VC++ Runtimes
            .PARAMETER PowerShellCommands
            Execute all PowerShell commands like Update-Help
            .PARAMETER PowerShellModules
            Install all PowerShell Modules
            .PARAMETER PowerShellModulesUpdate
            Update all installed PowerShell Modules to the latest version
            .PARAMETER PowerShellProfile
            Update the PowerShell Profile
            .PARAMETER RSATTools
            Install the Windows Remote System Administration Tools
            .PARAMETER $SCCMTools
            Install the System Center Configuration Manager tools like CMTrace
            .PARAMETER SysInternalsSuite
            Install the Windows Remote System Administration Tools
            .PARAMETER IntuneWinAppUtil
            Install the IntuneWinAppUtil in c:\windows\system32
            .INPUTS
            Defaults to -All if no other Parameters are specified
            .OUTPUTS
            Screen output and TransAction log which is available in %Temp%\Install.log
            .EXAMPLE
            PS> Install_Apps.ps1 -Apps
            Installs all Applications
            .EXAMPLE
            PS> Install_Apps.ps1 -SCCMTools -PowerShellModule
            Installs the System Center Configuration Manager Tools and installs all PowerShell Modules
            .LINK
            None
    #>

    #Parameters
    [CmdletBinding(DefaultParameterSetName = 'All')]
    Param (
        [Parameter(
                Mandatory = $False, 
                HelpMessage = 'Install all Software, Modules, Features and Settings', 
                ParameterSetName = 'All'
        )]
        [Switch]$All,
        [Parameter(
                Mandatory = $false, 
                HelpMessage = 'Install all Software', 
                ParameterSetName = 'Optional'
        )]
        [Switch]$Apps,
        [Parameter(
                Mandatory = $false, 
                HelpMessage = 'Install all Windows Features', 
                ParameterSetName = 'Optional'
        )]
        [Switch]$Features,
        [Parameter(
                Mandatory = $false, 
                HelpMessage = 'Install all Microsoft VC++ Runtimes', 
                ParameterSetName = 'Optional'
        )]
        [Switch]$MicrosftVCRuntime,
        [Parameter(
                Mandatory = $false, 
                HelpMessage = 'Execute all PowerShell commands like Update-Help', 
                ParameterSetName = 'Optional'
        )]
        [Switch]$PowerShellCommands,
        [Parameter(
                Mandatory = $false, 
                HelpMessage = 'Install all PowerShell Modules', 
                ParameterSetName = 'Optional'
        )]
        [Switch]$PowerShellModules,
        [Parameter(
                Mandatory = $false, 
                HelpMessage = 'Update all installed PowerShell Modules to the latest version', 
                ParameterSetName = 'Optional'
        )]
        [Switch]$PowerShellModulesUpdate,
        [Parameter(
                Mandatory = $false, 
                HelpMessage = 'Update the PowerShell Profile', 
                ParameterSetName = 'Optional'
        )]
        [Switch]$PowerShellProfile,
        [Parameter(
                Mandatory = $false, 
                HelpMessage = 'Install the Windows Remote System Administration Tools', 
                ParameterSetName = 'Optional'
        )]
        [Switch]$RSATTools,
        [Parameter(
                Mandatory = $false, 
                HelpMessage = 'Install the System Center Configuration Manager tools like CMTrace', 
                ParameterSetName = 'Optional'
        )]
        [Switch]$SCCMTools,
        [Parameter(
                Mandatory = $false, 
                HelpMessage = 'Install all SysInternals Suite tools and add them to the system path', 
                ParameterSetName = 'Optional'
        )]
        [Switch]$SysInternalsSuite,
        [Parameter(
                Mandatory = $false, 
                HelpMessage = 'Install the IntuneWinAppUtil to c:\windows\system32', 
                ParameterSetName = 'Optional'
        )]
        [Switch]$IntuneWinAppUtil
    )
    #Requires -RunAsAdministrator

    #Start Transcript logging in Temp folder
    Start-Transcript -Path $ENV:TEMP\install.log

    #region Variables
    $SC = 'SilentlyContinue'
    $Gr = @{ForegroundColor = 'Green'}
    $Ye = @{ForegroundColor = 'Yellow'}
    #endregion Variables

    If ($PSCmdlet.ParameterSetName -eq 'All') {
        Write-Host ('No parameter was specified and using all options') @Gr
        $All = $True
    }

    #Set-Executionpolicy and no prompting
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Force:$True -Confirm:$false -ErrorAction $SC
    Set-Variable -Name 'ConfirmPreference' -Value 'None' -Scope Global

    #Change invoke-webrequest progress bar to hidden for faster downloads
    $ProgressPreference = $SC

    #Import list of apps, features and modules that can be installed using json file
    $json = Get-Content -Path "$($PSScriptRoot)\Install_apps.json" | ConvertFrom-Json

    ### WINGET ### Check if Winget is installed, if not install it by installing VCLibs (Prerequisite) followed by Winget itself
    If ($Apps -or $MicrosftVCRuntime -or $All) {
        If (-not (Get-AppxPackage -Name Microsoft.Winget.Source)) {
            Write-Host ('Winget was not found and installing now') @Ye
            #Invoke-Webrequest -uri https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx -Outfile $ENV:TEMP\Microsoft.VCLibs.x64.14.00.Desktop.appx
            #Invoke-Webrequest -uri https://aka.ms/getwinget -Outfile $ENV:TEMP\winget.msixbundle    
            #Add-AppxPackage -Path $ENV:TEMP\Microsoft.VCLibs.x64.14.00.Desktop.appx -ErrorAction $SC
            #Add-AppxPackage -Path $ENV:TEMP\winget.msixbundle -ErrorAction $SC
            Start-WinGetUpdate
        }
    }

    If ($MicrosftVCRuntime -or $All) {
        #Install Microsoft Visual C++ Runtimes using WinGet
        Write-Host ('Installing Microsoft Visual C++ Runtime versions but skipping install if already present') @Gr
        $CurrentVC = Get-WmiObject -Class Win32_Product -Filter "Name LIKE '%Visual C++%'" -ErrorAction $SC | Select-Object -Property Name
        Foreach ($App in $json.MicrosftVCRuntime) {
            Write-Host ('Checking if {0} is already installed...' -f $App)
            If (-not ($CurrentVC | Select-String -Pattern $App.split('+')[2].SubString(0, 4) | Select-String -Pattern $App.split('-')[1])) {
                Write-Host ('{0} was not found and installing now' -f $App) @Ye
                winget.exe install $App --silent --force --source winget --accept-package-agreements --accept-source-agreements
            }
        }
    }

    #region Apps
    If ($Apps -or $All) {
        #Install applications using WinGet
        Write-Host ('Installing Applications but skipping install if already present') @Gr
        Foreach ($App in $json.Apps) {
            Write-Host ('Checking if {0} is already installed...' -f $App)
            winget.exe list --id $App --accept-source-agreements | Out-Null
            If ($LASTEXITCODE -eq '-1978335212') {
                Write-Host ('{0} was not found and installing now' -f $App.Split('.')[1]) @Ye
                winget.exe install $App --silent --force --source winget --accept-package-agreements --accept-source-agreements
                Foreach ($Application in $json.ProcessesToKill) {
                    Get-Process -Name $Application -ErrorAction $SC | Stop-Process -Force:$True -Confirm:$false
                }
            } 
        }
        #Clean-up downloaded Winget Packages
        Remove-Item -Path $ENV:TEMP\Winget -Recurse -Force:$True -ErrorAction $SC

        #Cleanup shortcuts from installed applications
        ForEach ($File in $json.filestoclean) {
            Write-Host ('Cleaning {0} from personal ad public Windows Desktop' -f $File) @Gr
            $UserDesktop = ([Environment]::GetFolderPath('Desktop'))
            Get-ChildItem -Path C:\Users\public\Desktop\$File -ErrorAction $SC         | Where-Object LastWriteDate -LE ((Get-Date).AddHours(-1)) | Remove-Item -Force:$True
            Get-ChildItem -Path $UserDesktop\$File -ErrorAction $SC                    | Where-Object LastWriteDate -LE ((Get-Date).AddHours(-1)) | Remove-Item -Force:$True
            Get-ChildItem -Path C:\Users\public\Desktop\$File -Hidden -ErrorAction $SC | Where-Object LastWriteDate -LE ((Get-Date).AddHours(-1)) | Remove-Item -Force:$True
            Get-ChildItem -Path $UserDesktop\$File -Hidden -ErrorAction $SC            | Where-Object LastWriteDate -LE ((Get-Date).AddHours(-1)) | Remove-Item -Force:$True
        }
    }

    ### SCCMTools (for CMTrace)
    If ($SCCMTools -or $All) {
        #Download and install System Center 2012 R2 Configuration Manager Toolkit for CMTRACE tool
        Write-Host ('Checking if System Center 2012 R2 Configuration Manager Toolkit is already installed') @Gr
        If (!(Test-Path -Path 'C:\Program Files (x86)\ConfigMgr 2012 Toolkit R2')) {
            Write-Host ('SCCM 2012 R2 Toolkit was not found and installing now') @Ye
            Invoke-Webrequest -uri https://download.microsoft.com/download/5/0/8/508918E1-3627-4383-B7D8-AA07B3490D21/ConfigMgrTools.msi -UseBasicParsing -Outfile $ENV:TEMP\ConfigMgrTools.msi
            msiexec.exe /i $ENV:TEMP\ConfigMgrTools.msi /qn
        }
    }

    ### SysInternalsSuite
    If ($SysInternalsSuite -or $All) {
        #Download and extract SysInternals Suite and add to system path
        Write-Host ('Checking if SysInternals Suite is present') @Gr
        If (!(Test-Path -Path 'C:\Program Files (x86)\SysInterals Suite')) {
            Write-Host ('SysInternalsSuite was not found and installing now') @Ye
            Invoke-Webrequest -uri https://download.sysinternals.com/files/SysinternalsSuite.zip -Outfile $ENV:TEMP\SysInternalsSuite.zip
            Expand-Archive -LiteralPath $ENV:TEMP\SysInternalsSuite.zip -DestinationPath 'C:\Program Files (x86)\SysInterals Suite'
            $OldPath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
            $NewPath = $OldPath + ';C:\Program Files (x86)\SysInterals Suite\'
            Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $NewPath
        }
    }

    ### IntuneAppUtil
    If ($IntuneWinAppUtil -or $All) {
        #Download IntuneWinAppUtil to c:\windows\system32
        Write-Host ('Checking if IntuneWinAppUtil Suite is present') @Gr
        If (!(Test-Path -Path 'C:\Windows\System32\IntuneWinAppUtil.exe')) {
            Write-Host ('IntuneWinAppUtil was not found and installing now') @Ye
            Invoke-Webrequest -uri https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool/raw/master/IntuneWinAppUtil.exe -Outfile c:\windows\system32\intunewinapputil.exe
        }
    }
    #endregion Apps
    
    #region Features
    If ($Features -or $All) {
        #Install Features
        Write-Host ('Installing Features but skipping install if already present') @Gr
        Foreach ($Feature in $json.Features) {
            Write-Host ('Checking if {0} is already installed...' -f $Feature)
            If ((Get-WindowsOptionalFeature -Online -FeatureName:$Feature).State -ne 'Enabled') {
                Write-Host ('{0} was not found and installing now' -f $Feature) @Ye
                Enable-WindowsOptionalFeature -Online -FeatureName:$Feature -NoRestart:$True -ErrorAction $SC | Out-Null
            }
        }
    }
    #endregion Features

    #region PowerShell Modules
    If ($PowerShellModules -or $All) {
        #Install PowerShell Modules
        Write-Host ('Installing Modules but skipping install if already present') @Gr
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

        Foreach ($Module in $json.PowerShellModules) {
            Write-Host ('Checking if the {0} is already installed...' -f $Module)
            If (!(Get-Module -Name $Module -ListAvailable)) {
                Write-Host ('{0} PowerShell Module was not found and installing now' -f $Module) @Ye
                Install-Module -Name $Module -Scope AllUsers -Force:$True -AllowClobber:$True
            }
        }
    }
    #endregion PowerShell Modules

    #region RSAT
    If ($RSATTools -or $All) {
        #Install selected RSAT Tools
        Write-Host ('Installing RSAT components but skipping install if already present') @Gr
        Foreach ($Tool in $json.RSATTools) {
            Write-Host ('Checking if {0} is already installed...' -f $Tool.Split('~')[0])
            If ((Get-WindowsCapability -Online -Name:$Tool).State -ne 'Installed') {
                Write-Host ('{0} was not found and installing now' -f $Tool.Split('~')[0]) @Ye
                DISM.exe /Online /add-capability /CapabilityName:$Tool /NoRestart /Quiet | Out-Null
            }
        }
    }
    #endregion RSAT

    #region PowerShell
    If ($PowerShellProfile -or $All) {
        #Add settings to PowerShell Profile (Creating Profile if not exist)
        Write-Host ('Adding settings to PowerShell Profile but skipping setting if already present') @Gr
        Foreach ($Setting in $json.PowerShellProfile) {
            Write-Host ('Checking if {0} is already added...' -f $Setting)
            If (-not (Test-Path -Path $profile)) {
                New-Item -Path $profile -ItemType:File -Force:$True | out-null
            }
            If (-not (Get-Content -Path $profile | Select-String -Pattern $Setting -SimpleMatch)) {
                Write-Host ('{0} was not found and adding now' -f $Setting) @Ye
                Add-Content -Path $profile -Value "`n$($Setting)"
            }
        }
    }

    If ($PowerShellModulesUpdate -or $All) {
        #Update PowerShell Modules if needed
        Write-Host ('Checking for older versions of PowerShell Modules and removing those if present') @Gr
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted

        Foreach ($Module in Get-InstalledModule | Select-Object -Property Name) {
            Write-Host ('Checking for older versions of the {0} PowerShell Module' -f $Module.Name)
            $AllVersions       = Get-InstalledModule -Name $Module.Name -AllVersions -ErrorAction $SC
            $AllVersions       = $AllVersions | Sort-Object -Property PublishedDate -Descending
            $MostRecentVersion = $AllVersions[0].Version
            If ($AllVersions.Count -gt 1) {
                ForEach ($Version in $AllVersions) {
                    If ($Version.Version -ne $MostRecentVersion) {
                        Write-Host ('Uninstalling previous version {0} of Module {1}' -f $Version.Version, $Module.Name) @Ye
                        Uninstall-Module -Name $Module.Name -RequiredVersion $Version.Version -Force:$True
                    }
                }
            }
        }
    }

    If ($PowerShellCommands -or $All) {
        #Run PowerShell commandline options
        Write-Host ('Running Commandline options and this could take a while') @Gr
        Foreach ($Command in $json.PowerShellCommands) {
            Write-Host ('Running {0}' -f $Command) @Ye
            Powershell.exe -Executionpolicy Bypass -Command $Command
        }
    }
    #endregion PowerShell

    #Stop Transcript logging
    Stop-Transcript
}
