#region installs
# core tech choco installs
$script:chocoCoreTech          = @(
    # 'vscode'  # visual studio code
    # 'python'  # python
    # '7zip'    # file archiver with good compression ratio
    # 'git'     # git for windows
    # 'firefox' # firefox browser
    'googlechrome'
    'microsoft-office-deployment'
)

# core tech winget installs
$script:wingetCoreTech         = @(
    'Git.Git'                    # git for windows
    'GitHub.cli'
    'GitHub.GitHubDesktop'
    #'Microsoft.VisualStudioCode' # visual studio code
    'Python.Python.3'            # python
    '7zip.7zip'                  # file archiver with good compression ratio
    'Mozilla.Firefox'            # firefox browser
    'Microsoft.PowerShell'       # powershell
    'JanDeDobbeleer.OhMyPosh'    # oh my posh
    'Microsoft.DeploymentToolkit'
    'Microsoft.dotnetRuntime'
    'Microsoft.dotnetRuntime.5'
    'Microsoft.EdgeWebView2Runtime'
    'Microsoft.Office'
    'Microsoft.OneDrive'
    'Microsoft.WindowsTerminal'
    'Microsoft.Teams'
)

# basic choco installs
$script:chocoSoftwareInstalls  = @(
    # 'ytmdesktop'      #https://github.com/ytmdesktop/ytmdesktop/issues/563
    'rsat'
    'filezilla'
    'rdm'
    'password-hub'
    'putty.install'
    'greenshot'
    'vlc'
    'sysinternals'
    # 'spotify'         # spotify
    # 'cacher'          # code snippet organizer
    # 'winscp'          # Open source free SFTP client, SCP client, FTPS client and FTP client
    # 'telegram'        # Cloud-based synchronized messaging app with a focus on speed and security
    # 'grepwin'         # powerful and fast search tool using regular expressions.
    # 'notepadplusplus' # source code editor and Notepad replacement
    # 'googlechrome'    # chrome browser
    # 'foxitreader'     # pdf client
    # 'paint.net'       # photo editor
)

# basic winget installs
$script:wingetSoftwareInstalls = @(
    'Adobe.Acrobat.Reader.64-bit'
    'WinSCP.WinSCP'                    # Open source free SFTP client, SCP client, FTPS client and FTP client
    'StefansTools.grepWin'             # powerful and fast search tool using regular expressions.
    'Notepad++.Notepad++'              # source code editor and Notepad replacement
    'Google.Chrome'                    # chrome browser
    'WinDirStat.WinDirStat'            # disk usage analyzer
    'Devolutions.RemoteDesktopManager' # Devolutions Remote Desktop Manager
    'Famatech.AdvancedIPScanner'
    'Greenshot.Greenshot'
    'AntibodySoftware.WizTree'
    'Microsoft.PowerToys'
    'Microsoft.RemoteDesktopClient'
    'Microsoft.WindowsAdminCenter'
    'mRemoteNG.mRemoteNG'
    'OpenJS.NodeJS'
    'Obsidian.Obsidian'
    'Ookla.Speedtest'
    'PuTTY.PuTTY'
    'Rufus.Rufus'
    'RevoUninstaller.RevoUninstaller'
    'TimKosse.FileZilla.Client'
    'WinSCP.WinSCP'
    'VideoLAN.VLC'
    # 'Spotify.Spotify'                 # spotify
    # 'PenguinLabs.Cacher'              # code snippet organizer
    # 'Telegram.TelegramDesktop'        # Cloud-based synchronized messaging app with a focus on speed and security
    # 'Foxit.FoxitReader'               # pdf client
    # 'JGraph.Draw'                     # draw.io
    # 'NickeManarin.ScreenToGif'        # screen recorder to gif
    # 'Canonical.Ubuntu'
    # 'Cisco AnyConnect Secure Mobility Client'
    # 'Cisco.CiscoWebexMeetings'
    # 'Insecure.Nmap'
)

# choco azure installs
$script:chocoInstallsAzure     = @(
    # 'azure-cli'                    # cli for azure
    # 'AzureStorageExplorer'         # the azure storage explorer
    # 'azure-functions-core-tools-3' # core tool set for local dev of azure functions
    # 'azcopy10'                     # azure copy tool
    # 'bicep'                        # bicep cli
)

# winget azure installs
$script:wingetInstallsAzure    = @(
    'Microsoft.AzureCLI'                # cli for azure
    # 'Microsoft.AzureStorageExplorer'    # the azure storage explorer
    'Microsoft.AzureFunctionsCoreTools' # core tool set for local dev of azure functions
    # 'Microsoft.AzureStorageEmulator'
    # 'Microsoft.Bicep'                   # bicep cli
)

# choco aws installs
$script:chocoInstallsAWS       = @(
    # 'aws-vault' # A tool to securely store and access AWS credentials in a development environment
    # 'awscli'    # aws cli
)

# winget aws installs
$script:wingetInstallsAWS      = @(
    # 'Amazon.AWSCLI'               # aws cli
    # 'Amazon.SAM-CLI'              # aws sam cli
    # 'Amazon.SessionManagerPlugin' # aws session manager plugin
)

# winget aws cdk typescript installs
$script:wingetAWSCDKTypeScript = @(
    # 'Amazon.AWSCLI' # aws cli
    # 'OpenJS.NodeJS' # nodejs
)

# a list of useful Azure PowerShell modules
$script:azureModules           = @(
    'Az'               # standard Azure modules
    'AzureDevOps'      # interact with the Azure DevOps REST API.
    'AzurePipelinesPS' # makes interfacing with Azure Pipelines a bit easier.
    'CosmosDB'         # provides cmdlets for working with Azure Cosmos DB.
    # 'PSArm'            # experimental DSL for ARM templates (based on bicep)
    # 'Bicep'            # enable the features provided by the Bicep CLI in PowerShell.
    'Azure'
    'AzureAD'
    'ExchangeOnlineManagement'
    'Microsoft.Graph'
    'Microsoft.Online.SharePoint.PowerShell'
    'Microsoft.PowerShell.SecretManagement'
    'Microsoft.PowerShell.SecretStore'
    'MSOnline'
    'Optimized.Mga'
)

# a list of useful AWS PowerShell modules
$script:awsModules             = @(
    # 'AWS.Tools.Common'
    # 'AWS.Tools.CloudWatch'
    # 'AWS.Tools.CostExplorer'
    # 'AWS.Tools.S3'
    # 'AWS.Tools.SecretsManager'
    # 'AWS.Tools.SecurityToken'
    # 'AWS.Tools.SQS'
    # 'AWSLambdaPSCore'
)

# a list of useful Core PowerShell modules
$script:modules                = @(
    @{ModuleName = 'Catesta';                 Version = 'Latest'}
    @{ModuleName = 'Convert';                 Version = 'Latest'}
    @{ModuleName = 'DnsClient-PS';            Version = 'Latest'}
    @{ModuleName = 'InvokeBuild';             Version = 'Latest'}
    @{ModuleName = 'Pester';                  Version = 'Latest'}
    @{ModuleName = 'platyPS';                 Version = '0.12.0'}
    @{ModuleName = 'posh-git';                Version = 'Latest'}
    @{ModuleName = 'PoshGram';                Version = 'Latest'}
    @{ModuleName = 'PSReadline';              Version = 'Latest'}
    @{ModuleName = 'PSScriptAnalyzer';        Version = 'Latest'}
    @{ModuleName = 'PSWordCloud';             Version = 'Latest'}
    @{ModuleName = 'Terminal-Icons';          Version = 'Latest'}
    @{ModuleName = 'ADEssentials';            Version = 'Latest'}
    @{ModuleName = 'Connectimo';              Version = 'Latest'}
    @{ModuleName = 'DSInternals';             Version = 'Latest'}
    @{ModuleName = 'GPOZaurr';                Version = 'Latest'}
    @{ModuleName = 'ImportExcel';             Version = 'Latest'}
    @{ModuleName = 'PSEventViewer';           Version = 'Latest'}
    @{ModuleName = 'PSReadline';              Version = 'Latest'}
    @{ModuleName = 'PSScriptAnalyzer';        Version = 'Latest'}
    @{ModuleName = 'PSSharedGoods';           Version = 'Latest'}
    @{ModuleName = 'PSSQLite';                Version = 'Latest'}
    @{ModuleName = 'PSWinDocumentation';      Version = 'Latest'}
    @{ModuleName = 'PSWinDocumentation.AD';   Version = 'Latest'}
    @{ModuleName = 'PSWinDocumentation.AWS';  Version = 'Latest'}
    @{ModuleName = 'PSWinDocumentation.DNS';  Version = 'Latest'}
    @{ModuleName = 'PSWinDocumentation.O365'; Version = 'Latest'}
    @{ModuleName = 'PSWindowsUpdate';         Version = 'Latest'}
    @{ModuleName = 'PSWriteColor';            Version = 'Latest'}
    @{ModuleName = 'PSWriteExcel';            Version = 'Latest'}
    @{ModuleName = 'PSWriteHTML';             Version = 'Latest'}
    @{ModuleName = 'Testimo';                 Version = 'Latest'}
)

# python VSCode extensions
$script:vscodeExtensionsPython = @(
    # 'almenon.arepl'             #AREPL automatically evaluates python code in real-time as you type.
    # 'formulahendry.code-runner' #Run code snippet or code file for multiple languages:
    # 'ms-python.python'          #python
    # 'ms-python.vscode-pylance'  #Fast, feature-rich language support for Python
    # 'ms-toolsai.jupyter'        #basic notebook support for language kernels
    # 'njpwerner.autodocstring'   #quickly generate docstrings for python functions.
)

# aws VSCode extensions
$script:vscodeExtensionsAWS    = @(
    # 'amazonwebservices.aws-toolkit-vscode'    #AWS Toolkit is an extension for Visual Studio Code that enables you to interact with Amazon Web Services (AWS).
    # 'aws-scripting-guy.cform'                 #CloudFormation support
    # 'DanielThielking.aws-cloudformation-yaml' #This extension adds some snippets to YAML based files for AWS CloudFormation.
    # 'kddejong.vscode-cfn-lint'                #VS Code CloudFormation Linter uses cfn-lint to lint your CloudFormation templates.
)

# aws cdktf VSCode extensions
$script:vscodeExtensionsAWSCDK = @(
    # 'dbaeumer.vscode-eslint' #Integrates ESLint JavaScript into VS Code.
)

# azure VSCode extensions
$script:vscodeExtensionsAzure  = @(
    # 'damienaicheh.azure-devops-snippets'       #Azure DevOps snippets
    # 'ms-dotnettools.vscode-dotnet-runtime'     #.NET Install Tool for Extension Authors - dependency
    # 'ms-azure-devops.azure-pipelines'          #Syntax highlighting, IntelliSense, and more for Azure Pipelines YAML
    # 'ms-azuretools.vscode-azureresourcegroups' #View and manage Azure resources directly from VS Code.
    # 'ms-azuretools.vscode-azurefunctions'      #Use the Azure Functions extension to quickly create, debug, manage, and deploy serverless apps directly from VS Code.
    # 'msazurermtools.azurerm-vscode-tools'      #The Azure Resource Manager (ARM) Tools for Visual Studio Code
    # 'ms-azuretools.vscode-bicep'               #Bicep language support
    # 'ms-vscode.azure-account'                  #The Azure Account extension provides a single Azure sign-in
    # 'ms-vscode.azurecli'                       #Scrapbooks for developing and running commands with the Azure CLI.
)

# core VSCode extensions
$script:vscodeExtensions       = @(
    # 'aaron-bond.better-comments'            #The Better Comments extension will help you create more human-friendly comments in your code.
    # 'alexey-strakh.stackoverflow-search'    #search stackoverflow direct from vscode
    # 'DavidAnson.vscode-markdownlint'        #Markdown/CommonMark linting and style checking
    # 'DotJoshJohnson.xml'                    #xml tools
    # 'eamodio.gitlens'                       #GitLens supercharges the Git capabilities
    # 'emilast.LogFileHighlighter'            #Adds color highlighting to log files
    # # 'GitHub.copilot'                      #AI pair programmer from GitHub
    # 'hediet.vscode-drawio'                  #This unofficial extension integrates Draw.io
    # 'mechatroner.rainbow-csv'               #Highlight columns in comma (.csv), tab (.tsv), semicolon and pipe
    # # 'ms-dotnettools.csharp'               #Welcome to the C# extension for Visual Studio Code!
    # 'ms-vscode.powershell'                  #PowerShell!
    # 'nobuhito.printcode'                    #adds print to VSCode
    # 'oderwat.indent-rainbow'                #make indentation more readable
    # 'PKief.material-icon-theme'             #material icon theme for icons
    # 'redhat.vscode-yaml'                    #Provides comprehensive YAML Language support - dependency
    # 'ritwickdey.LiveServer'                 #go live
    # 'ryanluker.vscode-coverage-gutters'     #codecoverage indicator
    # 'ryu1kn.partial-diff'                   #You can compare (diff) text selections within a file, across different files, or to the clipboard
    # 'shd101wyy.markdown-preview-enhanced'   #Markdown Preview Enhanced
    # 'SirTori.indenticator'                  #Visually highlights the current indent depth.
    # 'streetsidesoftware.code-spell-checker' #A basic spell checker that works well with camelCase code.
    # 'tuxtina.json2yaml'                     #Uses js-yaml to do the actual conversion json to yaml and vice-versa.
    # 'Tyriar.shell-launcher'                 #Easily launch multiple shell configurations in the terminal.
    # 'usernamehw.errorlens'                  #ErrorLens turbo-charges language diagnostic features by making diagnostics stand out more prominently
    # 'vangware.dark-plus-material'           #theme
    # 'vincentkos.snippet-creator'            #helps to automate snippet creation
    # 'wmontalvo.vsc-jsonsnippets'            #Makes writing key-value code (like JSON) fluent, with a simple set of snippets
    # 'yzhang.markdown-all-in-one'            #All you need for Markdown
)
#endregion

#region paths
$script:tempPath                      = -join ($env:TEMP, '\ws_setup')
#$script:vscodeSettingsPath            = -join ($env:APPDATA, '\Code\User')
#$script:vscodeSnippetsPath            = -join ($env:APPDATA, '\Code\User\snippets')
$script:windowsTerminalSettingsPath   = -join ($env:LOCALAPPDATA, '\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState')
$script:windowsTerminalBackgroundPath = -join ($env:LOCALAPPDATA, '\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\RoamingState')
$script:profilePath                   = -join ($env:USERPROFILE, '\Documents\PowerShell')
$script:ohmyposhSettings              = $env:USERPROFILE
#endregion

#region content locations
#$gistUrl = "https://api.github.com/gists/a208d2bd924691bae7ec7904cab0bd8e"
$gistUrl = "https://api.github.com/gists/71d272d879f5aa0b93006c08f7b0940f"

#$script:psProfile                    = 'https://api.github.com/gists/2b4d8e590a7fa41f32a76013df664020'
$script:psProfile                    = 'https://api.github.com/gists/4f04ee3ff54ae92194bd22d3b9bcc576'
#$script:vsCodeSettingsJSON           = 'https://api.github.com/gists/d0997337224510743e2072dc5c343363' #settings.json
#$script:vsCodePythonSnippetsJSON     = 'https://api.github.com/gists/042b2b47e7a94c1a5a2bc79439a4fb81' #vscode_python_snippets.json
#$script:vsCodePowerShellSnippetsJSON = 'https://api.github.com/gists/9ec91ab0ca26f96cf7ca4842053fa8fb' #vscode_ps_snippets.json
#$script:windowsTerminalSettingsJSON  = 'https://api.github.com/gists/df416a8df55c6c4009c9dcd337d4c8cf' #settings.json
$script:windowsTerminalSettingsJSON  = 'https://api.github.com/gists/05084664100121d1b9f8e282c31d6d56'
#$script:ohmyposhJSON                 = 'https://api.github.com/gists/da99b8255a8ca720430d188f649a9bd7' #.work.omp.json
$script:ohmyposhJSON                 = 'https://api.github.com/gists/71d272d879f5aa0b93006c08f7b0940f'
$script:setupFiles                   = 'https://tt-ws.s3-us-west-2.amazonaws.com/ws.zip'               #zip containing background images and fonts
#endregion

#region supporting functions
Function Test-Choco                      {
    <#
        .SYNOPSIS
        Evaluates if chocolatey is installed
    #>
    [CmdletBinding()]
    Param ()
    $result    = $true #assume the best
    $testchoco = pwsh -noprofile -c 'choco -v'
    If ($testchoco[0] -like "*.*.*" -and $testchoco[0] -notlike '*not*recognized*') {
        Write-Verbose -Message "Chocolatey Version: $testchoco"
    } Else {
        Write-Verbose -Message "Chocolatey is not installed."
        $result = $false
    }
    return $result
}

Function Test-WinGet                     {
    <#
        .SYNOPSIS
        Evaluates if WinGet is installed
    #>
    [CmdletBinding()]
    Param ()
    $result     = $true #assume the best
    $testwinget = pwsh -noprofile -c 'winget -v'
    If ($testwinget[0] -like "v*") {
        Write-Verbose -Message "winget Version: $testwinget"
    } Else {
        Write-Verbose -Message "winget is not installed."
        $result = $false
    }
    return $result
}

Function Install-Choco                   {
    <#
        .SYNOPSIS
        Installs chocolatey
    #>
    [CmdletBinding()]
    Param ()
    Write-Verbose -Message 'Installing Chocolately...'
    Write-Verbose -Message 'Setting execution and security settings...'
    Set-ExecutionPolicy Bypass -Scope Process -Force
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    Try {
        Write-Verbose -Message 'Downloading and installing...'
        Invoke-WebRequest https://chocolatey.org/install.ps1 -UseBasicParsing -ErrorAction Stop | Invoke-Expression -ErrorAction Stop
        Write-Verbose -Message 'INSTALL COMPLETE.'
    } Catch {
        Write-Error $_
    }
}

Function Install-HelpfulAzureModules     {
    <#
        .SYNOPSIS
        Installs Azure related PowerShell modules
    #>
    [CmdletBinding()]
    Param ()
    Write-Verbose -Message 'Evaluating Azure modules...'
    ForEach ($module in $script:azureModules) {
        Write-Verbose -Message ('     {0} evaluating...' -f $module)
        If (-not (Get-Module $module -ListAvailable)) {
            If ($module -eq 'PSArm') {
                Write-Verbose -Message ('          Installing {0}' -f $module)
                Install-Module -Name $module -Scope CurrentUser -Repository PSGallery -AllowPrerelease -Force -AllowClobber
            } Else {
                Write-Verbose -Message ('          Installing {0}' -f $module)
                Install-Module -Name $module -Scope CurrentUser -Repository PSGallery -Force
            }
        } Else {
            Write-Verbose -Message ('              {0} VERIFIED. NO ACTION TAKEN.' -f $module)
        }
    }
}

Function Install-BaseModules             {
    <#
        .SYNOPSIS
        Installs Core PowerShell modules
    #>
    [CmdletBinding()]
    Param ()
    Write-Verbose -Message 'Evaluating modules...'
    ForEach ($module in $script:modules) {
        Write-Verbose -Message ('     {0} evaluating...' -f $module.ModuleName)
        If ($module.Version -like "*beta*" -or $module.Version -like "*rc*") {
            Write-Verbose -Message ('          {0} version check...' -f $module.Version)
            $moduleEval = Get-InstalledModule -Name $module.ModuleName -RequiredVersion $module.Version -AllowPrerelease -ErrorAction SilentlyContinue
        } ElseIf ($module.Version -ne 'Latest') {
            Write-Verbose -Message ('          {0} version check...' -f $module.Version)
            $moduleEval = Get-InstalledModule -Name $module.ModuleName -RequiredVersion $module.Version -ErrorAction SilentlyContinue
        } Else {
            $moduleEval = Get-Module -Name $module.ModuleName -ListAvailable -ErrorAction SilentlyContinue
        }

        If (-not $moduleEval) {
            If ($module.Version -like "*beta*" -or $module.Version -like "*rc*") {
                Write-Verbose -Message ('          Installing {0} - {1}' -f $module.ModuleName, $module.Version)
                Install-Module -Name $module.ModuleName -Scope CurrentUser -Repository PSGallery -RequiredVersion $module.Version -Force -AllowPrerelease
            } ElseIf ($module.Version -ne 'Latest') {
                Write-Verbose -Message ('          Installing {0} - {1}' -f $module.ModuleName, $module.Version)
                Install-Module -Name $module.ModuleName -Scope CurrentUser -Repository PSGallery -RequiredVersion $module.Version -Force
            } Else {
                Write-Verbose -Message ('          Installing {0}' -f $module.ModuleName)
                Install-Module -Name $module.ModuleName -Scope CurrentUser -Repository PSGallery -Force
            }
        } Else {
            Write-Verbose -Message ('              {0} VERIFIED. NO ACTION TAKEN.' -f $module.ModuleName)
        }
    }
}

Function Uninstall-Pester ([switch]$All) {
    <#
        .SYNOPSIS
        Uninstalls older versions of Pester that ship with Windows
    #>
    If ([IntPtr]::Size * 8 -ne 64) {
        throw "Run this script from 64bit PowerShell."
    }

    $pesterPaths = ForEach ($programFiles in ($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        $path = "$programFiles\WindowsPowerShell\Modules\Pester"
        If ($null -ne $programFiles -and (Test-Path $path)) {
            If ($All) {
                Get-Item $path
            } Else {
                Get-ChildItem "$path\3.*"
            }
        }
    }

    If (-not $pesterPaths) {
        "There are no Pester$(if (-not $all) {" 3"}) installations in Program Files and Program Files (x86) doing nothing."
        return
    }

    ForEach ($pesterPath in $pesterPaths) {
        takeown /F $pesterPath /A /R
        icacls $pesterPath /reset
        # grant permissions to Administrators group, but use SID to do
        # it because it is localized on non-us installations of Windows
        icacls $pesterPath /grant "*S-1-5-32-544:F" /inheritance:d /T
        Remove-Item -Path $pesterPath -Recurse -Force -Confirm:$false
    }
}

Function Install-VSCodeExtension         {
    <#
        .SYNOPSIS
        Installs VSCode extension
    #>
    [CmdletBinding()]
    Param (
        [string[]]$ExtensionList
    )
    ForEach ($Extension in $ExtensionList) {
        Write-Verbose -Message "Installing $Extension ..."
        code --install-extension $Extension
    }
}

Function Test-ChocoInstall               {
    <#
        .SYNOPSIS
        Evaluates if a package is installed with choco
    #>
    [CmdletBinding()]
    Param (
        # choco package to be checked for
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ChocoPackage
    )
    $result = $true #assume the best
    $eval   = $null
    Write-Verbose -Message "Checking for $ChocoPackage..."
    $eval   = pwsh -noprofile -c "choco list --localonly $ChocoPackage"

    If ($eval -match $ChocoPackage) {
        Write-Verbose -Message 'Package VERIFIED.'
    } Else {
        Write-Verbose -Message 'Package NOT FOUND'
        $result = $false
    }
    return $result
}

Function Install-ChocoPackage            {
    <#
        .SYNOPSIS
        Install choco package
    #>
    [CmdletBinding()]
    Param (
        # choco package to be installed
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ChocoPackage
    )

    Write-Verbose -Message ('Choco installing - {0}' -f $ChocoPackage)
    If ($ChocoPackage -ne 'microsoft-office-deployment') {
        pwsh -noprofile -c "choco install $ChocoPackage -y"
    } Else {
        pwsh -noprofile -c "choco install -y --allow-empty-checksums --ignorechecksum microsoft-office-deployment --params='/Language:en-us /64bit /Product:ProPlus2021Volume /Exclude=Groove,Lync,OneNote'"
    }
}

Function Test-WingetInstall              {
    <#
        .SYNOPSIS
        Evaluates if a package is installed with choco
    #>
    [CmdletBinding()]
    Param (
        # winget package to be checked for
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$WingetPackage
    )
    $result = $true #assume the best
    $eval   = $null
    Write-Verbose -Message "Checking for $WingetPackage..."
    $eval   = pwsh -noprofile -c "winget list --id=$WingetPackage --exact --accept-source-agreements"
    If ($eval -like "*$WingetPackage*") {
        Write-Verbose -Message 'Package VERIFIED.'
    } Else {
        Write-Verbose -Message 'Package NOT FOUND'
        $result = $false
    }
    return $result
}

Function Install-RSAT                    {
    <#
        .SYNOPSIS
        Install RSAT features for Windows 10 1809 or 1903 or 1909 or 2004 or 20H2.
        .DESCRIPTION
        Install RSAT features for Windows 10 1809 or 1903 or 1909 or 2004 or 20H2. All features are installed online from Microsoft Update thus the script requires Internet access
        .PARAMETER All
        Installs all the features within RSAT. This takes several minutes, depending on your Internet connection
        .PARAMETER Basic
        Installs ADDS, DHCP, DNS, GPO, ServerManager
        .PARAMETER ServerManager
        Installs ServerManager
        .PARAMETER Uninstall
        Uninstalls all the RSAT features
        .PARAMETER disableWSUS
        Disables the use of WSUS prior to installing the RSAT features. This involves restarting the wuauserv service. The script will enable WSUS again post installing the features on demand
        .NOTES
        Filename: Install-RSATv1809v1903v1909v2004v20H2.ps1
        Version: 1.6
        Author: Martin Bengtsson
        Blog: www.imab.dk
        Twitter: @mwbengtsson
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Switch]$All,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Switch]$Basic,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Switch]$ServerManager,
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Switch]$Uninstall,
        [Parameter(Mandatory=$false)]
        [Switch]$DisableWSUS
    )

    # Check for administrative rights
    If (-NOT([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
        Write-Warning -Message 'The script requires elevation'
        break
    }

    # Create Write-Log function
    Function Write-Log() {
        [CmdletBinding()]
        Param (
            [Parameter(
                Mandatory = $true, 
                ValueFromPipelineByPropertyName = $true
            )]
            [ValidateNotNullOrEmpty()]
            [Alias('LogContent')]
            [String]$message,
            [Parameter(Mandatory=$false)]
            [Alias('LogPath')]
            [String]$path = "$env:windir\Install-RSAT.log",
            [Parameter(Mandatory=$false)]
            [ValidateSet('Error','Warn','Info')]
            [String]$level = 'Info'
        )
        Begin {
            $verbosePreference = 'Continue'
        }
        Process {
            If ((Test-Path -Path $Path)) {
                $logSize    = (Get-Item -Path $Path).Length/1MB
                $maxLogSize = 5
            }

            # Check for file size of the log. If greater than 5MB, it will create a new one and delete the old.
            If (
                (Test-Path -Path $Path) -AND 
                $LogSize -gt 
                $MaxLogSize
            ) {
                Write-Error -Message ('Log file {0} already exists and file exceeds maximum file size. Deleting the log and starting fresh.' -f $Path)
                Remove-Item -Path $Path -Force
                $script:newLogFile = New-Item -Path $Path -Force -ItemType File
            } ElseIf (-NOT (Test-Path -Path $Path)) {
                # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path.
                Write-Verbose -Message ('Creating {0}.' -f $Path)
                $script:newLogFile = New-Item -Path $Path -Force -ItemType File
            } #Else {# Nothing to see here yet.}

            # Format Date for our Log File
            $formattedDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            # Write message to error, warning, or verbose pipeline and specify $LevelText
            Switch ($level) {
                'Error' {
                    Write-Error -Message $message
                    $levelText = 'ERROR:'
                }
                'Warn'  {
                    Write-Warning -Message $Message
                    $levelText = 'WARNING:'
                }
                'Info'  {
                    Write-Verbose -Message $Message
                    $levelText = 'INFO:'
                }
            }
            # Write log entry to $Path
            ('{0} {1} {2}' -f $formattedDate, $levelText, $message) | Out-File -FilePath $path -Append
        }
        End {}
    }

    # Create Pending Reboot function for registry
    Function Test-PendingRebootRegistry {
        $cbsRebootKey = Get-ChildItem -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending' -ErrorAction Ignore
        $wuRebootKey  = Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction Ignore
        If (
            ($null -ne $cbsRebootKey) -OR 
            ($null -ne $wuRebootKey)
        ) {
            $true
        } Else {
            $false
        }
    }

    $1809Build                 = '17763' # Minimum required Windows 10 build (v1809)
    $windowsBuild              = (Get-CimInstance -Class Win32_OperatingSystem).BuildNumber # Get running Windows build
    # Get information about local WSUS server
    $wuServer                  = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name WUServer -ErrorAction Ignore).WUServer
    $useWUServer               = (Get-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction Ignore).UseWuServer
    $testPendingRebootRegistry = Test-PendingRebootRegistry # Look for pending reboots in the registry

    If ($windowsBuild -ge $1809Build) {
        Write-Log -Message ('Running correct Windows 10 build number for installing RSAT with Features on Demand. Build number is: {0}' -f $WindowsBuild)
        Write-Log -Message '***********************************************************'

        If ($null -ne $wuServer) {
            Write-Log -Message ('A local WSUS server was found configured by group policy: {0}' -f $wuServer)
            Write-Log -Message 'You might need to configure additional setting by GPO if things are not working'
            Write-Log -Message 'The GPO of interest is following: Specify settings for optional component installation and component repair'
            Write-Log -Message 'Check ON: Download repair content and optional features directly from Windows Update...'
            Write-Log -Message '***********************************************************'
            Write-Log -Message 'Alternatively, run this script with parameter -disableWSUS to allow the script to temporarily disable WSUS'
        }
        If ($PSBoundParameters['DisableWSUS']) {
            If (-NOT[string]::IsNullOrEmpty($useWUServer)) {
                If ($useWUServer -eq 1) {
                    Write-Log -Message '***********************************************************'
                    Write-Log -Message 'DisableWSUS selected. Temporarily disabling WSUS in order to successfully install features on demand'
                    Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'UseWuServer' -Value 0
                    Restart-Service -Name wuauserv
                }
            }
        }

        If ($testPendingRebootRegistry -eq $true) {
            Write-Log -Message '***********************************************************'
            Write-Log -Message 'Reboots are pending. The script will continue, but RSAT might not install successfully'
        }

        If ($PSBoundParameters['All']) {
            Write-Log -Message '***********************************************************'
            Write-Log -Message 'Script is running with -All parameter. Installing all available RSAT features'
            $install = Get-WindowsCapability -Online | Where-Object {$_.Name -like 'Rsat*' -AND $_.State -eq 'NotPresent'}
            If ($null -ne $install) {
                ForEach ($item in $install) {
                    $RSATItem = $item.Name
                    Write-Log -Message ('Adding {0} to Windows' -f $RSATItem)
                    Try {
                        Add-WindowsCapability -Online -Name $RSATItem
                    } Catch [System.Exception] {
                        Write-Log -Message ('Failed to add {0} to Windows' -f $RSATItem) -Level Warn 
                        Write-Log -Message ('{0}' -f $_.Exception.Message) -Level Warn 
                    }
                }
                If ($PSBoundParameters['DisableWSUS']) {
                    If (-NOT[string]::IsNullOrEmpty($useWUServer)) {
                        If ($useWUServer -eq 1) {
                            Write-Log -Message '***********************************************************'
                            Write-Log -Message 'Enabling WSUS again post installing features on demand'
                            Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'UseWuServer' -Value 1
                            Restart-Service -Name wuauserv
                        }
                    }
                }
            } Else {
                Write-Log -Message 'All RSAT features seems to be installed already'
            }
        }

        If ($PSBoundParameters['Basic']) {
            Write-Log -Message '***********************************************************'
            Write-Log -Message 'Script is running with -Basic parameter. Installing basic RSAT features'
            # Querying for what I see as the basic features of RSAT. Modify this if you think something is missing. :-)
            $install  = Get-WindowsCapability -Online | 
                        Where-Object {
                            $_.Name -like 'Rsat.ActiveDirectory*' -OR 
                            $_.Name -like 'Rsat.DHCP.Tools*' -OR 
                            $_.Name -like 'Rsat.Dns.Tools*' -OR 
                            $_.Name -like 'Rsat.GroupPolicy*' -OR 
                            $_.Name -like 'Rsat.ServerManager*' -AND 
                            $_.State -eq 'NotPresent'
                        }
            If ($null -ne $install) {
                ForEach ($item in $install) {
                    $RSATItem = $item.Name
                    Write-Log -Message ('Adding {0} to Windows' -f $RSATItem)
                    Try {
                        Add-WindowsCapability -Online -Name $RSATItem
                    } Catch [System.Exception] {
                        Write-Log -Message ('Failed to add {0} to Windows' -f $RSATItem) -Level Warn 
                        Write-Log -Message ('{0}' -f $_.Exception.Message) -Level Warn 
                    }
                }
                If ($PSBoundParameters['DisableWSUS']) {
                    If (-NOT[string]::IsNullOrEmpty($useWUServer)) {
                        If ($useWUServer -eq 1) {
                            Write-Log -Message '***********************************************************'
                            Write-Log -Message 'Enabling WSUS again post installing features on demand'
                            Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'UseWuServer' -Value 1
                            Restart-Service -Name wuauserv
                        }
                    }
                }
            } Else {
                Write-Log -Message 'The basic features of RSAT seems to be installed already'
            }
        }

        If ($PSBoundParameters['ServerManager']) {
            Write-Log -Message '***********************************************************'
            Write-Log -Message 'Script is running with -ServerManager parameter. Installing Server Manager RSAT feature'
            $install = Get-WindowsCapability -Online | Where-Object {$_.Name -like 'Rsat.ServerManager*' -AND $_.State -eq 'NotPresent'} 
            If ($null -ne $install) {
                $RSATItem = $Install.Name
                Write-Log -Message ('Adding {0} to Windows' -f $RSATItem)
                Try {
                    Add-WindowsCapability -Online -Name $RSATItem
                } Catch [System.Exception] {
                    Write-Log -Message ('Failed to add {0} to Windows' -f $RSATItem) -Level Warn 
                    Write-Log -Message ('{0}' -f $_.Exception.Message) -Level Warn 
                }
                If ($PSBoundParameters['DisableWSUS']) {
                    If (-NOT[string]::IsNullOrEmpty($useWUServer)) {
                        If ($useWUServer -eq 1) {
                            Write-Log -Message '***********************************************************'
                            Write-Log -Message 'Enabling WSUS again post installing features on demand'
                            Set-ItemProperty -Path 'HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'UseWuServer' -Value 1
                            Restart-Service -Name wuauserv
                        }
                    }
                }
            } Else {
                Write-Log -Message ('{0} seems to be installed already' -f $RSATItem)
            }
        }

        If ($PSBoundParameters['Uninstall']) {
            Write-Log -Message '***********************************************************'
            Write-Log -Message 'Script is running with -Uninstall parameter. Uninstalling all RSAT features'
            # Querying for installed RSAT features first time
            $installed    = Get-WindowsCapability -Online | 
                            Where-Object {
                                $_.Name -like 'Rsat*' -AND 
                                $_.State -eq 'Installed' -AND 
                                $_.Name -notlike 'Rsat.ServerManager*' -AND 
                                $_.Name -notlike 'Rsat.GroupPolicy*' -AND 
                                $_.Name -notlike 'Rsat.ActiveDirectory*'
                            }
            If ($null -ne $installed) {
                Write-Log -Message 'Uninstalling the first round of RSAT features'
                # Uninstalling first round of RSAT features - some features seems to be locked until others are uninstalled first
                ForEach ($item in $installed) {
                    $RSATItem = $item.Name
                    Write-Log -Message ('Uninstalling {0} from Windows' -f $RSATItem)
                    Try {
                        Remove-WindowsCapability -Name $RSATItem -Online
                    } Catch [System.Exception] {
                        Write-Log -Message ('Failed to uninstall {0} from Windows' -f $RSATItem) -Level Warn 
                        Write-Log -Message ('{0}' -f $_.Exception.Message) -Level Warn 
                    }
                }
            }

            # Querying for installed RSAT features second time
            $installed = Get-WindowsCapability -Online | Where-Object {$_.Name -like 'Rsat*' -AND $_.State -eq 'Installed'}
            If ($null -ne $installed) { 
                Write-Log -Message 'Uninstalling the second round of RSAT features'
                # Uninstalling second round of RSAT features
                ForEach ($item in $installed) {
                    $RSATItem = $item.Name
                    Write-Log -Message ('Uninstalling {0} from Windows' -f $RSATItem)
                    Try {
                        Remove-WindowsCapability -Name $RSATItem -Online
                    } Catch [System.Exception] {
                        Write-Log -Message ('Failed to remove {0} from Windows' -f $RSATItem) -Level Warn 
                        Write-Log -Message ('{0}' -f $_.Exception.Message) -Level Warn 
                    }
                } 
            } Else {
                Write-Log -Message 'All RSAT features seems to be uninstalled already'
            }
        }
    } Else {
        Write-Log -Message ('Not running correct Windows 10 build: {0}' -f $windowsBuild) -Level Warn
    }
}

Function Install-WinGet                  {
    <#
            .SYNOPSIS
            Downloads the latest version of Winget, its dependencies, and installs everything
            .DESCRIPTION
            Downloads the latest version of Winget, its dependencies, and installs everything. 
            PATH variable is adjusted after installation. Reboot required after installation.
            .EXAMPLE
            winget-install
            .NOTES
            Version      : 0.0.4
            Created by   : asheroto
            .LINK
            Project Site: https://github.com/asheroto/winget-installer
    #>

    Function Get-NewestLink {
        <#
            .SYNOPSIS
            Prints a Write-Section divider for easy reading of the output.
        #>
        Param (
            [Parameter(Mandatory,HelpMessage='Match')]
            [String]$match
        )
        $uri  = 'https://api.github.com/repos/microsoft/winget-cli/releases/latest'
        Write-Verbose -Message "[$((Get-Date).TimeofDay)] Getting information from $uri"

        $get  = Invoke-RestMethod -uri $uri -Method Get -ErrorAction Stop
        Write-Verbose -Message "[$((Get-Date).TimeofDay)] getting latest release"

        $data = $get[0].assets | Where-Object {$_.Name -Match $match}
        return $data.browser_download_url
    }

    $wingetUrl        = Get-NewestLink('msixbundle')
    $wingetLicenseUrl = Get-NewestLink('License1.xml')

    Function Write-Section {
        <#
            .SYNOPSIS
            Prints a Write-Section divider for easy reading of the output.
        #>
        Param (
            [Parameter(Mandatory,HelpMessage='Text')]
            [String]$text
        )
        $Sep = '###################################'
        Write-Output -InputObject $Sep
        Write-Output -InputObject "# $text"
        Write-Output -InputObject $Sep
    }

    # Add AppxPackage and silently continue on error
    Function Add-AAP {
        <#
                .SYNOPSIS
                Adds an AppxPackage to the system.
        #>
        Param (
            [Parameter(Mandatory,HelpMessage='Package')]
            [String]$pkg
        )
        Add-AppxPackage $pkg -ErrorAction SilentlyContinue
    }

    # Download XAML nupkg and extract appx file
    Write-Section('Downloading Xaml nupkg file... (19000000ish bytes)')
    $url         = 'https://www.nuget.org/api/v2/package/Microsoft.UI.Xaml/2.7.1'
    $nupkgFolder = 'Microsoft.UI.Xaml.2.7.1.nupkg'
    $zipFile     = 'Microsoft.UI.Xaml.2.7.1.nupkg.zip'
    Invoke-WebRequest -Uri $url -OutFile $zipFile
    Write-Section('Extracting appx file from nupkg file...')
    Expand-Archive -Path $zipFile

    # Determine architecture
    If ([Environment]::Is64BitOperatingSystem) {
        Write-Section('64-bit OS detected')

        # Install x64 VCLibs
        Write-Section('Downloading & installing x64 VCLibs... (21000000ish bytes)')
        Add-AAP('https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx')

        # Install x64 XAML
        Write-Section('Installing x64 XAML...')
        Add-AAP('Microsoft.UI.Xaml.2.7.1.nupkg\tools\AppX\x64\Release\Microsoft.UI.Xaml.2.7.appx')
    } Else {
        Write-Section('32-bit OS detected')

        # Install x86 VCLibs
        Write-Section('Downloading & installing x86 VCLibs... (21000000ish bytes)')
        Add-AAP('https://aka.ms/Microsoft.VCLibs.x86.14.00.Desktop.appx')

        # Install x86 XAML
        Write-Section('Installing x86 XAML...')
        Add-AAP('Microsoft.UI.Xaml.2.7.1.nupkg\tools\AppX\x86\Release\Microsoft.UI.Xaml.2.7.appx')
    }

    # Finally, install winget
    Write-Section('Downloading winget... (21000000ish bytes)')
    $wingetPath        = 'winget.msixbundle'
    Invoke-WebRequest -Uri $wingetUrl -OutFile $wingetPath
    $wingetLicensePath = 'License1.xml'
    Invoke-WebRequest -Uri $wingetLicenseUrl -OutFile $wingetLicensePath
    Write-Section('Installing winget...')
    Add-AppxProvisionedPackage -Online -PackagePath $wingetPath -LicensePath $wingetLicensePath -ErrorAction SilentlyContinue

    # Adding WindowsApps directory to PATH variable for current user
    Write-Section('Adding WindowsApps directory to PATH variable for current user...')
    $path = [Environment]::GetEnvironmentVariable('PATH', 'User')
    $path = $path + ';' + [IO.Path]::Combine([Environment]::GetEnvironmentVariable('LOCALAPPDATA'), 'Microsoft', 'WindowsApps')
    [Environment]::SetEnvironmentVariable('PATH', $path, 'User')

    # Cleanup
    Write-Section('Cleaning up...')
    Remove-Item -Path $zipFile
    Remove-Item -Path $nupkgFolder -Recurse
    Remove-Item -Path $wingetPath
    Remove-Item -Path $wingetLicensePath

    # Finished
    Write-Section('Installation complete!')
    Write-Section('Please restart your computer to complete the installation.')
}

Function Install-WingetPackage           {
    <#
        .SYNOPSIS
        Install winget package
    #>
    [CmdletBinding()]
    Param (
        # winget package to be installed
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$WingetPackage
    )
    Write-Verbose -Message ('winget installing - {0}' -f $WingetPackage)
    pwsh -noprofile -c "winget install --id=$WingetPackage --silent --accept-package-agreements --accept-source-agreements"
}

Function Get-WSSetupFiles                {
    <#
        .SYNOPSIS
        Evaluates if workstation setup files are present. If not downloads and unzips.
    #>
    [CmdletBinding()]
    Param ()
    $wsFilesPath = -join ($script:tempPath, '\ws_files')

    Write-Verbose -Message "Evaluating if $wsFilesPath is present..."
    If (-not (Test-Path $wsFilesPath)) {
        Write-Verbose -Message '    Downloading workstation setup files...'
        Try {
            $invokeSplat = @{
                Uri         = $script:setupFiles
                OutFile     = "$script:tempPath\ws.zip"
                ErrorAction = 'Stop'
            }
            Invoke-WebRequest @invokeSplat
            Write-Verbose -Message '    Download complete.'
        } Catch {
            Write-Error $_
            return
        }

        Try {
            Write-Verbose -Message '    Expanding zip download...'
            $expandSplat = @{
                LiteralPath     = "$script:tempPath\ws.zip"
                DestinationPath = $wsFilesPath
                ErrorAction     = 'Stop'
            }
            Expand-Archive @expandSplat
            Write-Verbose -Message '    UNZIPPED!'
        } Catch {
            Write-Error $_
            return
        }
    } Else {
        Write-Verbose -Message "    VERIFIED. No action taken."
    }
}

Function Set-SettingsFiles               {
    <#
        .SYNOPSIS
        Retrieves settings files from github and places in appropriate locations
    #>
    [CmdletBinding()]
    Param ()
    $settings = @(
        <#
        @{
            Name = 'VSCode Settings'
            URI  = $script:vsCodeSettingsJSON
            File = -join ($script:vscodeSettingsPath, '\settings.json')
        }
        @{
            Name = 'VSCode Python Snippets'
            URI  = $script:vsCodePythonSnippetsJSON
            File = -join ($script:vscodeSnippetsPath, '\python.json')
        }
        @{
            Name = 'VSCode PowerShell Snippets'
            URI  = $script:vsCodePowerShellSnippetsJSON
            File = -join ($script:vscodeSnippetsPath, '\powershell.json')
        }#>
        @{
            Name = 'Windows Terminal Settings'
            URI  = $script:windowsTerminalSettingsJSON
            File = -join ($script:windowsTerminalSettingsPath, '\settings.json')
        }
        @{
            Name = 'oh-my-posh Settings'
            URI  = $script:ohmyposhJSON
            File = -join ($script:ohmyposhSettings, '\.work.omp.json')
        }
        @{
            Name = 'PowerShell profile'
            URI  = $script:psProfile
            File = -join ($script:profilePath, '\profile.ps1')
        }
    )

    ForEach ($setting in $settings) {
        Start-Sleep -Milliseconds 500
        Write-Verbose -Message ('Downloading {0} to {1}' -f $setting.Name, $setting.File)

        $gistUrl     = $null
        $fileName    = $null
        $gistContent = $null
        $gistUrl     = $setting.URI
        $fileName    = Split-Path $setting.File -leaf
        # $path        = 'C:\rs-pkgs\settings'

        Try {
            $invokeSplat = @{
                Uri         = $gistUrl
                ErrorAction = 'Stop'
            }

            $gist        = Invoke-RestMethod @invokeSplat
            $gistContent = $gist.Files.$fileName.Content
            Write-Verbose -Message '    Download COMPLETED.'
        } Catch {
            Write-Error $_
            continue
        }

        Try {
            Write-Verbose -Message '    Writing out content...'
            $setContentSplat = @{
                # Path        = "$path\$fileName"
                Path        = $setting.File
                Value       = $gistContent
                Confirm     = $false
                Force       = $true
                ErrorAction = 'Stop'
            }
            Set-Content @setContentSplat
            Write-Verbose -Message '    Setting applied!'
        } Catch {
            Write-Error $_
            continue
        }
    }
}

Function Install-Fonts                   {
    <#
        .SYNOPSIS
        Installs all specified fonts in fonts folder
    #>
    [CmdletBinding()]
    Param ()
    Write-Verbose -Message 'Starting fonts installation...'
    $wsFilesPath = -join ($script:tempPath, '\ws_files\ws')
    $fontPath    = -join ($script:tempPath, '\ws_files\ws\Fonts\Fonts')

    Write-Verbose -Message '    Getting required fonts to install...'
    . $wsFilesPath\Fonts\PS_Font_Scripts\Add-Font.ps1 -Path $fontPath
}

Function Set-BackImages                  {
    <#
        .SYNOPSIS
        Copies all background images for Windows terminal
    #>
    [CmdletBinding()]
    Param ()

    Write-Verbose -Message 'Starting Windows Terminal background files copy...'
    $wsFilesPath    = -join ($script:tempPath, '\ws_files\ws\backs')

    Write-Verbose -Message '    Getting required backgrounds...'
    $allBackgrounds = Get-ChildItem -Path $wsFilesPath

    ForEach ($background in $allBackgrounds) {
        $testPath = -join ($script:windowsTerminalBackgroundPath, '\', $background.Name)
        Write-Verbose -Message ('        Evaluating - {0}' -f $background.FullName)
        If (-not (Test-Path $testPath)) {
            Write-Verbose -Message '        NOT found. Copying.'
            Copy-Item -Path $background.FullName -Destination $testPath
        } Else {
            Write-Verbose -Message '        FOUND. No action taken.'
        }
    }
}

Function Set-AzurePathVariables          {
    [CmdletBinding()]
    Param ()
    $pathsToAdd = @(
        'C:\Program Files (x86)\Microsoft SDKs\Azure\Storage Emulator'
        'C:\Program Files (x86)\Microsoft SDKs\Azure\Azcopy'
    )

    Write-Verbose -Message 'Backing up curent paths to file...'
    $fileName = -join ('path_', (Get-Date -format yyyy-MM-ddTHH-mm-ss-ff), '.txt')
    [System.Environment]::GetEnvironmentVariable('PATH', 'machine') | Out-File "$script:tempPath\$fileName" -Force

    Write-Verbose -Message 'Evaluating if current paths present...'
    $paths    = ($env:PATH).split(";")
    ForEach ($pathAdd in $pathsToAdd) {
        $eval = $false
        ForEach ($path in $paths) {
            If ($path -eq $pathAdd) {
                $eval = $true
                Write-Verbose -Message (    '{0} Found!' -f $pathAdd)
            }
        }
        If ($eval -eq $false) {
            Write-Verbose -Message (    '{0} NOT Found! Adding...' -f $pathAdd)
            $oldPath = [System.Environment]::GetEnvironmentVariable('PATH', 'machine')
            $newPath = "$OLDPATH;$pathAdd"
            [Environment]::SetEnvironmentVariable("PATH", "$NEWPATH", "Machine")
        } Else {
            Write-Verbose -Message '    No Action taken'
        }
    }
}
#endregion

#region main
Function Invoke-WSSetup                  {
    <#
        .SYNOPSIS
            Sets up a new workstation for desired development configuration
        .DESCRIPTION
            Downloads files, settings, and configurations to set new workstation to desired development setup and config.
        .EXAMPLE
            Invoke-WSSetup

            Configures workstation to base level dev configuration.
        .EXAMPLE
            Invoke-WSSetup -Python -AWS -Azure -Fonts

            Configures workstation to base level dev configuration. Also adds fonts, python, aws, and azure utilities.
        .PARAMETER Python
            If specified installs additional Python utilities and settings
        .PARAMETER AWS
            If specified installs additional AWS utilities and settings
        .PARAMETER AWSCDK
            If specified installs additional AWS CDK utilities for TypeScript CDK
        .PARAMETER Azure
            If specified installs additional Azure utilities and settings
        .PARAMETER Fonts
            If specified installs downloaded Nerd font packages
        .NOTES
            What does this actually do?
            It downloads a package config zip that contains:
                - Various Nerd fonts
                - Background photos for Windows Terminal
            Installs choco if required
            Installs base level things like VSCode via choco
            Downloads configuration from GitHub gists and applies to proper locations:
                - Configures VSCode with desired configurations
                - Populates VSCode snippets
                - Sets oh-my-posh theme configuration
                - Configures Windows Terminal with desired configurations
                - Sets PowerShell profile.ps1
            Installs base level desired PowerShell modules
            Install desired VSCode extensions
            Installs tech specific utilities/configs/extensions based on specified switches
    #>
    [CmdletBinding()]
    Param (
        [switch]$Software,
        [switch]$Python,
        [switch]$AWS,
        [switch]$AWSCDK,
        [switch]$Azure,
        [switch]$Fonts
    )

    #Requires -Version 7
    #Requires -RunAsAdministrator

    $ProgressPreference = 'SilentlyContinue'

    ### Verify if winget is installed
    If (-not (Test-WinGet)) {
        #throw 'WinGet not installed. You need to install App Installer from the Microsoft Store'
        Install-WinGet
    }

    ### Remove old versions of Pester
    Uninstall-Pester

    ### Set-up the temp dir if required
    Write-Verbose -Message 'Verifying temp dir...'
    If (-not (Test-Path $script:tempPath)) {
        Write-Verbose -Message '    CREATING temp dir.'
        New-Item -Path $script:tempPath -ItemType Directory -Force
    } Else {
        Write-Verbose -Message '    VERIFIED Temp.'
    }

    ### Make sure we have the workstation setup files
    Get-WSSetupFiles

    ### Verify chocolatey is installed
    If (-not (Test-Choco)) {
        Install-Choco
    }

    ### Install our base winget packages
    ForEach ($package in $script:wingetCoreTech) {
        If (-not (Test-WingetInstall -WingetPackage $package)) {
            Install-WingetPackage -WingetPackage $package
        }
    }

    ### Install our base choco packages
    ForEach ($package in $script:chocoCoreTech) {
        If (-not (Test-ChocoInstall -ChocoPackage $package)) {
            Install-ChocoPackage -ChocoPackage $package
        }
    }

    <### Temp add vscode path:
    $env:Path += ";C:\Program Files\Microsoft VS Code\bin"
    $env:Path += ";$env:LOCALAPPDATA\Programs\Microsoft VS Code\bin"

    ### Create snippets path if not created
    If (-not (Test-Path $script:vscodeSnippetsPath)) {
        New-Item -Path $script:vscodeSnippetsPath -ItemType Directory -Force
    }#>

    ### Install our base PowerShell modules
    Install-BaseModules

    ### Install VSCode extensions
    #Install-VSCodeExtension -ExtensionList $script:vscodeExtensions

    ### Download and place our settings files
    Set-SettingsFiles

    ### Copy Windows Terminal background images to proper location
    Set-BackImages

    ### Installs fonts if font switch specified
    If ($fonts) {
        Install-Fonts
    }

    ### Installs software packages if specified
    If ($Software) {
        ForEach ($package in $script:wingetSoftwareInstalls) {
            If (-not (Test-WingetInstall -WingetPackage $package)) {
                Install-WingetPackage -WingetPackage $package
            }
        }
        ForEach ($package in $script:chocoSoftwareInstalls) {
            If (-not (Test-ChocoInstall -ChocoPackage $package)) {
                Install-ChocoPackage -ChocoPackage $package
            }
        }
    }

    ### Installs azure resources if azure switch is specified
    If ($azure) {
        ### Install azure winget packages
        ForEach ($package in $script:wingetInstallsAzure) {
            If (-not (Test-WingetInstall -WingetPackage $package)) {
                Install-WingetPackage -WingetPackage $package
            }
        }

        ### Install azure choco packages
        ForEach ($package in $script:chocoInstallsAzure) {
            If (-not (Test-ChocoInstall -ChocoPackage $package)) {
                Install-ChocoPackage -ChocoPackage $package
            }
        }

        ### Install azure Modules
        Install-HelpfulAzureModules

        ### Install azure extensions
        #Install-VSCodeExtension -ExtensionList $script:vscodeExtensionsAzure

        ### Set azure path variables
        Set-AzurePathVariables
    }

    ### Installs aws resources if aws switch is specified
    If ($aws) {
        ### Install aws winget packages
        ForEach ($package in $script:wingetInstallsAWS) {
            If (-not (Test-WingetInstall -WingetPackage $package)) {
                Install-WingetPackage -WingetPackage $package
            }
        }

        ### Install aws choco packages
        ForEach ($package in $script:chocoInstallsAWS) {
            If (-not (Test-ChocoInstall -ChocoPackage $package)) {
                Install-ChocoPackage -ChocoPackage $package
            }
        }

        ### Install aws tools installer module
        Install-Module -Name AWS.Tools.Installer -Scope CurrentUser -Repository PSGallery -Force

        ### Install aws modules
        ForEach ($module in $script:awsModules) {
            Write-Verbose -Message ('     {0} evaluating...' -f $module)

            If (-not (Get-Module $module -ListAvailable)) {
                Write-Verbose -Message ('          Installing {0}' -f $module)
                Install-AWSToolsModule -Name $module -Scope CurrentUser -Force
            } Else {
                Write-Verbose -Message ('              {0} VERIFIED. NO ACTION TAKEN.' -f $module)
            }
        }

        ### Install aws extensions
        Install-VSCodeExtension -ExtensionList $script:vscodeExtensionsAWS
    }

    ### Installs aws cdk resources if awscdk switch is specified
    If ($awscdk) {
        ### install aws winget packages
        ForEach ($package in $script:wingetAWSCDKTypeScript) {
            If (-not (Test-WingetInstall -WingetPackage $package)) {
                Install-WingetPackage -WingetPackage $package
            }
        }

        ### Install aws cdk useful extensions
        Install-VSCodeExtension -ExtensionList $script:vscodeExtensionsAWSCDK

        ### Temp add vscode path:
        $env:Path += ";C:\Program Files\nodejs"

        ### Install the TypeScript compiler
        npm install -g typescript

        ### Install aws cdk library
        npm install aws-cdk-lib

        ### Install the aws cdk
        npm install -g aws-cdk
    }

    ### Installs python resources if python switch is specified
    If ($python) {
        ### Install python extensions
        Install-VSCodeExtension -ExtensionList $script:vscodeExtensionsPython
    }
}
#endregion
