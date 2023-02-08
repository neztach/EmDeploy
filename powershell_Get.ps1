$script:tempPath = -join ($env:TEMP, '\ws_setup')
Write-Verbose -Message 'Verifying temp dir...'
If (-not (Test-Path $script:tempPath)) {
    Write-Verbose -Message '    CREATING temp dir.'
    New-Item -Path $script:tempPath -ItemType Directory -Force
} Else {
    Write-Verbose -Message '    VERIFIED Temp.'
}

Function Get-WSSetupFile   {
    <#
        .SYNOPSIS
        Evaluates if workstation setup files are present. If not downloads and unzips.
    #>
    [CmdletBinding()]
    Param ()
    $wsFilesPath = -join ($script:tempPath, '\ws_files')

    Write-Verbose -Message "Evaluating if $wsFilesPath is present..."
    If (-not (Test-Path $wsFilesPath)) {
        Write-Verbose -Message '    Downloading workstation setup file...'
        Try {
            $invokeSplat = @{
                Uri         = 'https://raw.githubusercontent.com/neztach/EmDeploy/main/ws_setup.ps1'
                OutFile     = "$script:tempPath\ws_setup.ps1"
                ErrorAction = 'Stop'
            }
            Invoke-WebRequest @invokeSplat
            Write-Verbose -Message '    Download complete.'
        } Catch {
            Write-Error $_
            return
        }
    } Else {
        Write-Verbose -Message "    VERIFIED. No action taken."
    }
}

Function Invoke-RemoteScript {
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [String]$address,
        [Parameter(ValueFromRemainingArguments = $true)]
        $remainingArgs
    )
    Invoke-Expression "& { $(Invoke-RestMethod $address) } $remainingArgs"
}
Set-Alias -Name irs -Value Invoke-RemoteScript

irs 'https://aka.ms/install-powershell.ps1'
Invoke-RestMethod 'https://raw.githubusercontent.com/neztach/my-box/master/bootstrap/pwsh-core.ps1' -OutFile $script:tempPath\pwsh-core.ps1
Get-WSSetupFile
$pwsh = "$env:LOCALAPPDATA\Microsoft\powershell-daily\pwsh.exe"
. $pwsh -nologo -noprofile -file $script:tempPath\ws_setup.ps1
