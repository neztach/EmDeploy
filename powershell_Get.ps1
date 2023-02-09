$script = $MyInvocation.MyCommand.Definition
$ps     = Join-Path $PSHome 'powershell.exe'

$isLocalAdmin = [bool]((net localgroup administrators) -match "$env:USERDOMAIN\\$env:USERNAME")

If ($isLocalAdmin) {
    If (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
        Start-Process $ps -Verb runas -ArgumentList "& '$script'"
        exit
    }
}# Else {
#    Start-Process $ps -ArgumentList (@('-File', $script) + $args) -Credential $credential
#    exit
#}

$script:tempPath = 'C:\down\ws_setup'

Write-Verbose -Message 'Verifying temp dir...'
If (-not (Test-Path $script:tempPath)) {
    Write-Verbose -Message '    CREATING temp dir.'
    New-Item -Path $script:tempPath -ItemType Directory -Force
} Else {
    Write-Verbose -Message '    VERIFIED Temp.'
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
Invoke-RestMethod 'https://raw.githubusercontent.com/neztach/EmDeploy/main/ws_setup.ps1' -OutFile $script:tempPath\ws_setup.ps1

$pwsh = "$env:LOCALAPPDATA\Microsoft\powershell\pwsh.exe"
. $pwsh -nologo -noprofile -file $script:tempPath\ws_setup.ps1
