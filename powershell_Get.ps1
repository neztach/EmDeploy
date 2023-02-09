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
$args = "-nologo -noprofile -file $script:tempPath\ws_setup.ps1"
Start-Process pwsh.exe -ArgumentList $args
#. $pwsh -nologo -noprofile -file $script:tempPath\ws_setup.ps1
