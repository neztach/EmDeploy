Function Install-SysInternalsSuite {
    Param ([Parameter(Mandatory = $true)][String]$InstallPath)

    #regin Variables
    $St = 'Stop'
    $Gr = @{ForegroundColor = 'Green'}
    $SysIntPath = "$env:TEMP\SysInternalsSuite"
    $SysIntZip  = "$env:TEMP\SysInternalsSuite.zip"
    $regKey     = 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment'

    #Create the installation folder if not already present
    If (-not (Test-Path -path $InstallPath)) {   
        Try {
            New-Item -ItemType Directory -Path $InstallPath -ErrorAction $St | Out-Null
            Write-Host ('Specified installation path {0} not found, creating now....' -f $InstallPath) @Gr
        } Catch {
            Write-Warning -Message ('Install path {0} not found, creating now....' -f $InstallPath)
            Write-Warning -Message ('Error creating path {0}, check path and permissions. Exiting now...' -f $InstallPath)
            return
        }
    } Else {
        Write-Host ('Specified installation path {0} found, continuing....' -f $InstallPath) @Gr
    }

    #Check if the previous download folder is present. Remove it first if it is
    If (Test-Path -Path $SysIntPath) {
        Write-Warning -Message ('Previous extracted version found in {0}, removing it now...' -f $env:temp)
        Remove-Item -Path $SysIntPath -Force:$true -Confirm:$false -Recurse 
    } Else {
        Write-Host ('No previous download found in {0}\SysInternalsSuite, continuing...' -f $env:temp) @Gr
    }

    #Download and extract the latest version
    Try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-Webrequest -uri https://download.sysinternals.com/files/SysinternalsSuite.zip -Outfile $SysIntZip -ErrorAction $St
        Write-Host ('Downloading latest version to {0}\SysinternalsSuite.zip' -f $env:temp) @Gr
        Expand-Archive -LiteralPath $SysIntZip -DestinationPath $SysIntPath -Force:$true -ErrorAction $St
        Write-Host ('Extracting files to {0}\SysInternalsSuite' -f $env:temp) @Gr
    } Catch {
        Write-Warning -Message ('Error downloading/extracting the SysInternalsSuite, exiting...')
        return
    }

    #Loop through the files and only overwrite older versions and report updated programs on-screen. 
    #Additional files which were not present in the installation folder will be added
    $totalfiles = (Get-ChildItem -Path $SysIntPath).count
    $updated    = 0
    ForEach ($file in Get-ChildItem -Path $SysIntPath) {
        If ((Test-Path -path ('{0}\{1}' -f ($InstallPath), $file.Name)) -and (Test-Path -Path ('{0}\SysInternalsSuite\{1}' -f ($env:temp), $file.name))) {
            $currentversion  = (Get-Item -Path ('{0}\{1}' -f ($InstallPath), $file.Name)).VersionInfo
            $downloadversion = (Get-Item -Path ('{0}\SysInternalsSuite\{1}' -f ($env:temp), $file.name)).VersionInfo
            If ($currentversion.ProductVersion -lt $downloadversion.ProductVersion) {
                Try {
                    Copy-Item -LiteralPath ('{0}\SysInternalsSuite\{1}' -f ($env:temp), $file.name) -Destination ('{0}\{1}' -f ($InstallPath), $file.Name) -Force:$true -Confirm:$false -ErrorAction $St
                    write-host ('- Updating {0} from version {1} to version {2}' -f $file.Name, $currentversion.ProductVersion, $downloadversion.ProductVersion) @Gr
                    ++$updated
                } Catch {
                    Write-Warning -Message ('Error overwriting {0}, please check permissions or perhaps the file is in use?' -f $file.name)
                }
            }
        } Else {
            Try {
                Copy-Item -LiteralPath ('{0}\SysInternalsSuite\{1}' -f ($env:temp), $file.name) -Destination ('{0}\{1}' -f ($InstallPath), $file.Name) -Force:$true -Confirm:$false -ErrorAction $St
                write-host ('- Copying new file {0} to {1}' -f $file.Name, $InstallPath) @Gr
                ++$updated
            } Catch {
                Write-Warning -Message ('Error copying {0}, please check permissions' -f $file.name)
            }
        }
    }

    #Add installation folder to Path for easy access if not already present
    If ((Get-ItemProperty -Path $regKey -Name PATH).Path -split ';' -notcontains $InstallPath) { 
        Write-Host ('Adding {0} with the SysInternalsSuite to the System Path' -f $InstallPath) @Gr
        $OldPath = (Get-ItemProperty -Path $regKey -Name PATH).Path
        $NewPath = $OldPath + (';{0}' -f ($InstallPath))
        Set-ItemProperty -Path $regKey -Name PATH -Value $NewPath
    } Else {
        Write-Host ('The installation folder {0} is already present in the System Path, skipping adding it...' -f $InstallPath) @Gr
    }

    #Cleanup files
    If (Test-Path -Path $SysIntPath) {
        Write-Host ('Cleaning extracted version in {0}' -f $env:temp) @Gr
        Remove-Item -Path $SysIntPath -Force:$true -Confirm:$false -Recurse 
    }
    If (Test-Path -Path $SysIntZip) {
        Write-Host ('Cleaning downloaded SysinternalsSuite.zip file in {0}' -f $env:temp) @Gr
        Remove-Item -Path $SysIntZip -Force:$true -Confirm:$false
    }

    #Display totals and exit
    Write-Host ('Updated {0} files in {1} from the downloaded {2} files' -f $updated, $InstallPath, $totalfiles) @Gr
    return
}
