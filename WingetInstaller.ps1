# https://gist.github.com/fcenobi/502a16e3dc7f97b2b00afd29f87a1025#file-install-winget-ps1

Function Install-WinGet {
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
        Param ([Parameter(Mandatory,HelpMessage='Match')][String]$match)
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
        Param ([Parameter(Mandatory,HelpMessage='Text')][String]$text)
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
        Param ([Parameter(Mandatory,HelpMessage='Package')][String]$pkg)
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
