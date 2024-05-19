param (
    [Parameter()]
    [switch]$UninstallSpotifyStoreEdition = (Read-Host -Prompt 'Desinstaller l''edition Spotify Windows Store si elle existe (O/N)').ToLower() -eq 'o',
    [Parameter()]
    [switch]$UpdateSpotify
)

# Effacer l'écran après avoir lu l'entrée de l'utilisateur
Clear-Host

# Configurer pour utiliser TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Ignorer les erreurs de `Stop-Process`
$PSDefaultParameterValues['Stop-Process:ErrorAction'] = [System.Management.Automation.ActionPreference]::SilentlyContinue

[System.Version]$minimalSupportedSpotifyVersion = '1.2.8.923'

function Get-File {
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [System.Uri]$Uri,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo]$TargetFile,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Int32]$BufferSize = 1,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('KB', 'MB')]
        [String]$BufferUnit = 'MB',

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Int32]$Timeout = 10000
    )

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $useBitTransfer = $null -ne (Get-Module -Name BitsTransfer -ListAvailable) -and 
                      ($PSVersionTable.PSVersion.Major -le 5) -and 
                      ((Get-Service -Name BITS).StartType -ne [System.ServiceProcess.ServiceStartMode]::Disabled)

    if ($useBitTransfer) {
        Write-Host -ForegroundColor Cyan 'Utilisation d''une methode de secours BitTransfer car vous utilisez Windows PowerShell'
        Write-Host ""
        Start-BitsTransfer -Source $Uri -Destination $TargetFile.FullName
    } else {
        $request = [System.Net.HttpWebRequest]::Create($Uri)
        $request.set_Timeout($Timeout)
        $response = $request.GetResponse()
        $totalLength = [System.Math]::Floor($response.get_ContentLength() / 1024)
        $responseStream = $response.GetResponseStream()
        $targetStream = New-Object -TypeName System.IO.FileStream -ArgumentList $TargetFile.FullName, 'Create'

        switch ($BufferUnit) {
            'KB' { $BufferSize *= 1024 }
            'MB' { $BufferSize *= 1024 * 1024 }
            Default { $BufferSize = 1024 * 1024 }
        }

        Write-Host -ForegroundColor Yellow "Taille du tampon : $BufferSize B ($($BufferSize/($BufferUnit)) $BufferUnit)"
        Write-Host ""
        $buffer = New-Object byte[] $BufferSize
        $count = $responseStream.Read($buffer, 0, $buffer.length)
        $downloadedBytes = $count
        $downloadedFileName = $Uri.AbsolutePath.Split('/')[-1]

        while ($count -gt 0) {
            $targetStream.Write($buffer, 0, $count)
            $count = $responseStream.Read($buffer, 0, $buffer.length)
            $downloadedBytes += $count
            Write-Progress -Activity "Telechargement du fichier '$downloadedFileName'" -Status "Telecharge ($([System.Math]::Floor($downloadedBytes/1024))K sur $totalLength K) : " -PercentComplete ((([System.Math]::Floor($downloadedBytes / 1024)) / $totalLength) * 100)
        }

        Write-Progress -Activity "Telechargement du fichier '$downloadedFileName' termine"
        Write-Host ""
        $targetStream.Flush()
        $targetStream.Close()
        $targetStream.Dispose()
        $responseStream.Dispose()
    }
}

function Test-SpotifyVersion {
    param (
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [System.Version]$MinimalSupportedVersion,

        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [System.Version]$TestedVersion
    )

    process {
        return ($MinimalSupportedVersion.CompareTo($TestedVersion) -le 0)
    }
}

Write-Host -ForegroundColor Green @"
**********************************
Auteurs : @Nuzair46, @KUTlime
**********************************
"@
Write-Host ""

$spotifyDirectory = Join-Path -Path $env:APPDATA -ChildPath 'Spotify'
$spotifyExecutable = Join-Path -Path $spotifyDirectory -ChildPath 'Spotify.exe'
$spotifyApps = Join-Path -Path $spotifyDirectory -ChildPath 'Apps'

[System.Version]$actualSpotifyClientVersion = (Get-ChildItem -LiteralPath $spotifyExecutable -ErrorAction:SilentlyContinue).VersionInfo.ProductVersionRaw

Write-Host -ForegroundColor Blue "Arret de Spotify...`n"
Write-Host ""
Stop-Process -Name Spotify
Stop-Process -Name SpotifyWebHelper

if ($PSVersionTable.PSVersion.Major -ge 7) {
    Import-Module Appx -UseWindowsPowerShell -WarningAction:SilentlyContinue
}

if (Get-AppxPackage -Name SpotifyAB.SpotifyMusic) {
    Write-Host -ForegroundColor Red "La version Microsoft Store de Spotify a ete detectee, ce qui n'est pas pris en charge.`n"
    Write-Host ""

    if ($UninstallSpotifyStoreEdition) {
        Write-Host -ForegroundColor Blue "Desinstallation de Spotify.`n"
        Write-Host ""
        Get-AppxPackage -Name SpotifyAB.SpotifyMusic | Remove-AppxPackage
    } else {
        Read-Host "Sortie...`nAppuyez sur une touche pour quitter..."
        exit
    }
}

Push-Location -LiteralPath $env:TEMP
try {
    New-Item -Type Directory -Name "BlockTheSpot-$(Get-Date -UFormat '%Y-%m-%d_%H-%M-%S')" | Convert-Path | Set-Location
} catch {
    Write-Output $_
    Read-Host 'Appuyez sur une touche pour quitter...'
    exit
}

$spotifyInstalled = Test-Path -LiteralPath $spotifyExecutable

if (-not $spotifyInstalled) {
    $unsupportedClientVersion = $true
} else {
    $unsupportedClientVersion = ($actualSpotifyClientVersion | Test-SpotifyVersion -MinimalSupportedVersion $minimalSupportedSpotifyVersion) -eq $false
}

if (-not $UpdateSpotify -and $unsupportedClientVersion) {
    if ((Read-Host -Prompt 'Pour installer Block the Spot, votre client Spotify doit etre mis a jour. Voulez-vous continuer ? (O/N)').ToLower() -ne 'o') {
        exit
    }
}

if (-not $spotifyInstalled -or $UpdateSpotify -or $unsupportedClientVersion) {
    Write-Host -ForegroundColor Blue 'Telechargement de la derniere configuration complete de Spotify, veuillez patienter...'
    Write-Host ""
    $spotifySetupFilePath = Join-Path -Path $PWD -ChildPath 'SpotifyFullSetup.exe'
    try {
        $uri = if ([Environment]::Is64BitOperatingSystem) { 'https://download.scdn.co/SpotifyFullSetupX64.exe' } else { 'https://download.scdn.co/SpotifyFullSetup.exe' }
        Get-File -Uri $uri -TargetFile $spotifySetupFilePath
    } catch {
        Write-Output $_
        Read-Host 'Appuyez sur une touche pour quitter...'
        exit
    }
    New-Item -Path $spotifyDirectory -ItemType Directory -Force | Write-Verbose

    [System.Security.Principal.WindowsPrincipal]$principal = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $isUserAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Host -ForegroundColor Blue 'Execution de l''installation...'
    Write-Host ""
    if ($isUserAdmin) {
        Write-Host -ForegroundColor Yellow 'Creation d''une tache planifiee...'
        Write-Host ""
        $apppath = 'powershell.exe'
        $taskname = 'Installation de Spotify'
        $action = New-ScheduledTaskAction -Execute $apppath -Argument "-NoLogo -NoProfile -Command & '$spotifySetupFilePath'"
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date)
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -WakeToRun
        Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskname -Settings $settings -Force | Write-Verbose
        Write-Host 'La tache d''installation a ete planifiee. Demarrage de la tache...'
        Write-Host ""
        Start-ScheduledTask -TaskName $taskname
        Start-Sleep -Seconds 2
        Write-Host 'Desinscription de la tache...'
        Write-Host ""
        Unregister-ScheduledTask -TaskName $taskname -Confirm:$false
        Start-Sleep -Seconds 2
    } else {
        Start-Process -FilePath $spotifySetupFilePath
    }

    while ($null -eq (Get-Process -Name Spotify -ErrorAction SilentlyContinue)) {
        Start-Sleep -Milliseconds 100
    }

    Write-Host -ForegroundColor Blue 'Arret de Spotify...Encore'
    Write-Host ""
    Stop-Process -Name Spotify
    Stop-Process -Name SpotifyWebHelper
    if ([Environment]::Is64BitOperatingSystem) {
        Stop-Process -Name SpotifyFullSetupX64
    } else {
        Stop-Process -Name SpotifyFullSetup
    }
}

Write-Host -ForegroundColor Blue "Telechargement du dernier correctif (chrome_elf.zip)...`n"
Write-Host ""
$elfPath = Join-Path -Path $PWD -ChildPath 'chrome_elf.zip'
try {
    $bytes = [System.IO.File]::ReadAllBytes($spotifyExecutable)
    $peHeader = [System.BitConverter]::ToUInt16($bytes[0x3C..0x3D], 0)
    $is64Bit = $bytes[$peHeader + 4] -eq 0x64

    $uri = if ($is64Bit) { 'https://github.com/mrpond/BlockTheSpot/releases/latest/download/chrome_elf.zip' } else {
        Write-Host -ForegroundColor Red 'Pour le moment, le bloqueur de publicite peut ne pas fonctionner correctement car l''architecture x86 n''a pas recu de nouvelle mise a jour.'
        Write-Host ""
        'https://github.com/mrpond/BlockTheSpot/releases/download/2023.5.20.80/chrome_elf.zip'
    }

    Get-File -Uri $uri -TargetFile $elfPath
} catch {
    Write-Output $_
    Start-Sleep
}

Expand-Archive -Force -LiteralPath $elfPath -DestinationPath $PWD
Remove-Item -LiteralPath $elfPath -Force

Write-Host -ForegroundColor Blue 'Correction de Spotify...'
Write-Host ""

$patchFiles = (Join-Path -Path $PWD -ChildPath 'dpapi.dll'), (Join-Path -Path $PWD -ChildPath 'config.ini')

Copy-Item -LiteralPath $patchFiles -Destination $spotifyDirectory

function Install-VcRedist {
    $vcRedistX86Url = "https://aka.ms/vs/17/release/vc_redist.x86.exe"
    $vcRedistX64Url = "https://aka.ms/vs/17/release/vc_redist.x64.exe"

    if ([Environment]::Is64BitOperatingSystem) {
        if (!(Test-Path 'HKLM:\Software\Microsoft\VisualStudio\14.0\VC\Runtimes\x64')) {
            $vcRedistX64File = Join-Path -Path $PWD -ChildPath 'vc_redist.x64.exe'
            Write-Host -ForegroundColor Blue "Telechargement et installation de vc_redist.x64.exe..."
            Write-Host ""
            Get-File -Uri $vcRedistX64Url -TargetFile $vcRedistX64File
            Start-Process -FilePath $vcRedistX64File -ArgumentList "/install /quiet /norestart" -Wait
        }
    } else {
        if (!(Test-Path 'HKLM:\Software\Microsoft\VisualStudio\14.0\VC\Runtimes\x86')) {
            $vcRedistX86File = Join-Path -Path $PWD -ChildPath 'vc_redist.x86.exe'
            Write-Host -ForegroundColor Blue "Telechargement et installation de vc_redist.x86.exe..."
            Write-Host ""
            Get-File -Uri $vcRedistX86Url -TargetFile $vcRedistX86File
            Start-Process -FilePath $vcRedistX86File -ArgumentList "/install /quiet /norestart" -Wait
        }
    }
}

Install-VcRedist

$tempDirectory = $PWD
Pop-Location

Remove-Item -LiteralPath $tempDirectory -Recurse

Write-Host -ForegroundColor Green 'Correction terminee, demarrage de Spotify...'
Write-Host ""

Start-Process -WorkingDirectory $spotifyDirectory -FilePath $spotifyExecutable

Write-Host -ForegroundColor Green 'Fait.'
Write-Host ""

# Ajout d'une pause a la fin du script pour permettre a l'utilisateur de voir les messages
Read-Host 'Script termine. Appuyez sur une touche pour fermer cette fenetre...'
exit
