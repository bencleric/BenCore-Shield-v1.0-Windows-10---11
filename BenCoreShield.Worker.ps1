# Isolated foreground-service worker. Runs as a child of the desktop app; no self-elevation.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Audit','Quick','Full','Update')][string]$Mode,
    [Parameter(Mandatory)][string]$JobDirectory
)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'BenCoreShield.Engine.psm1') -Force
$root=Join-Path (Get-BCSDataRoot) 'Jobs'
$expectedRoot=[System.IO.Path]::GetFullPath($root).TrimEnd('\') + '\'
$resolved=[System.IO.Path]::GetFullPath($JobDirectory)
if(-not $resolved.StartsWith($expectedRoot,[StringComparison]::OrdinalIgnoreCase)) {throw 'Invalid job directory.'}
[void](New-Item -ItemType Directory -Path $resolved -Force)
$statePath=Join-Path $resolved 'status.json'
$resultPath=Join-Path $resolved 'result.json'

function Write-BCSStatus([string]$State,[string]$Message){
    $obj=[ordered]@{ State=$State; Message=$Message; Updated=(Get-Date).ToString('o') }
    $temp=Join-Path $resolved ('status-'+[guid]::NewGuid().ToString('N')+'.tmp')
    $obj | ConvertTo-Json | Set-Content -LiteralPath $temp -Encoding UTF8
    Move-Item -LiteralPath $temp -Destination $statePath -Force
}

$record=[ordered]@{Mode=$Mode; Started=(Get-Date).ToString('o'); Finished=''; Status='Incomplete'; Processes=@(); Services=@(); Startup=@(); Detections=@(); Warnings=@(); DefenderBefore=$null; DefenderAfter=$null}
try {
    Write-BCSStatus 'Running' "Starting $Mode..."
    $record.DefenderBefore=Get-BCSDefenderStatus
    if($Mode -eq 'Audit'){
        $cache=@{}
        Write-BCSStatus 'Running' 'Checking running processes and file signatures...'
        try { $record.Processes=@(Get-BCSProcesses -Cache $cache) } catch { $record.Warnings+=('Process inventory incomplete: '+$_.Exception.Message) }
        Write-BCSStatus 'Running' 'Checking running Windows services...'
        try { $record.Services=@(Get-BCSServices -Cache $cache) } catch { $record.Warnings+=('Service inventory incomplete: '+$_.Exception.Message) }
        Write-BCSStatus 'Running' 'Reviewing startup entries and scheduled tasks...'
        try { $record.Startup=@(Get-BCSStartup -Cache $cache) } catch { $record.Warnings+=('Startup inventory incomplete: '+$_.Exception.Message) }
        Write-BCSStatus 'Running' 'Reading Defender detection history...'
        $record.Detections=@(Get-BCSDefenderHistory)
    } else {
        if(-not $record.DefenderBefore.Available -or -not $record.DefenderBefore.AntivirusEnabled) {
            throw 'Microsoft Defender Antivirus is not active or unavailable. Check Windows Security or your installed antivirus.'
        }
        if($Mode -eq 'Quick') {
            if(-not (Get-Command Start-MpScan -ErrorAction SilentlyContinue)){throw 'Start-MpScan is unavailable.'}
            Write-BCSStatus 'Running' 'Microsoft Defender quick scan running. Duration varies; results come from Defender.'
            Start-MpScan -ScanType QuickScan -ErrorAction Stop
        } elseif($Mode -eq 'Full') {
            if(-not (Get-Command Start-MpScan -ErrorAction SilentlyContinue)){throw 'Start-MpScan is unavailable.'}
            Write-BCSStatus 'Running' 'Microsoft Defender full scan running; this could take substantial time.'
            Start-MpScan -ScanType FullScan -ErrorAction Stop
        } else {
            if(-not (Get-Command Update-MpSignature -ErrorAction SilentlyContinue)){throw 'Update-MpSignature is unavailable.'}
            Write-BCSStatus 'Running' 'Requesting latest Microsoft Defender security intelligence...'
            Update-MpSignature -ErrorAction Stop
        }
        $record.Detections=@(Get-BCSDefenderHistory)
    }
    $record.DefenderAfter=Get-BCSDefenderStatus
    $record.Status=if($record.Warnings.Count){'Partial'}else{'Complete'}
    Write-BCSStatus $record.Status "$Mode finished. See results and Windows Security for confirmed threat status."
} catch {
    $record.Status='Failed'
    $record.Warnings+=($_.Exception.Message)
    Write-BCSStatus 'Failed' $_.Exception.Message
} finally {
    $record.Finished=(Get-Date).ToString('o')
    $record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $resultPath -Encoding UTF8
}
