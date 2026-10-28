# BenCore Shield v1.0 -- PowerShell 5.1 / WPF controller
# Protect the Core. Secure the System. | Developed by Benie Mansueto Vison
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
if ($env:OS -ne 'Windows_NT') { throw 'BenCore Shield requires Windows 11.' }
if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { throw 'Start the app using Start-BenCoreShield.cmd (STA required).' }
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase
Add-Type -AssemblyName System.Windows.Forms
Import-Module (Join-Path $PSScriptRoot 'BenCoreShield.Engine.psm1') -Force
[xml]$xaml=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'BenCoreShield.UI.xaml') -Raw -Encoding UTF8
$reader=New-Object System.Xml.XmlNodeReader($xaml)
$script:Window=[Windows.Markup.XamlReader]::Load($reader)
$script:Controls=@{}
$names=@(
    'NavHome','NavProcesses','NavServices','NavStartup','NavDetections','NavAbout',
    'PageHome','PageProcesses','PageServices','PageStartup','PageDetections','PageAbout',
    'BtnAudit','BtnQuick','BtnFull','BtnUpdate','BtnOffline','BtnWindowsSecurity','BtnRefresh',
    'BtnProcessFolder','BtnProcessHash','BtnServiceFolder','BtnServiceHash','BtnHistorySecurity',
    'BtnOpenReports','BtnExport','TxtComputer','TxtProtection','TxtSignatures',
    'TxtProcessCount','TxtServiceCount','TxtReviewCount','TxtLastScan','TxtStatus',
    'GridFindings','GridProcesses','GridServices','GridStartup','GridDetections'
)
foreach ($name in $names) {
    $ctl=$script:Window.FindName($name)
    if($null -eq $ctl) {throw "XAML control not found: $name"}
    $script:Controls[$name]=$ctl
}
$script:LastAudit=$null
$script:LastResult=$null
$script:LastResultPath=''
$script:CurrentProcess=$null
$script:CurrentJobDir=''
$script:LastStateText=''
$script:Pages=@('Home','Processes','Services','Startup','Detections','About')
$script:ScanButtons=@('BtnAudit','BtnQuick','BtnFull','BtnUpdate')
$script:Timer=New-Object System.Windows.Threading.DispatcherTimer
$script:Timer.Interval=[timespan]::FromMilliseconds(1350)
$script:Timer.IsEnabled=$false

function Set-BCSStatusText([string]$value) { $script:Controls['TxtStatus'].Text=$value }

function Show-BCSNotice([string]$message,[string]$title='BenCore Shield') {
    [void][System.Windows.MessageBox]::Show($script:Window,$message,$title,'OK','Information')
}

function Show-BCSError([string]$message) {
    Set-BCSStatusText "Error: $message"
    [void][System.Windows.MessageBox]::Show($script:Window,$message,'BenCore Shield - issue encountered','OK','Warning')
}

function Show-BCSPage([string]$page) {
    foreach($name in $script:Pages){
        $active=$name -eq $page
        $script:Controls['Page'+$name].Visibility=if($active){[System.Windows.Visibility]::Visible}else{[System.Windows.Visibility]::Collapsed}
        $button=$script:Controls['Nav'+$name]
        $button.Background=([System.Windows.Media.BrushConverter]::new()).ConvertFromString($(if($active){'#264B64'}else{'#101E32'}))
        $button.Foreground=([System.Windows.Media.BrushConverter]::new()).ConvertFromString($(if($active){'#FFFFFF'}else{'#B8CAE0'}))
    }
}

function Refresh-BCSProtection {
    try {
        $data=Get-BCSOverview
        $script:Controls['TxtComputer'].Text="$($data.Computer)  |  RAM: $($data.RAMGB) GB, free: $($data.FreeGB) GB  |  Local inspection"
        $d=$data.Defender
        $script:Controls['TxtProtection'].Text=if(-not $d.Available){'Unavailable'}elseif($d.AntivirusEnabled -and $d.RealTimeProtectionEnabled){'Active'}elseif($d.AntivirusEnabled){'Check status'}else{'Not active'}
        $script:Controls['TxtSignatures'].Text="Signatures: $($d.Signatures)"
    } catch {Set-BCSStatusText "Could not refresh Defender status: $($_.Exception.Message)"}
}

function Update-BCSCounts {
    if ($null -eq $script:LastAudit) {return}
    $a=$script:LastAudit
    $script:Controls['TxtProcessCount'].Text=[string]@($a.Processes).Count
    $script:Controls['TxtServiceCount'].Text=[string]@($a.Services).Count
    $review=@(@($a.Processes)+@($a.Services)+@($a.Startup) | Where-Object {$_.Risk -eq 'Review'})
    $script:Controls['TxtReviewCount'].Text=[string]$review.Count
    $script:Controls['GridProcesses'].ItemsSource=@($a.Processes)
    $script:Controls['GridServices'].ItemsSource=@($a.Services)
    $script:Controls['GridStartup'].ItemsSource=@($a.Startup)
    $script:Controls['TxtLastScan'].Text="Last local audit: $($a.Finished)  |  $($a.Status)  |  $(@($a.Startup).Count) startup/task entries"
}

function Update-BCSResults {
    if($null -eq $script:LastResult){return}
    $r=$script:LastResult
    if($r.Mode -eq 'Audit') { $script:LastAudit=$r; Update-BCSCounts }
    $detections=@($r.Detections)
    $script:Controls['GridDetections'].ItemsSource=$detections
    $findings=New-Object System.Collections.Generic.List[object]
    foreach ($d in @($detections | Where-Object { $_.Risk -eq 'Defender attention' })){[void]$findings.Add($d)}
    if($null -ne $script:LastAudit){
        foreach($record in @(@($script:LastAudit.Processes)+@($script:LastAudit.Services)+@($script:LastAudit.Startup) | Where-Object {$_.Risk -eq 'Review'} | Select-Object -First 60)){
            [void]$findings.Add($record)
        }
    }
    foreach ($d in @($detections | Where-Object { $_.Risk -eq 'History' } | Select-Object -First 10)){[void]$findings.Add($d)}
    $script:Controls['GridFindings'].ItemsSource=$findings.ToArray()
    if(@($r.Warnings).Count){
        $notice=(@($r.Warnings) -join ' | ')
        Set-BCSStatusText "$($r.Status): $notice"
    } else {Set-BCSStatusText "$($r.Mode) finished. Check Windows Security to interpret confirmed malware findings."}
}

function Set-BCSButtonsEnabled([bool]$enabled) {
    foreach ($name in $script:ScanButtons) { $script:Controls[$name].IsEnabled=$enabled }
}

function Start-BCSWorker([ValidateSet('Audit','Quick','Full','Update')][string]$mode) {
    if($null -ne $script:CurrentProcess){ Show-BCSNotice 'An inspection or scan is already running. Finish it before starting another.'; return }
    if($mode -eq 'Full') {
        $choice=[System.Windows.MessageBox]::Show($script:Window,'A full Defender scan can run for a long time and impact PC performance. Start it now?','Start full scan?','YesNo','Question')
        if($choice -ne 'Yes'){return}
    }
    if($mode -eq 'Update'){
        $choice=[System.Windows.MessageBox]::Show($script:Window,'Request an update of Microsoft Defender security intelligence? An internet connection may be required.','Update Defender','YesNo','Question')
        if($choice -ne 'Yes'){return}
    }
    try{
        $jobs=Join-Path (Get-BCSDataRoot) 'Jobs'
        [void](New-Item -ItemType Directory -Path $jobs -Force)
        $dir=Join-Path $jobs ((Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
        [void](New-Item -ItemType Directory -Path $dir -Force)
        $worker=Join-Path $PSScriptRoot 'BenCoreShield.Worker.ps1'
        if($worker.Contains('"') -or $dir.Contains('"')){throw 'Unsupported quote character in installation or user folder path.'}
        $powerShell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $arguments='-NoLogo -NoProfile -ExecutionPolicy Bypass -File "{0}" -Mode {1} -JobDirectory "{2}"' -f $worker,$mode,$dir
        $script:CurrentJobDir=$dir
        $script:CurrentProcess=Start-Process -FilePath $powerShell -ArgumentList $arguments -WindowStyle Hidden -PassThru -ErrorAction Stop
        Set-BCSButtonsEnabled $false
        $script:Timer.Start()
        Set-BCSStatusText "$mode in progress. The dashboard stays responsive."
    } catch { $script:CurrentProcess=$null; Set-BCSButtonsEnabled $true; Show-BCSError $_.Exception.Message }
}

function Complete-BCSWorker {
    $script:Timer.Stop()
    $script:CurrentProcess.Dispose()
    $script:CurrentProcess=$null
    Set-BCSButtonsEnabled $true
    $path=Join-Path $script:CurrentJobDir 'result.json'
    if(-not (Test-Path -LiteralPath $path)) {Show-BCSError 'The scan process ended without a report. Try Run-Diagnostics.cmd or inspect the local Jobs folder.';return}
    try {
        $r=Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        $script:LastResult=$r
        $script:LastResultPath=$path
        Update-BCSResults
        Refresh-BCSProtection
    } catch {Show-BCSError "Could not read completed report: $($_.Exception.Message)"}
}

$script:Timer.Add_Tick({
    if($null -eq $script:CurrentProcess){return}
    try {
        $statusFile=Join-Path $script:CurrentJobDir 'status.json'
        if(Test-Path -LiteralPath $statusFile){
            try {
                $progress=Get-Content -LiteralPath $statusFile -Raw -Encoding UTF8 | ConvertFrom-Json
                $message="$($progress.State): $($progress.Message)"
                if($script:LastStateText -ne $message){$script:LastStateText=$message;Set-BCSStatusText $message}
            }catch{} # Ignore momentary status-file replacement race.
        }
        if($script:CurrentProcess.HasExited) {Complete-BCSWorker}
    } catch { $script:Timer.Stop();Set-BCSButtonsEnabled $true; $script:CurrentProcess=$null;Show-BCSError $_.Exception.Message }
})

function Open-BCSLocation([string]$gridName) {
    $rec=$script:Controls[$gridName].SelectedItem
    if($null -eq $rec){Show-BCSNotice 'Select a record first.';return}
    $path=[string]$rec.Path
    if(-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)){Show-BCSNotice 'The executable path is not available or cannot be accessed.';return}
    try{Start-Process -FilePath 'explorer.exe' -ArgumentList ('/select,"'+$path+'"') -ErrorAction Stop}
    catch{Show-BCSError $_.Exception.Message}
}

function Copy-BCSHash([string]$gridName) {
    $rec=$script:Controls[$gridName].SelectedItem
    if($null -eq $rec){Show-BCSNotice 'Select a record first.';return}
    $path=[string]$rec.Path
    if(-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)){Show-BCSNotice 'The executable path is not available or cannot be accessed.';return}
    try{
        $hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash
        [System.Windows.Clipboard]::SetText($hash)
        Show-BCSNotice "SHA-256 copied to clipboard:`n$hash`n`nA hash alone is not a malware verdict."
    }catch{Show-BCSError "Cannot hash file: $($_.Exception.Message)"}
}

function Open-BCSSecurity {
    try {Start-Process 'windowsdefender:' -ErrorAction Stop}
    catch {Show-BCSError 'Unable to open Windows Security. Search for Windows Security from Start.'}
}

function Show-BCSOfflineGuide {
    $msg="For suspected rootkits or deeply persistent malware, use Microsoft Defender Offline Scan.`n`n"+
         "1. Save all files and close running applications.`n"+
         "2. Open Windows Security > Virus & threat protection > Scan options.`n"+
         "3. Choose Microsoft Defender Antivirus (offline scan), then Scan now.`n"+
         "4. Windows will restart. Check Protection history after it finishes.`n`n"+
         "The dashboard cannot detect kernel rootkits itself, and no scanner guarantees a clean PC.`n`nOpen Windows Security now?"
    $response=[System.Windows.MessageBox]::Show($script:Window,$msg,'BenCore Shield - Offline scan guidance','YesNo','Warning')
    if($response -eq 'Yes'){Open-BCSSecurity}
}

function Export-BCSReport {
    if(-not $script:LastResultPath -or -not (Test-Path -LiteralPath $script:LastResultPath)){Show-BCSNotice 'Run an audit or Defender scan first. No report is available yet.';return}
    try{
        $dlg=New-Object Microsoft.Win32.SaveFileDialog
        $dlg.Title='Export BenCore Shield report (contains local file paths)'
        $dlg.FileName='BenCoreShield-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.json'
        $dlg.Filter='JSON reports (*.json)|*.json'
        if($dlg.ShowDialog($script:Window) -eq $true){
            Copy-Item -LiteralPath $script:LastResultPath -Destination $dlg.FileName -Force
            Show-BCSNotice 'Report saved. Review paths, usernames and detected threat details before sharing it.'
        }
    } catch{Show-BCSError $_.Exception.Message}
}

$script:Controls['NavHome'].Add_Click({Show-BCSPage 'Home'})
$script:Controls['NavProcesses'].Add_Click({Show-BCSPage 'Processes'})
$script:Controls['NavServices'].Add_Click({Show-BCSPage 'Services'})
$script:Controls['NavStartup'].Add_Click({Show-BCSPage 'Startup'})
$script:Controls['NavDetections'].Add_Click({Show-BCSPage 'Detections'})
$script:Controls['NavAbout'].Add_Click({Show-BCSPage 'About'})
$script:Controls['BtnAudit'].Add_Click({Start-BCSWorker 'Audit'})
$script:Controls['BtnQuick'].Add_Click({Start-BCSWorker 'Quick'})
$script:Controls['BtnFull'].Add_Click({Start-BCSWorker 'Full'})
$script:Controls['BtnUpdate'].Add_Click({Start-BCSWorker 'Update'})
$script:Controls['BtnRefresh'].Add_Click({Refresh-BCSProtection;Set-BCSStatusText 'Status refreshed. An audit is not automatic.'})
$script:Controls['BtnOffline'].Add_Click({Show-BCSOfflineGuide})
$script:Controls['BtnWindowsSecurity'].Add_Click({Open-BCSSecurity})
$script:Controls['BtnHistorySecurity'].Add_Click({Open-BCSSecurity})
$script:Controls['BtnProcessFolder'].Add_Click({Open-BCSLocation 'GridProcesses'})
$script:Controls['BtnServiceFolder'].Add_Click({Open-BCSLocation 'GridServices'})
$script:Controls['BtnProcessHash'].Add_Click({Copy-BCSHash 'GridProcesses'})
$script:Controls['BtnServiceHash'].Add_Click({Copy-BCSHash 'GridServices'})
$script:Controls['BtnExport'].Add_Click({Export-BCSReport})
$script:Controls['BtnOpenReports'].Add_Click({
    try {Start-Process -FilePath 'explorer.exe' -ArgumentList ('"'+(Get-BCSDataRoot)+'"')}catch{Show-BCSError $_.Exception.Message}
})
$script:Window.Add_Closing({
    param($sender, $eventArgs)
    if($null -ne $script:CurrentProcess -and -not $script:CurrentProcess.HasExited){
        $r=[System.Windows.MessageBox]::Show($script:Window,'A scan/audit is still running. Closing this window does not stop Microsoft Defender. The background worker may finish writing its report. Close the dashboard anyway?','Scan still running','YesNo','Warning')
        if($r -ne 'Yes'){$eventArgs.Cancel=$true}
    }
})
Show-BCSPage 'Home'
Refresh-BCSProtection
Set-BCSStatusText 'Ready. Choose Audit or start a Microsoft Defender scan. No automatic removal.'
[void]$script:Window.ShowDialog()
