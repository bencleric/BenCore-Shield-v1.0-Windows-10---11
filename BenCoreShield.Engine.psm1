# BenCore Shield - read-only audit helpers. No remediation, deletes, registry edits or exclusions.
Set-StrictMode -Version 2

function Get-BCSDataRoot {
    $root = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'BenCoreShield'
    if (-not (Test-Path -LiteralPath $root)) { [void](New-Item -ItemType Directory -Path $root -Force) }
    return $root
}

function Get-BCSDefenderStatus {
    $s = [ordered]@{ Available=$false; AntivirusEnabled=$null; RealTimeProtectionEnabled=$null; Signatures='Unknown'; SignatureUpdated='Unknown'; QuickScan='Unknown'; FullScan='Unknown'; Note='Microsoft Defender status unavailable or inaccessible.' }
    if (-not (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)) { return [pscustomobject]$s }
    try {
        $v = Get-MpComputerStatus -ErrorAction Stop
        $s.Available = $true
        $s.AntivirusEnabled = [bool]$v.AntivirusEnabled
        $s.RealTimeProtectionEnabled = [bool]$v.RealTimeProtectionEnabled
        $s.Signatures = [string]$v.AntivirusSignatureVersion
        if ($v.AntivirusSignatureLastUpdated) { $s.SignatureUpdated = [string]$v.AntivirusSignatureLastUpdated }
        if ($v.QuickScanEndTime) { $s.QuickScan = [string]$v.QuickScanEndTime }
        if ($v.FullScanEndTime) { $s.FullScan = [string]$v.FullScanEndTime }
        $s.Note = if ($v.AntivirusEnabled) { 'Defender reporting is accessible.' } else { 'Defender antivirus is not active; another AV product may be installed.' }
    } catch { $s.Note = "Cannot read Defender: $($_.Exception.Message)" }
    return [pscustomobject]$s
}

function Get-BCSSignature {
    param([string]$Path, [hashtable]$Cache)
    if ([string]::IsNullOrWhiteSpace($Path)) { return 'Unavailable' }
    if ($Cache.ContainsKey($Path)) { return $Cache[$Path] }
    $result = 'Unavailable'
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
            $result = [string]$sig.Status
        }
    } catch { $result = 'Unavailable' }
    $Cache[$Path] = $result
    return $result
}

function Resolve-BCSExecutable {
    param([string]$CommandLine)
    if ([string]::IsNullOrWhiteSpace($CommandLine)) { return '' }
    $value = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    $value = $value -replace '^\\SystemRoot\\', "${env:windir}\\"
    $value = $value -replace '^\\\?\?\\', ''
    if ($value -match '^\s*"([^"]+\.(?:exe|dll|sys|com))"') { return $Matches[1] }
    if ($value -match '^\s*([^"\r\n]+?\.(?:exe|dll|sys|com))(?=\s|$)') { return $Matches[1].Trim() }
    if ($value -match '^\s*"([^"]+)"') { return $Matches[1] }
    return ''
}

function Get-BCSAssessment {
    param([string]$Name,[string]$Path,[string]$Signature,[string]$Kind)
    $reasons = New-Object System.Collections.Generic.List[string]
    $risk='Informational'
    if (-not $Path) { return [pscustomobject]@{Risk='Unknown'; Reason='Executable path not accessible; cannot assess.'} }
    $p = $Path.ToLowerInvariant().Replace('/','\')
    $userLocation = ($p -match '\\appdata\\local\\temp\\|\\windows\\temp\\|\\users\\public\\|\\downloads\\')
    $masquerade = ($Name -match '^(?:svchost|lsass|services|winlogon|csrss|smss|dwm|explorer)(?:\.exe)?$') -and
        -not ($p.StartsWith(($env:windir.TrimEnd('\')+'\').ToLowerInvariant()))
    if ($userLocation) { [void]$reasons.Add('Executable runs from a temporary, public, or download folder.') }
    if ($masquerade) { [void]$reasons.Add('Name resembles a Windows component but file is outside the Windows folder.') }
    if (($Signature -ne 'Valid') -and $userLocation) { [void]$reasons.Add('Executable is not verified as signed and runs from a writable location.') }
    if ($masquerade -or (($Signature -ne 'Valid') -and $userLocation)) { $risk='Review' }
    if ($Kind -eq 'Service' -and $userLocation) { $risk='Review' }
    if ($reasons.Count -eq 0) {
        if ($Signature -eq 'Valid') { [void]$reasons.Add('Valid signature; this does not guarantee safety.') }
        elseif ($Signature -eq 'NotSigned') { [void]$reasons.Add('Unsigned executable; many legitimate programs are unsigned.') }
        else { [void]$reasons.Add('No high-signal location rule matched; not a malware clearance.') }
    }
    return [pscustomobject]@{Risk=$risk;Reason=($reasons -join ' ')}
}

function New-BCSRecord {
    param([string]$Category,[string]$Name,[string]$Identifier,[string]$Path,[hashtable]$Cache,[string]$Extra='')
    $signature=Get-BCSSignature -Path $Path -Cache $Cache
    $assessment=Get-BCSAssessment -Name $Name -Path $Path -Signature $signature -Kind $Category
    return [pscustomobject]@{
        Category=$Category; Name=$Name; Identifier=$Identifier; Risk=$assessment.Risk
        Signature=$signature; Path=$Path; Reason=$assessment.Reason; Details=$Extra
    }
}

function Get-BCSProcesses {
    param([hashtable]$Cache)
    $items = New-Object System.Collections.Generic.List[object]
    $procs = @(Get-CimInstance Win32_Process -ErrorAction Stop)
    foreach ($p in $procs) {
        $path = [string]$p.ExecutablePath
        $rec=New-BCSRecord -Category 'Process' -Name ([string]$p.Name) -Identifier ([string]$p.ProcessId) -Path $path -Cache $Cache -Extra "Parent PID: $($p.ParentProcessId)"
        [void]$items.Add($rec)
    }
    return $items.ToArray()
}

function Get-BCSServices {
    param([hashtable]$Cache)
    $items = New-Object System.Collections.Generic.List[object]
    $svcs = @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object { $_.State -eq 'Running' })
    foreach ($svc in $svcs) {
        $path=Resolve-BCSExecutable -CommandLine ([string]$svc.PathName)
        $rec=New-BCSRecord -Category 'Service' -Name ([string]$svc.Name) -Identifier ([string]$svc.ProcessId) -Path $path -Cache $Cache -Extra ("Display: {0} | Start: {1} | Account: {2}" -f $svc.DisplayName, $svc.StartMode, $svc.StartName)
        [void]$items.Add($rec)
    }
    return $items.ToArray()
}

function Get-BCSStartup {
    param([hashtable]$Cache)
    $items=New-Object System.Collections.Generic.List[object]
    $keys=@(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach($key in $keys){
        try {
            if(-not (Test-Path -LiteralPath $key)) {continue}
            $props=Get-ItemProperty -LiteralPath $key -ErrorAction Stop
            foreach($prop in $props.PSObject.Properties){
                if($prop.Name -match '^PS(?:Path|ParentPath|ChildName|Drive|Provider)$'){continue}
                $cmd=[string]$prop.Value
                $path=Resolve-BCSExecutable -CommandLine $cmd
                $rec=New-BCSRecord -Category 'Startup' -Name $prop.Name -Identifier $key -Path $path -Cache $Cache -Extra $cmd
                [void]$items.Add($rec)
            }
        } catch { continue }
    }
    try {
        foreach($task in @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' })){
            foreach($action in @($task.Actions)){
                if($null -eq $action -or -not $action.Execute){continue}
                $cmd=[string]$action.Execute
                $path=Resolve-BCSExecutable -CommandLine $cmd
                if (-not $path -and (Test-Path -LiteralPath $cmd -PathType Leaf -ErrorAction SilentlyContinue)) { $path=$cmd }
                $rec=New-BCSRecord -Category 'Scheduled task' -Name $task.TaskName -Identifier $task.TaskPath -Path $path -Cache $Cache -Extra ("Execute: {0} {1}" -f $cmd, $action.Arguments)
                [void]$items.Add($rec)
            }
        }
    } catch { }
    return $items.ToArray()
}

function Get-BCSDefenderHistory {
    $items=New-Object System.Collections.Generic.List[object]
    if(-not (Get-Command Get-MpThreatDetection -ErrorAction SilentlyContinue)){return $items.ToArray()}
    $codes=@{ '0'='Unknown'; '1'='Detected'; '2'='Cleaned'; '3'='Quarantined'; '4'='Removed'; '5'='Allowed'; '6'='Blocked'; '101'='Clean failed'; '102'='Quarantine failed'; '103'='Remove failed'; '104'='Allow failed'; '105'='Abandoned'; '107'='Block failed' }
    try {
        $threats = @(Get-MpThreatDetection -ErrorAction Stop | Sort-Object InitialDetectionTime -Descending | Select-Object -First 60)
        foreach($t in $threats) {
            $code=[string]$t.ThreatStatusID
            $status=if($codes.ContainsKey($code)){$codes[$code]}else{"Status $code"}
            $risk=if($code -in @('1','5','101','102','103','104','105','107')){'Defender attention'}else{'History'}
            [void]$items.Add([pscustomobject]@{Category='Defender detection'; Name=("Threat ID {0}" -f $t.ThreatID); Identifier=[string]$t.DetectionID; Risk=$risk;Signature='Defender';Path=(@($t.Resources) -join '; '); Reason=("Defender reported: {0}; review Windows Security Protection history." -f $status);Details=("Detected: {0}; Last change: {1}; Action succeeded: {2}" -f $t.InitialDetectionTime,$t.LastThreatStatusChangeTime,$t.ActionSuccess)})
        }
    } catch {
        [void]$items.Add([pscustomobject]@{Category='Audit notice';Name='Defender detection history unavailable';Identifier='';Risk='Unknown';Signature='Unavailable';Path='';Reason=$_.Exception.Message;Details='Open Windows Security > Protection history.'})
    }
    return $items.ToArray()
}

function Get-BCSOverview {
    $d=Get-BCSDefenderStatus
    $os=Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    return [pscustomobject]@{
        Computer=$env:COMPUTERNAME; Defender=$d
        RAMGB=if($os){[math]::Round($os.TotalVisibleMemorySize / 1MB,1)}else{0}
        FreeGB=if($os){[math]::Round($os.FreePhysicalMemory / 1MB,1)}else{0}
        Timestamp=(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    }
}

Export-ModuleMember -Function Get-BCSDataRoot,Get-BCSDefenderStatus,Get-BCSProcesses,Get-BCSServices,Get-BCSStartup,Get-BCSDefenderHistory,Get-BCSOverview
