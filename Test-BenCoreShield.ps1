# Read-only first-run verification. Does not trigger antivirus scans or write settings.
$ErrorActionPreference='Continue'
Write-Host 'BenCore Shield v1.0 | Diagnostics' -ForegroundColor Cyan
Write-Host 'Developer: Benie Mansueto Vison'
Write-Host ('PowerShell version: '+$PSVersionTable.PSVersion.ToString())
$needed=@('BenCoreShield.ps1','BenCoreShield.UI.xaml','BenCoreShield.Engine.psm1','BenCoreShield.Worker.ps1')
$errors=0
foreach($file in $needed) {
    if(Test-Path -LiteralPath (Join-Path $PSScriptRoot $file)){ Write-Host "[PASS] $file" -ForegroundColor Green }
    else {Write-Host "[FAIL] Missing $file" -ForegroundColor Red;$errors++}
}
if($PSVersionTable.PSVersion.Major -lt 5){Write-Host '[FAIL] Windows PowerShell 5.1 recommended.' -ForegroundColor Red;$errors++}
$tokens=$null; $parseErrors=$null
foreach($file in @('BenCoreShield.ps1','BenCoreShield.Worker.ps1','BenCoreShield.Engine.psm1')) {
    $path=Join-Path $PSScriptRoot $file
    if(Test-Path -LiteralPath $path){
        $null=[System.Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$parseErrors)
        if($parseErrors.Count){foreach($e in $parseErrors){Write-Host "[FAIL] $file : $($e.Message)" -ForegroundColor Red};$errors++}
        else {Write-Host "[PASS] PowerShell syntax: $file" -ForegroundColor Green}
    }
}
try{
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase -ErrorAction Stop
    [xml]$xaml=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'BenCoreShield.UI.xaml') -Raw -Encoding UTF8
    $reader=New-Object System.Xml.XmlNodeReader($xaml)
    $win=[Windows.Markup.XamlReader]::Load($reader)
    if($null -eq $win){throw 'Empty XAML result'}
    Write-Host '[PASS] WPF XAML loaded.' -ForegroundColor Green
    $win.Close()
}catch{Write-Host "[FAIL] WPF XAML: $($_.Exception.Message)" -ForegroundColor Red;$errors++}
foreach($cmd in 'Get-MpComputerStatus','Get-MpThreatDetection','Start-MpScan','Update-MpSignature','Get-AuthenticodeSignature','Get-CimInstance'){
    $found=[bool](Get-Command $cmd -ErrorAction SilentlyContinue)
    if($found){Write-Host "[PASS] Available: $cmd" -ForegroundColor Green}
    else{Write-Host "[WARN] Unavailable: $cmd" -ForegroundColor Yellow}
}
Write-Host ''
if($errors){Write-Host "Diagnostics found $errors error(s). Do not deploy until corrected." -ForegroundColor Red;exit 1}
Write-Host 'Basic checks passed. No scans, settings changes, or Windows modifications were performed.' -ForegroundColor Green
Write-Host 'Windows 11 UI integration and scanner behavior still need real-device validation.' -ForegroundColor Yellow
