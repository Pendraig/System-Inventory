<# 

Ownership:

This script is the property of William John (Bill) Hamill. Unauthorized copying, distribution, or use of this script is prohibited.

Synopsis:

Collects detailed system inventory information, including GPU properties, storage capacity, Windows features, Server Roles, network adapters, 
ISP details, antivirus details, PowerShell & .NET Framework versions, browser URL associations, critical/error events, and updates/hotfixes.
Designed to be shared as 'System Inventory.txt' and run in PowerShell ISE using the instructions below.
Functional within PowerShell or VS Code Console when saved as a .ps1 file (e.g., System Inventory.ps1).

Instructions:

1) Download this text file | Open with Notepad.
2) Search for Windows PowerShell ISE | Right-click (Run as Administrator).

    Note: This script *must* be run as an administrator to work!

3) PowerShell ISE | View | Show Script Pane
4) Notepad | Control + A to select all text, then Control + C to copy it. 
5) PowerShell ISE | Script Pane | Control + V to paste the copied text from Notepad.
6) PowerShell ISE | File | Run. The results will be displayed on the screen and saved to your Downloads folder as "System Inventory - <ComputerName>.txt".

Disclaimer:

This script is provided "as is," without warranty of any kind. Use at your own risk. The author or distributor shall not be held liable 
for any damage or issues arising from the use of this script.

#>

# Define Error Handling, Line Breaks, Initialize Output File & Progress Bar

$ErrorActionPreference = "Stop"; $NewLine = "`n"; $SystemInventory = @(); $Global:TaskCount = 0; $Global:TotalTasks = 15

# Check elevation status, halt if not running as admin.

function Confirm-ElevationStatus {    
    if (-not ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))) {
        Hide-ISEScriptPane; Write-Host "This script must be run as an administrator to work!" -ForegroundColor Red; Write-Host
        exit 1
    }
}

# Bypass execution policy for the current PowerShell session only. Security will be restored to its previous state once this session is closed.

function Disable-ExecutionPolicy {
    $ExecutionContext.InvokeCommand.InvokeScript('Set-ExecutionPolicy Bypass -Scope Process')
}

# Hide the script pane in PowerShell ISE by simulating 'Ctrl + R' key press and clear the console screen

function Hide-ISEScriptPane {
    if ($host.Name -eq 'Windows PowerShell ISE Host') {
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.SendKeys]::SendWait("^r")
        Clear-Host
    }
}   

# Windows Product Key

function Get-WindowsProductKey {
    try {
        function Get-OSDigitalID($Key) {

            $KeyOffset = 52 
            $isWin8 = [Int]($Key[66] / 6) -bAND 1
            $HF7 = 0xF7
            $Key[66] = ($Key[66] -bAND $HF7) -bOR (($isWin8 -bAND 2) * 4)
            $i = 24
            [String]$Chars = 'BCDFGHJKMPQRTVWXY2346789'	
            do {
                $Current = 0 
                $j = 14
                do {
                    $Current = $Current * 256    
                    $Current = $Key[$j + $KeyOffset] + $Current
                    $Key[$j + $KeyOffset] = [math]::Floor([double]($Current / 24))
                    $Current = $Current % 24
                    $j = $j - 1 
                } while ($j -ge 0)
                $i = $i - 1
                $KeyOutput = $Chars.SubString($Current, 1) + $KeyOutput
                $Last = $Current
            } while ($i -ge 0)
            
            $KeyPart1 = $KeyOutput.SubString(1, $Last)
            $KeyPart2 = $KeyOutput.SubString(1, $KeyOutput.Length - 1)
            if ($Last -eq 0) {
                $KeyOutput = 'N' + $KeyPart2
            }
            else {
                $KeyOutput = $KeyPart2.Insert($KeyPart2.IndexOf($KeyPart1) + $KeyPart1.Length, 'N')
            }
            $a = $KeyOutput.SubString(0, 5)
            $b = $KeyOutput.SubString(5, 5)
            $c = $KeyOutput.SubString(10, 5)
            $d = $KeyOutput.SubString(15, 5)
            $e = $KeyOutput.SubString(20, 5)
            $KeyProduct = $a + '-' + $b + '-' + $c + '-' + $d + '-' + $e
            $KeyProduct 
        }
        
        $DigitalID = (Get-ItemPropertyValue 'HKLM:Software\Microsoft\Windows NT\CurrentVersion' -Name 'DigitalProductId')
        $ProductKey = Get-OSDigitalID $DigitalID    
        [PSCustomObject]@{ 'Product Key' = $ProductKey }   
    }
    catch {
        throw "An error occurred retrieving product key information: $($_.Exception.Message)"
    }
}

# Graphics Card Details

function Get-GpuProperties {
    try {
        $gpuProperties = Get-CimInstance -ClassName Win32_VideoController
        $gpuDetails = foreach ($gpu in $gpuProperties) {
            [PSCustomObject]@{
                'Device Name'         = $gpu.Name
                'Video RAM'           = [Math]::Round($gpu.AdapterRAM / 1MB, 2)
                'Driver Version'      = $gpu.DriverVersion
                'Install Date & Time' = $gpu.DriverDate
            } 
        }
        return $gpuDetails
    }   
    catch {
        throw "An error occurred while retrieving GPU properties: $($_.Exception.Message)"
    }
}

# Storage Capacity

function Get-FreeSpace {
    try {
        Get-CimInstance -Class Win32_LogicalDisk |
            Select-Object SystemName, DeviceID, VolumeName,
            @{ Name = "Free Space (GB)"; expression = { "{0:N2}" -f ($_.Freespace / 1GB) } },
            @{ Name = "Total Size (GB)"; expression = { "{0:N2}" -f ($_.Size / 1GB) } },
            @{ Name = "Free Space %"   ; expression = { "{0:N2}" -f (($_.Freespace / $_.Size) * 100) } }
    }
    catch {
        throw "An error occurred retrieving free space information: $($_.Exception.Message)"
    }
}

# Optional Windows Features\Active Server Roles

function Get-RolesAndFeatures {
    try {
        $CimSysType = (Get-CimInstance Win32_OperatingSystem).ProductType

        if ($CimSysType -eq 1) {
            $FeatureLabel = "# Windows Client - Active Optional Features"  
            $RolesAndFeatures = Get-WindowsOptionalFeature -Online | Where-Object State -EQ 'Enabled' | Select-Object FeatureName | Sort-Object FeatureName          
        }
        else { 
            $FeatureLabel = "# Windows Server - Installed Server Roles"
            $RolesAndFeatures = Get-WindowsFeature | Where-Object InstallState -EQ 'Installed' | Select-Object DisplayName             
        }
        return [PSCustomObject]@{
            FeatureLabel     = $FeatureLabel
            RolesAndFeatures = $RolesAndFeatures
        }
    }
    catch {
        throw "An error occurred retrieving roles and features: $($_.Exception.Message)"
    }
}

# .Net Properties

function Get-DotNetProperties {

    # Source:  https://stackoverflow.com/questions/3487265/powershell-script-to-return-versions-of-net-framework-on-a-machine

    try {
        # .NET Framework Lookup Table
        $Lookup = @{
            378389 = '4.5'
            378675 = '4.5.1'
            378758 = '4.5.1'
            379893 = '4.5.2'
            393295 = '4.6'
            393297 = '4.6'
            394254 = '4.6.1'
            394271 = '4.6.1'
            394802 = '4.6.2'
            394806 = '4.6.2'
            460798 = '4.7'
            460805 = '4.7'
            461308 = '4.7.1'
            461310 = '4.7.1'
            461808 = '4.7.2'
            461814 = '4.7.2'
            528040 = '4.8'
            528049 = '4.8'
            533320 = '4.8.1'
        }
    
        # Retrieve .NET Framework Versions
        $netFrameworkVersions = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse |
            Get-ItemProperty -Name Version, Release -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -eq "Full" } |
                    Select-Object @{ Name = "Client" ; Expression = { $_.PSChildName } },
                                  @{ Name = "Version"; Expression = { $Lookup[$_.Release] } }, 
                                  Release
    
        # Retrieve .NET Core Versions
        $dotNetCoreVersions = & "C:\Program Files\dotnet\dotnet.exe" --list-runtimes |
            ForEach-Object {
                $parts = $_ -split '\s+'
                [PSCustomObject]@{
                    'Client'  = $parts[0]
                    'Version' = $parts[1]
                    'Path'    = $parts[2]
                }
            }
    
        # Combine Results
        $combinedResults = @(); $combinedResults += $netFrameworkVersions; $combinedResults += $dotNetCoreVersions
            
        if ($combinedResults) { return $combinedResults } else { Write-Output "No .NET versions found on this machine." }
    }
    catch {
        throw "An error occurred while enumerating .NET properties: $($_.Exception.Message)"
    }
}

# ISP Details & External IP Addresses

function Get-ISPDetails {
    try {
        $IPv4 = Invoke-RestMethod -Uri 'http://ipinfo.io/'
        $IPv6 = Invoke-RestMethod -Uri 'http://ident.me/'
        return [PSCustomObject]@{
            IPv4 = $IPv4
            IPv6 = $IPv6
        }
    }
    catch {
        throw "An error occurred while retrieving ISP details: $($_.Exception.Message)"
    }
}

# Antivirus Details

function Get-AntiVirus {

    # Source:  https://jdhitsolutions.com/blog/powershell/5187/get-antivirus-product-status-with-powershell/
    
    try {
        $antivirus = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName "AntiVirusProduct"
    }
    catch {
        throw "An error occurred while retrieving antivirus information: $($_.Exception.Message)"
        return
    }

    # Decode hexadecimal productState value to derive Enabled & UpToDate values (True or False)
    
    Function ConvertTo-Hex {
        Param([int]$Number)
        try {
            return '0x{0:x}' -f $Number
        }
        catch {
            throw "Failed to convert number to hexadecimal: $($_.Exception.Message)"
            return $null
        }
    }
    $AntiVirusDetails = $antivirus | ForEach-Object {
        try {
            $hx = ConvertTo-Hex $_.ProductState
            if ($hx -and $hx.Length -ge 5) {
                $mid = $hx.Substring(3, 2)
                $Enabled = if ($mid -match "00|01") { $False } else { $True }

                $end = $hx.Substring(5)
                $UpToDate = if ($end -eq "00") { $True } else { $False }
            }
            else {
                $Enabled = $False
                $UpToDate = $False
            }

    # Collect and format results

            [PSCustomObject]@{
                "Display Name"  = $_.displayName
                "Install Path"  = $_.pathToSignedReportingExe
                "Enabled"       = $Enabled
                "Updated"       = $UpToDate
                "Latest Scan"   = Get-Date $_.timestamp -Format "dddd, dd-MMM-yyyy hh:mm:ss tt"
                "Computer"      = $Env:COMPUTERNAME
            }
        }
        catch {
            throw "Failed to process antivirus product: $($_.Exception.Message)"
        }
    }
    $AntiVirusDetails
}

# Browser URL Associations

function Get-BrowserURL {
    try {
        $AppHash = @{}
        $RegPath = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations"
        Get-ChildItem "$RegPath\*\UserChoice\" -ErrorAction SilentlyContinue |
            ForEach-Object {
                $AppHash.Add((Get-Item $_.PSParentPath).PSChildName, $_.GetValue('progId'))
            }
        if ( $AppHash.Count -gt 0 ) { $AppHash.GetEnumerator() | Sort-Object Value, Name } 
    }
    catch {
        throw "An error occurred while retrieving browser URL associations: $($_.Exception.Message)"
    }
}

# Event Log Activity

function Get-CriticalErrorEvents {
    try {
        $startTime = (Get-Date).AddDays(-1)
        
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'System', 'Application'
            Level     = 1, 2  
            StartTime = $startTime
        }         
        $events | Select-Object LevelDisplayName, Id, TimeCreated, ProviderName, Message | Sort-Object LevelDisplayName, ID
    }
    catch {
        if ($_.Exception.Message -match "No events were found that match the specified selection criteria") {
            Write-Output $NewLine
            Write-Output "No Critical or Error events raised over the past 24 hours."
            Write-Output $NewLine
        }
        else {
            throw "An error occurred while retrieving the event logs: $($_.Exception.Message)"
        }
    }
}

# Updates & Hotfixes 
  
function Get-WindowsUpdateHistory {
    try {
        $Session = New-Object -ComObject Microsoft.Update.Session
        $Search  = $Session.CreateUpdateSearcher()
        $Count   = $Search.GetTotalHistoryCount()
        $Patch   = $Search.QueryHistory(0, $Count)
        $Updates = New-Object System.Collections.ArrayList
        
        foreach ($Update in $Patch) {
            if ($Update.Operation -eq 1 -and $Update.ResultCode -eq 2 -and $Update.Title -notlike '*KB2267602*') {
               
                # Daily virus definition updates filtered for brevity: KB2267602 Security Intelligence Update for Microsoft Defender Antivirus

                $Updates.Add([PSCustomObject]@{            
                        'KB Number'   = [regex]::match($Update.Title, 'KB(\d+)').Value
                        'Installed'   = $Update.Date
                        'Title'       = $Update.Title
                        'Description' = $Update.Description
                    }) | Out-Null
            } 
        } 
        $Updates 
    }
    catch {
        throw "An error occurred while retrieving Windows update history: $($_.Exception.Message)"
    }
}

# Update Progress Bar

function Update-Progress {
    param (
        [string]$Activity, 
        [string]$Status
    )
    try {
        $global:TaskCount++
        Write-Progress -Activity $Activity -Status $Status -PercentComplete (($global:TaskCount / $global:TotalTasks) * 100)          
    }
    catch {
        throw "An error occurred while updating progress: $($_.Exception.Message)"
    }
}

# Verify elevation, configure environment

Confirm-ElevationStatus; Disable-ExecutionPolicy; Hide-ISEScriptPane

# Current Date

$TimeStamp = Get-Date -Format F 
$SystemInventory = "# Current Date", $NewLine, $TimeStamp, $NewLine | Out-String 

# Detailed System Information

$OS = systeminfo.exe
Update-Progress -Activity "Gathering system inventory" -Status "Detailed Operating System Information" -PercentComplete (($TaskCount / $TotalTasks) * 100)
$SystemInventory += "# Operating System", $OS, $NewLine | Out-String 

# OEM Identifier

$OemUniqueId = Get-CimInstance -ClassName win32_bios | Select-Object -Property SerialNumber
Update-Progress -Activity "Gathering system inventory" -Status "OEM Identifier\Serial Number\Service Tag" -PercentComplete (($TaskCount / $TotalTasks) * 100)
$SystemInventory += "# OEM Identifier", $OemUniqueId | Out-String 

# Windows Product Key

$ProductKey = Get-WindowsProductKey | Select-Object 'Product Key' 
Update-Progress -Activity "Gathering system inventory" -Status "Windows Product Key" -PercentComplete (($TaskCount / $TotalTasks) * 100)
$SystemInventory += "# Windows Product Key", $ProductKey | Out-String 

# Graphics Card Details

$GraphicCards = Get-GpuProperties | Sort-Object 'Video Ram' -Descending
Update-Progress -Activity "Gathering system inventory" -Status "Graphics Card Details" -PercentComplete (($TaskCount / $TotalTasks) * 100)
$SystemInventory += "# Graphic Cards", $GraphicCards | Out-String

# Storage Capacity

$Storage = Get-FreeSpace | Format-Table -AutoSize
Update-Progress -Activity "Gathering system inventory" -Status "Storage Capacity" -PercentComplete (($TaskCount / $TotalTasks) * 100)
$SystemInventory += "# Storage Capacity", $Storage | Out-String

# Server Roles\Optional Windows Features

$Results = Get-RolesAndFeatures
Update-Progress -Activity "Gathering system inventory" -Status "Server Roles\Optional Windows Features" -PercentComplete (($TaskCount / $TotalTasks) * 100)
$SystemInventory += $Results.FeatureLabel, $Results.RolesAndFeatures | Out-String

# Network Adapters & Mac Addresses 

$NetAdapters = Get-NetAdapter | Format-Table -AutoSize
Update-Progress -Activity "Gathering system inventory" -Status "Network Adapters & Mac Addresses" -PercentComplete (($TaskCount / $TotalTasks) * 100)
$SystemInventory += "# Network Adapters & Mac Addresses", $NetAdapters | Out-String

# ISP Details & External IP Addresses

$ISPDetails = Get-ISPDetails
Update-Progress -Activity "Gathering system inventory" -Status "ISP Details & External IP Addresses" -PercentComplete (($TaskCount / $TotalTasks) * 100)
$SystemInventory += "# ISP Details & External IP Addresses", $ISPDetails.IPv4, $ISPDetails.IPv6 | Out-String

# Security Posture - Antivirus\Antimalware Details

$AntiVirus = Get-AntiVirus
Update-Progress -Activity "Gathering system inventory" -Status "Security Posture - Antivirus\Antimalware Details" -PercentComplete (($TaskCount / $TotalTasks) * 100)
$SystemInventory += "# Antivirus Details", $AntiVirus | Out-String

# PowerShell 

$PoSh = $PSVersionTable.PSVersion 
Update-Progress -Activity "Gathering system inventory" -Status "PowerShell Details" -PercentComplete (($TaskCount / $TotalTasks) * 100)
$SystemInventory += "# PowerShell", $PoSh | Out-String

# .Net Properties

$NetFrmWrk = Get-DotNetProperties
Update-Progress -Activity "Gathering system inventory" -Status ".NET Properties" -PercentComplete (($TaskCount / $TotalTasks) * 100)
$SystemInventory += "# .Net Framework", $NetFrmWrk | Out-String

# Browswer URL Associations

$BrowserURLs = Get-BrowserURL 
Update-Progress -Activity "Gathering system inventory" -Status "Browswer URL Associations" -PercentComplete (($TaskCount / $TotalTasks) * 100)
$SystemInventory += "# Browser URL Associations", $BrowserURLs | Out-String

# Event Log Activity

$EventLogActivty = Get-CriticalErrorEvents | Format-Table -AutoSize -Wrap
Update-Progress -Activity "Gathering system inventory" -Status "Event Log Activity" -PercentComplete (($TaskCount / $TotalTasks) * 100)
$SystemInventory += "# Event Log Activity", $EventLogActivty | Out-String

# Updates & Hotfixes 

$UpdateHistory = Get-WindowsUpdateHistory | Select-Object "KB Number", Installed, Title | Sort-Object Installed -Descending 
Update-Progress -Activity "Gathering system inventory" -Status "Updates & Hotfixes" -PercentComplete (($TaskCount / $TotalTasks) * 100)  
$SystemInventory += "# Updates & Hotfixes", $UpdateHistory | Out-String

# Save & Display Results

$OutputFile = Join-Path $Env:USERPROFILE "Downloads\System Inventory - $($Env:COMPUTERNAME).txt"
Update-Progress -Activity "Gathering system inventory" -Status "Saving Results" -PercentComplete (($TaskCount / $TotalTasks) * 100) 
$SystemInventory | Out-File -FilePath $OutputFile -Encoding ascii
Get-Content -Path $OutputFile
Write-Host "Hard copy saved as" $OutputFile; Write-Host
