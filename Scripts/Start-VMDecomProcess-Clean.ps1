<#
.SYNOPSIS
    Cleaned-up interactive VM decommissioning script using Start-DecomPrep.ps1 for all system checks and info gathering.
.DESCRIPTION
    This script focuses only on the decommissioning process, assuming all VM info and validation is provided by Start-DecomPrep.ps1.
.PARAMETER PrepObject
    The object returned by Start-DecomPrep.ps1 containing all VM info and validation results.
.PARAMETER TicketNumber
    The ticket or change number for tracking and export/log file naming.
.EXAMPLE
    $prep = .\Start-DecomPrep.ps1 -VMName "TestServer0001x" -TenantFolder "Servers\Test"
    .\Start-VMDecomProcess-Clean.ps1 -PrepObject $prep -TicketNumber "CHG123654"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    $PrepObject,
    [Parameter(Mandatory)]
    [string]$TicketNumber
)

# Validate prep object
if (-not $PrepObject -or -not $PrepObject.VMObject) {
    Write-Error "Invalid or missing PrepObject. Run Start-DecomPrep.ps1 first."
    return
}

$vm = $PrepObject.VMObject
$vmName = $PrepObject.VMName
$logPath = Join-Path -Path (Get-Location) -ChildPath ("$($vmName)-$TicketNumber-VMDecom.log")

function Write-DecomLog {
    param([string]$Message)
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Add-Content -Path $logPath -Value ("[$timestamp] $Message")
}

# Log header
$logHeader = @()
$logHeader += "===== VM Decommissioning Log ====="
$logHeader += "User: $env:USERNAME"
$logHeader += "Ticket: $TicketNumber"
$logHeader += "Log Start: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$logHeader += "==================================="
Set-Content -Path $logPath -Value $logHeader

# Log and display VM info
Write-Host ("Server Name: {0}" -f $PrepObject.VMName)
Write-Host ("IP Address: {0}" -f $PrepObject.IPAddress)
Write-Host ("Operating System: {0}" -f $PrepObject.OS)
Write-Host ("Parent Folder: {0}" -f $PrepObject.FolderPath)
Write-DecomLog -Message ("Server Name: {0}" -f $PrepObject.VMName)
Write-DecomLog -Message ("IP Address: {0}" -f $PrepObject.IPAddress)
Write-DecomLog -Message ("Operating System: {0}" -f $PrepObject.OS)
Write-DecomLog -Message ("Parent Folder: {0}" -f $PrepObject.FolderPath)

# --- Decommissioning Logic ---
$TasksCompleted = @()

# Shutdown logic
if ($vm.PowerState -eq 'PoweredOn') {
    try {
        $null = Shutdown-VMGuest -VM $vm -Confirm:$false -ErrorAction Stop
        $TasksCompleted += '[OK] Shutdown (graceful)'
    } catch {
        $TasksCompleted += '[FAIL] Shutdown (graceful)'
    }
    $timeout = 60
    $elapsedTime = 0
    while ($vm.PowerState -ne 'PoweredOff' -and $elapsedTime -lt $timeout) {
        Start-Sleep -Seconds 5
        $vm = Get-VM -Name $vm.Name
        $elapsedTime += 5
    }
    if ($vm.PowerState -ne 'PoweredOff') {
        try {
            $null = Stop-VM -VM $vm -Confirm:$false -ErrorAction Stop
            $TasksCompleted += '[OK] Shutdown (forced)'
        } catch {
            $TasksCompleted += '[FAIL] Shutdown (forced)'
        }
    }
} else {
    $TasksCompleted += '[OK] Already powered off'
}

# NIC disconnect
try {
    $NetAd = Get-NetworkAdapter -VM $vm
    $null = Set-NetworkAdapter -NetworkAdapter $NetAd -StartConnected:$false -Confirm:$false -ErrorAction Stop
    $TasksCompleted += '[OK] NIC Disconnected'
} catch {
    $TasksCompleted += '[FAIL] NIC Disconnected'
}

# Move to _DECOM
try {
    $null = Move-VM -VM $vm -InventoryLocation (Get-Folder -Server $PrepObject.ViServer | Where-Object { $_.Name -eq '_DECOM' })[0]
    $TasksCompleted += '[OK] Moved to _DECOM'
} catch {
    $TasksCompleted += '[FAIL] Moved to _DECOM'
}

# Rename
$currentDate = (Get-Date).ToString('MM-dd-yyyy')
$futureDate = (Get-Date).AddDays(15).ToString('MM-dd-yyyy')
$newName = '{0}_DECOM-{1}_SHUTDOWN-{2}' -f $vm.Name, $currentDate, $futureDate
try {
    $null = Set-VM -VM $vm -Name $newName -Confirm:$false -ErrorAction Stop
    $TasksCompleted += '[OK] Renamed'
} catch {
    $TasksCompleted += '[FAIL] Renamed'
}

# Output and log results
Write-Host "`n===== VM Decommissioning Result ====="
$TasksCompleted | ForEach-Object { Write-Host $_; Write-DecomLog -Message $_ }
