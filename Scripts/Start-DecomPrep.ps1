<#
.SYNOPSIS
    Gather and validate all system information and readiness for VM decommissioning.
.DESCRIPTION
    This script performs all preparatory checks and data collection for a VM prior to decommissioning. It:
    - Resolves DNS and Active Directory status for the VM
    - Collects VM properties (name, FQDN, IP, OS, vCenter, folder, etc.)
    - Validates folder location and tenant folder
    - Outputs a single object with all relevant info for use by decom scripts
.PARAMETER VMName
    The (partial or full) name of the VM to prepare for decommissioning.
.PARAMETER TenantFolder
    The expected folder path for validation (optional).
.EXAMPLE
    $prep = .\Start-DecomPrep.ps1 -VMName "TestServer0001x" -TenantFolder "Servers\Test"
    $prep | Format-List
.NOTES
    Designed to be called by other decom scripts for consistent info gathering and validation.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$VMName,
    [string]$TenantFolder
)

# Get all VMs matching the input name
$vms = Get-VM -Name "*$VMName*" -ErrorAction SilentlyContinue
if (-not $vms) {
    Write-Error "No VMs found matching '$VMName'."
    return $null
}

# Build a list with folder paths
$vmList = @()
foreach ($vm in $vms) {
    $folder = $vm.Folder
    $folderPath = $folder.Name
    while ($folder.Parent -and $folder.Parent -ne $folder) {
        $folder = $folder.Parent
        $folderPath = ("{0}/{1}" -f $folder.Name, $folderPath)
    }
    $vmList += [PSCustomObject]@{
        Name       = $vm.Name
        PowerState = $vm.PowerState
        FolderPath = $folderPath
        VMId       = $vm.Id
        VMObject   = $vm
    }
}

# If more than one VM, prompt user to select
if ($vmList.Count -gt 1) {
    Write-Host "\nMatching VMs:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $vmList.Count; $i++) {
        $vm = $vmList[$i]
        Write-Host ("[{0}] Name: {1} | PowerState: {2} | Folder: {3}" -f ($i+1), $vm.Name, $vm.PowerState, $vm.FolderPath)
    }
    $selection = Read-Host ("Enter the number of the VM to prepare (1-$($vmList.Count)) or 0 to cancel")
    if ($selection -eq '0' -or -not $selection -or $selection -notmatch '^[0-9]+$' -or $selection -lt 1 -or $selection -gt $vmList.Count) {
        Write-Host "Operation cancelled."
        return $null
    }
    $selectedVM = $vmList[$selection-1]
} else {
    $selectedVM = $vmList[0]
}

# Collect VM info
$vm = $selectedVM.VMObject
$guest = $vm.ExtensionData.Guest
$fqdn = $guest.HostName
$ip = $guest.IpAddress
$osType = $vm.Guest.OSFullName
$viServer = ($vm | Select-Object -Property @{N='ViServer';E={ $_.uid.Split(':')[0].Split('@')[1] }}).ViServer

# DNS check
try {
    $dnsResult = Resolve-DnsName -Name $fqdn -ErrorAction Stop | Where-Object { $_.QueryType -eq 'A' } | Select-Object -ExpandProperty IPAddress
} catch {
    $dnsResult = 'Not in DNS'
}

# AD check
try {
    $adObject = Get-ADComputer -Identity $fqdn -ErrorAction Stop
    $adStatus = $adObject.DistinguishedName
} catch {
    $adStatus = 'Not found in AD'
}

# Folder validation
$folderValid = $true
if ($TenantFolder) {
    $folderValid = $selectedVM.FolderPath -like "*$TenantFolder*"
}

# Output all info as a single object
[PSCustomObject]@{
    VMName      = $vm.Name
    FQDN        = $fqdn
    IPAddress   = $ip
    PowerState  = $vm.PowerState
    OS          = $osType
    ViServer    = $viServer
    FolderPath  = $selectedVM.FolderPath
    FolderValid = $folderValid
    DNS         = $dnsResult
    ADStatus    = $adStatus
    VMObject    = $vm
}
