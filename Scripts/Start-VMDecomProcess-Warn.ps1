<#
.SYNOPSIS
  VM Decommissioning with warning and continue/cancel if multiple VMs match the input name.
.DESCRIPTION
  Lists all VMs matching the input name, shows their folder paths, and warns the user if there are multiple matches. User must confirm to continue with all or cancel.
.PARAMETER VMName
  The (partial or full) name of the VM to decommission.
.PARAMETER TenantFolder
  The expected folder path for validation (optional).
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
  return
}

# Build a list with folder paths
$vmList = @()
foreach ($vm in $vms) {
  $folder = $vm.Folder
  $folderPath = $folder.Name
  while ($folder.ParentId -and $folder.ParentId -ne $folder.Id) {
    $folder = Get-Folder -Id $folder.ParentId
    if ($folder) { $folderPath = "$($folder.Name)/$folderPath" } else { break }
  }
  $vmList += [PSCustomObject]@{
    Name = $vm.Name
    PowerState = $vm.PowerState
    FolderPath = $folderPath
    VMId = $vm.Id
  }
}

Write-Host "\nMatching VMs:"
$vmList | Format-Table -AutoSize
if ($vmList.Count -gt 1) {
  $resp = Read-Host "WARNING: Multiple VMs match '$VMName'. Continue with all? (Y/N)"
  if ($resp -notin @('Y','y')) {
    Write-Host "Operation cancelled."
    return
  }
}
# ...Proceed with decommissioning logic for all $vmList.Name...
