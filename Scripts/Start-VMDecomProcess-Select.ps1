<#
.SYNOPSIS
  VM Decommissioning with prompt-driven selection if multiple VMs match the input name.
.DESCRIPTION
  Lists all VMs matching the input name, shows their folder paths, and prompts the user to select the correct VM before proceeding with decommissioning.
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

# This script has been deprecated and is no longer used.
# Please use Start-VMDecomProcess-Interactive.ps1 or Start-VMDecomProcess-Clean.ps1 instead.

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

# Display and prompt for selection
Write-Host "\nMatching VMs:" -ForegroundColor Cyan
for ($i = 0; $i -lt $vmList.Count; $i++) {
    $vm = $vmList[$i]
    Write-Host ("[{0}] Name: {1} | PowerState: {2} | Folder: {3}" -f ($i+1), $vm.Name, $vm.PowerState, $vm.FolderPath)
}
if ($vmList.Count -gt 1) {
  $selection = Read-Host "Enter the number of the VM to decommission (1-$($vmList.Count)) or 0 to cancel"
  if ($selection -eq '0' -or -not $selection -or $selection -notmatch '^[0-9]+$' -or $selection -lt 1 -or $selection -gt $vmList.Count) {
    Write-Host "Operation cancelled."
    return
  }
  $selectedVM = $vmList[$selection-1]
} else {
  $selectedVM = $vmList[0]
}

Write-Host "Selected VM: $($selectedVM.Name) in folder $($selectedVM.FolderPath)"
# ...Proceed with decommissioning logic for $selectedVM.Name...
