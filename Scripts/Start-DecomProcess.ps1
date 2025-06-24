<#

    .SYNOPSIS
    Processes a list of virtual machines (VMs) for decommissioning by performing various tasks such as retrieving information, shutting them down, and preparing them for deletion.


    .DESCRIPTION
    This script takes a list of VM names as input and performs the following tasks:

    1. Retrieves the VM's Fully Qualified Domain Name (FQDN), IP address, and Active Directory status.

    2. Gathers resource information, including CPU, memory, and storage usage.

    3. Powers off the VM (gracefully if possible, or forces shutdown after a timeout).

    4. Disconnects the VM's network adapter.

    5. Relocates the VM to the "_Decom" folder for decommissioned machines.

    6. Renames the VM to indicate its decommissioning status with a timestamp.

    7. Outputs a simple, email-friendly summary table listing all processed VMs and total resources reclaimed. The summary is also copied to the clipboard for easy pasting into an email.

    8. Supports nested folder paths for the TenantFolder parameter (e.g., "Root/Dept/Team").
 

    .PARAMETER VMNames
    An array of VM names to process; this parameter is mandatory.

 

    .PARAMETER TenantFolder
    Specifies the folder (can be a nested path, e.g., "Root/Dept/Team") in which the VM should be located before processing; this parameter is mandatory. (This is a safety measure to prevent the impact of a typo in the name of a VM. May be deprecated in future versions.)


    .NOTES
    Version: 6.23.2025
    Requires: PowerCLI module for VMware vSphere management.
    Requires: Active Directory module for PowerShell (for AD status checks).
    Requires: PowerShell 5.1 or later for clipboard functionality.
    GUID: 12345678-abcd-1234-ef00-1234567890ab
    Author: Erik Arnesen
    Date: 6/23/2025

    - The script outputs a summary table of all processed VMs, including VM name, FQDN, IP address, AD status, vCPU, memory, and storage.

    - The summary is copied to the clipboard for easy pasting into an email (if available).

    - Skipped VMs (already in _DECOM or not in the specified folder) are not included in the summary.

    - The TenantFolder parameter supports nested folder paths for accurate VM location validation.

 

    .EXAMPLE
    PS C:\> .\Start-DecomProcess.ps1 -VMNames "VM1", "VM2", "VM3" -TenantFolder "Region/ProjectA"

    Processes the VMs "VM1", "VM2", and "VM3" from the specified nested folder path "Region/ProjectA", following the defined steps, and outputs a summary table for email.

#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param (
  [Parameter(Mandatory = $true, HelpMessage = 'Specify the names of the VMs to process.')]
  [string[]]$VMNames,
  [Parameter(Mandatory = $true, HelpMessage = 'Specify the folder where the VM should be located.')]
  [string]$TenantFolder
)
$Depricated = 'The "TenantFolder" parameter may be depricated in future versions'
Write-Host (' ' * ($Depricated.Length + 4)) -BackgroundColor Black
Write-Host ('  {0}  ' -f $Depricated) -ForegroundColor Yellow -BackgroundColor Black
Write-Host (' ' * ($Depricated.Length + 4)) -BackgroundColor Black

# For output
function FancyOutput 
{
  param (
    [Parameter(Mandatory)]
    [string]$Message
  )
  $border = '=' * ($Message.Length + 4)
  Write-Host "`n$border"
  Write-Host "  $Message" -ForegroundColor Yellow
  Write-Host "$border`n"
}

# Function to get the VM's FQDN, IP address, and AD status
function Get-VMFQDNIPandADStatus 
{
  param (
    [Parameter(Mandatory = $true)]
    [string]$VMName
  )
  $CleanVMName = $VMName.Split('.- (_')[0]
  $DnsDomain = $env:USERDNSDOMAIN
  try 
  {
    # Resolve the FQDN to an IP address
    $ipAddress = (Resolve-DnsName -Name $CleanVMName -ErrorAction Stop |
      Where-Object -FilterScript {
        $_.QueryType -eq 'A'
      } |
    Select-Object -ExpandProperty IPAddress)[0]
  }
  catch 
  {
    $ipAddress = 'Not in DNS'
  }
  # Check if the VM is still in Active Directory
  try 
  {
    $adObject = Get-ADComputer -Identity $CleanVMName -ErrorAction Stop
    $adStatus = $adObject.DistinguishedName
  }
  catch 
  {
    $adStatus = 'Not found in AD'
  }
  # Output the VM's name, FQDN, IP address, and AD status
  [PSCustomObject]@{
    VMName    = $VMName
    FQDN      = "$VMName.$DnsDomain"
    IPAddress = $ipAddress
    ADStatus  = $adStatus
  }
}

# Function to get the VM's FQDN and IP address
function Get-VMInfo 
{
  param (
    [Parameter(Mandatory = $true)]
    [string]$VMName
  )
  $GuessedFQDN = '{0}.knarrstudio.com' -f $VMName
  try 
  {
    # Resolve the FQDN to an IP address
    $ipAddress = (Resolve-DnsName -Name $GuessedFQDN -ErrorAction Stop |
      Where-Object -FilterScript {
        $_.QueryType -eq 'A'
      } |
    Select-Object -ExpandProperty IPAddress)[0]
  }
  catch 
  {
    $ipAddress = 'Not in DNS'
  }
  
  # Retrieve the VM and its guest OS details
  $vm = Get-VM -Name $VMName
  $guest = $vm.ExtensionData.Guest
  $fqdn = $guest.HostName
  $ip = $guest.IpAddress
  $ViServer = ($vm | Select-Object -Property @{
      N = 'ViServer'
      E = {
        $_.uid.Split(':')[0].Split('@')[1]
      }
  }).ViServer
  
  # Collect resource information
  $cpu = $vm.NumCpu
  $memory = [math]::Round($vm.MemoryGB, 2)
  $TotalStorageGB = 0
  foreach ($datastorageUsage in $vm.ExtensionData.Storage.PerDatastoreUsage) 
  {
    $TotalStorageGB += [Math]::Round(($datastorageUsage.committed /1GB), 2)
  }
  
  # Return the collected VM information
  return [PSCustomObject]@{
    VMName         = $vm.Name
    FQDN           = $fqdn
    IPAddress      = $ip
    ViServer       = $ViServer
    NumCPU         = $cpu
    MemoryGB       = $memory
    TotalStorageGB = $TotalStorageGB
  }
}

# Helper function to resolve a nested folder path (e.g., "Root/Dept/Team")
function Get-FolderByPath 
{
  param (
    [string]$Path,
    [string]$ViServer
  )
  $parts = $Path -split '[\\/]'  # Support both / and \ as separators
  $folder = Get-Folder -Server $ViServer -Name $parts[0]
  for ($i = 1; $i -lt $parts.Count; $i++) 
  {
    $folder = Get-Folder -Server $ViServer -Name $parts[$i] -Location $folder
  }
  return $folder
}

# Function to process each VM
function Invoke-VMProcess 
{
  param (
    [Parameter(Mandatory = $true)]
    [string]$VMName,
    [string]$TenantFolder
  )
  function Get-NewVMName 
  {
    param (
      [string]$VMName,
      [bool]$AlreadyPoweredOff
    )
    $currentDate = (Get-Date).ToString('MM-dd-yyyy')
    $futureDate = (Get-Date).AddDays(14).ToString('MM-dd-yyyy')
    if ($AlreadyPoweredOff) 
    {
      return "$VMName_SHUTDOWN_Previously_DECOM-$futureDate"
    }
    else 
    {
      return "$VMName_SHUTDOWN_$currentDate_DECOM-$futureDate"
    }
  }
  
  #Set PowerState
  $AlreadyPoweredOff = $false
  
  # Get VM info
  $vmInfo = Get-VMInfo -VMName $VMName
  $vm = Get-VM $VMName
  
  # Example usage
  $VMFQDNIPandADStatus = Get-VMFQDNIPandADStatus -VMName $VMName
  
  # Check if VM is already in the "_DECOM" folder
  $decomFolder = (Get-Folder -Server $vmInfo.ViServer -Name '_DECOM')[0]
  if ($vm.Folder.Id -eq $decomFolder.Id) 
  {
    Write-Host "VM is already in the '_DECOM' folder. Skipping VM: $VMName"
    return
  }
  
  # Check if VM is in the specified TenantFolder
  $tenantFolderObj = Get-FolderByPath -Path $TenantFolder -ViServer $vmInfo.ViServer
  if (-not $tenantFolderObj) 
  {
    Write-Host ('Could not find folder path: {0}. Skipping VM: {1}' -f $TenantFolder, $VMName)
    return
  }
  $vmFolderId = [String]$vm.FolderId
  $tenantFolderId = [String]$tenantFolderObj.Id
  if ($vmFolderId -ne $tenantFolderId) 
  {
    Write-Host ('VM {1} is not in the specified Folder {0}. Skipping VM.' -f $TenantFolder, $VMName)
    return
  }
  
  # Shutdown the VM if it's powered on
  if ($vm.PowerState -eq 'PoweredOn') 
  {
    $null = Shutdown-VMGuest -VM $vm -Confirm:$false -ErrorAction SilentlyContinue
    
    # Wait for the VM to power off or force power off after timeout
    $timeout = 60
    $elapsedTime = 0
    while ($vm.PowerState -ne 'PoweredOff' -and $elapsedTime -lt $timeout) 
    {
      Start-Sleep -Seconds 5
      $vm = Get-VM -Name $vm.Name
      $elapsedTime += 5
    }
    if ($vm.PowerState -ne 'PoweredOff') 
    {
      Write-Host 'Timeout reached. Forcing VM to power off.'
      $null = Stop-VM -VM $vm -Confirm:$false
    }
  }
  else
  {
    $AlreadyPoweredOff = $true
  }
  
  # Disconnect the VM's network adapter
  $NetAd = Get-NetworkAdapter -VM $vm
  $null = Set-NetworkAdapter -NetworkAdapter $NetAd -StartConnected:$false -Confirm:$false -ErrorAction SilentlyContinue
  
  # Move the VM to the "_Decom" folder
  $null = Move-VM -VM $vm -InventoryLocation (Get-Folder -Server $vmInfo.ViServer | Where-Object -FilterScript {
      $_.Name -eq '_DECOM'
  })[0]

  # Rename the VM
  $currentDate = (Get-Date).ToString('MM-dd-yyyy')
  $futureDate = (Get-Date).AddDays(15).ToString('MM-dd-yyyy')
  if ($AlreadyPoweredOff) 
  {
    $newName = '{0}_DECOM-{1}_SHUTDOWN-Previously' -f $vm.Name, $futureDate
  }
  else 
  {
    $newName = '{0}_DECOM-{2}_SHUTDOWN_{1}' -f $vm.Name, $currentDate, $futureDate
  }
  $null = Set-VM -VM $vm -Name $newName -Confirm:$false

  # Return the VM process result
  return [PSCustomObject]@{
    VMName         = $vmInfo.VMName
    NewVMName      = $newName
    FQDN           = $VMFQDNIPandADStatus.FQDN
    IPAddress      = $VMFQDNIPandADStatus.IPAddress
    ADStatus       = $VMFQDNIPandADStatus.ADStatus
    NumCPU         = $vmInfo.NumCPU
    MemoryGB       = $vmInfo.MemoryGB
    StorageGB      = $vmInfo.TotalStorageGB
    TasksCompleted = @(' ', 
      '☑ Shutdown', 
      '☑ NIC Disconnected', 
      '☑ Moved to _Decom', 
      '☑ Renamed'
    ) -join "`n"
  }
}

# =========================
# Main script execution
# =========================

# Initialize results array and resource counters
$results = @()
$GroupvCPU = 0
$GroupMemory = 0
$GroupStorage = 0

# Loop through each VM name provided as input
foreach ($VMName in $VMNames) 
{
  # Process the VM and collect the result object
  $result = Invoke-VMProcess -VMName $VMName -TenantFolder $TenantFolder
  if ($result) 
  {
    # Add the result to the results array
    $results += $result
    # Accumulate resource totals for summary
    $GroupvCPU += [int]$result.NumCPU
    $GroupMemory += [int]$result.MemoryGB
    $GroupStorage += [int]$result.StorageGB
  }
}

# =========================
# Prepare a simple, email-friendly summary table
# =========================

$summary = @()
$summary += ''
$summary += '---------------- VM Decommissioning Summary ----------------'
$summary += ''
$summary += ('{0,-20} {1,-30} {2,-15} {3,-25} {4,-8} {5,-8} {6,-10}' -f 'VM Name', 'FQDN', 'IP Address', 'AD Status', 'vCPU', 'Memory', 'Storage')
$summary += ('{0}' -f ('-'*120))
# Add each VM's details to the summary table
foreach ($r in $results) 
{
  $summary += ('{0,-20} {1,-30} {2,-15} {3,-25} {4,-8} {5,-8} {6,-10}' -f $r.VMName, $r.FQDN, $r.IPAddress, $r.ADStatus, $r.NumCPU, $r.MemoryGB, $r.StorageGB)
}
$summary += ('{0}' -f ('-'*120))
$summary += ''
# Add total resources reclaimed
$summary += ('Total vCPUs:    {0,-5}   Total Memory (GB): {1,-7}   Total Storage (GB): {2,-7}' -f $GroupvCPU, $GroupMemory, $GroupStorage)
$summary += '------------------------------------------------------------'
$summary += ''

# =========================
# Output the summary for easy copy-paste to email
# =========================

try 
{
  # Attempt to copy the summary to the clipboard (Windows/PowerShell 5.1+)
  $summary | Set-Clipboard
  Write-Host "`n$($summary -join "`n")`n"
  Write-Host '(Summary table has been copied to clipboard for easy email pasting.)' -ForegroundColor Green
}
catch 
{
  # If clipboard is not available, just print the summary
  Write-Host "`n$($summary -join "`n")`n"
  Write-Host '(Could not copy to clipboard. Please copy manually.)' -ForegroundColor Yellow
}

# End of script

# SIG # Begin signature block
# MIIF... (signature will be inserted here by Set-AuthenticodeSignature)
# SIG # End signature block
