<#

    .SYNOPSIS
    Interactive VM Decommissioning: select the correct VM from a numbered list, then process and display detailed results for each VM.

    .DESCRIPTION
    This script interactively guides the user through the decommissioning of a VMware VM. It:
    - Checks for a vCenter connection matching the VM name prefix and prompts to connect if needed.
    - Lists all VMs matching the input name, displaying their folder paths and power state.
    - Prompts the user to select the correct VM from a numbered list (or cancels if desired).
    - Validates the VM's folder location and tenant folder before proceeding.
    - Exports all VM properties to a JSON file for backup/reference, named with the VM and ticket number.
    - Runs a step-by-step decommissioning process for the selected VM, including:
        - Graceful and forced shutdown (with ASCII [OK]/[FAIL] status for each step)
        - NIC disconnect
        - Move to _DECOM folder
        - Rename with decom/shutdown date
    - Logs all actions and results to a persistent log file per VM and ticket number.
    - Displays a detailed, formatted summary of the decommissioning result for the VM.
    - Ensures robust error handling and clear output for team handoff and operational use.
    - Compatible with PowerShell 5.1 and plain ASCII output/logging.

    .PARAMETER VMName
    The (partial or full) name of the VM to decommission. Used for searching and selection.

    .PARAMETER TenantFolder
    The expected folder path for validation (optional, but recommended for safety).

    .PARAMETER TicketNumber
    The ticket or change number for tracking and export/log file naming.

    .NOTES
    - Designed for team use and operational handoff.
    - All actions are logged and exported for audit and rollback.
    - Menu-driven and CLI-friendly workflow.
    - All output and logs are plain ASCII for compatibility.
    - Requires VMware PowerCLI and Active Directory modules.
    - Script is idempotent: will skip VMs already in _DECOM or not in the specified folder.
    - For questions or improvements, see script comments and contact the author.

#>

[CmdletBinding()]

param(

  [Parameter(Mandatory)]
  [string]$VMName,

  [string]$TenantFolder,

  [String]$TicketNumber

)

 

# vCenter connection check based on first 6 letters of VM name
$vcShort = $VMName.Substring(0,6)
$connectedVCs = Get-VIServer
$foundVC = $null
foreach ($vc in $connectedVCs) 
{
  if ($vc.Name -like "$vcShort*") 
  {
    $foundVC = $vc
    break
  }
}
if (-not $foundVC) 
{
  $vcNameToConnect = Read-Host -Prompt ("Not connected to vCenter matching '{0}*'. Enter full vCenter name to connect" -f $vcShort)
  try 
  {
    Connect-VIServer -Server $vcNameToConnect -ErrorAction Stop
    Write-Host ('Connected to vCenter: {0}' -f $vcNameToConnect)
  }
  catch 
  {
    Write-Error -Message ('Failed to connect to vCenter: {0}. {1}' -f $vcNameToConnect, $_)
    return
  }
}
else 
{
  Write-Host ('Already connected to vCenter: {0}' -f $foundVC.Name)
}

# Get all VMs matching the input name

$vms = Get-VM -Name "*$VMName*" -ErrorAction SilentlyContinue

if (-not $vms) 
{
  Write-Error -Message ("No VMs found matching '{0}'." -f $VMName)

  return
}

 

# Build a list with folder paths

$vmList = @()

foreach ($vm in $vms) 
{
  $folder = $vm.Folder

  $folderPath = $folder.Name

  while ($folder.Parent -and $folder.Parent -ne $folder) 
  {
    $folder = $folder.Parent

    $folderPath = ('{0}/{1}' -f $folder.Name, $folderPath)
  }

  $vmList += [PSCustomObject]@{
    Name       = $vm.Name
    PowerState = $vm.PowerState
    FolderPath = $folderPath
    VMId       = $vm.Id
  }
}


# Display and prompt for selection

Write-Host "`nMatching VMs:" -ForegroundColor Cyan

for ($i = 0; $i -lt $vmList.Count; $i++) 
{
  $vm = $vmList[$i]

  Write-Host ('[{0}] Name: {1} | PowerState: {2} | Folder: {3}' -f ($i+1), $vm.Name, $vm.PowerState, $vm.FolderPath)
}

if ($vmList.Count -gt 1) 
{
  $selection = Read-Host -Prompt ('Enter the number of the VM to decommission (1-{0}) or 0 to cancel' -f $vmList.Count)

  if ($selection -eq '0' -or -not $selection -or $selection -notmatch '^[0-9]+$' -or $selection -lt 1 -or $selection -gt $vmList.Count) 
  {
    Write-Host 'Operation cancelled.'

    return
  }

  $selectedVM = $vmList[$selection-1]
}
else 
{
  $selectedVM = $vmList[0]
}


Write-Host ('Selected VM: {0} in folder {1}' -f $selectedVM.Name, $selectedVM.FolderPath)
 

# --- VM Decommissioning Logic ---

function Get-VMFQDNIPandADStatus 
{
  param([string]$VMName)

  $CleanVMName = $VMName.Split('.- (_')[0]

  $DnsDomain = $env:USERDNSDOMAIN

  try 
  {
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

  try 
  {
    $adObject = Get-ADComputer -Identity $CleanVMName -ErrorAction Stop

    $adStatus = $adObject.DistinguishedName
  }
  catch 
  {
    $adStatus = 'Not found in AD' 
  }

  [PSCustomObject]@{
    VMName    = $VMName
    FQDN      = "$VMName.$DnsDomain"
    IPAddress = $ipAddress
    ADStatus  = $adStatus
  }
}

 

function Get-VMInfo 
{
  param([string]$VMName)

  $GuessedFQDN = '{0}.knarrstudio.com' -f $VMName

  try 
  {
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

  $cpu = $vm.NumCpu

  $memory = [math]::Round($vm.MemoryGB, 2)

  $TotalStorageGB = 0

  foreach ($datastorageUsage in $vm.ExtensionData.Storage.PerDatastoreUsage) 
  {
    $TotalStorageGB += [Math]::Round(($datastorageUsage.committed /1GB), 2)
  }

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

 

function Get-FolderByPath 
{
  param([string]$Path, [string]$ViServer)

  $parts = $Path -split '[\\/]'  # Support both / and \ as separators

  $folder = Get-Folder -Server $ViServer -Name $parts[0]

  for ($i = 1; $i -lt $parts.Count; $i++) 
  {
    $folder = Get-Folder -Server $ViServer -Name $parts[$i] -Location $folder
  }

  return $folder
}

 

function Invoke-VMProcess 
{
  param([string]$VMName, [string]$TenantFolder)

  $AlreadyPoweredOff = $false

  $TasksCompleted = @()

  $vmInfo = Get-VMInfo -VMName $VMName

  $vm = Get-VM -Name $VMName

  $VMFQDNIPandADStatus = Get-VMFQDNIPandADStatus -VMName $VMName

  $decomFolder = (Get-Folder -Server $vmInfo.ViServer -Name '_DECOM')[0]

  if ($vm.Folder.Id -eq $decomFolder.Id) 
  {
    Write-Host ("VM is already in the '_DECOM' folder. Skipping VM: {0}" -f $VMName)

    $TasksCompleted += '✗ Already in _DECOM folder'

    return $null
  }

  $tenantFolderObj = Get-FolderByPath -Path $TenantFolder -ViServer $vmInfo.ViServer

  if (-not $tenantFolderObj) 
  {
    Write-Host ('Could not find folder path: {0}. Skipping VM: {1}' -f $TenantFolder, $VMName)

    $TasksCompleted += '✗ Tenant folder not found'

    return $null
  }

  $vmFolderId = [String]$vm.FolderId

  $tenantFolderId = [String]$tenantFolderObj.Id

  if ($vmFolderId -ne $tenantFolderId) 
  {
    Write-Host ('VM {1} is not in the specified Folder {0}. Skipping VM.' -f $TenantFolder, $VMName)

    $TasksCompleted += '✗ Not in specified folder'

    return $null
  }

  # Shutdown
  if ($vm.PowerState -eq 'PoweredOn') 
  {
    try 
    {
      $null = Shutdown-VMGuest -VM $vm -Confirm:$false -ErrorAction Stop
      $TasksCompleted += '[OK] Shutdown (graceful)'
    }
    catch 
    {
      $TasksCompleted += '[FAIL] Shutdown (graceful)'
    }
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
      try 
      {
        $null = Stop-VM -VM $vm -Confirm:$false -ErrorAction Stop
        $TasksCompleted += '[OK] Shutdown (forced)'
      }
      catch 
      {
        $TasksCompleted += '[FAIL] Shutdown (forced)'
      }
    }
  }
  else 
  {
    $AlreadyPoweredOff = $true
    $TasksCompleted += '[OK] Already powered off'
  }
  # NIC disconnect
  try 
  {
    $NetAd = Get-NetworkAdapter -VM $vm
    $null = Set-NetworkAdapter -NetworkAdapter $NetAd -StartConnected:$false -Confirm:$false -ErrorAction Stop
    $TasksCompleted += '[OK] NIC Disconnected'
  }
  catch 
  {
    $TasksCompleted += '[FAIL] NIC Disconnected'
  }
  # Move to _DECOM
  try 
  {
    $null = Move-VM -VM $vm -InventoryLocation (Get-Folder -Server $vmInfo.ViServer | Where-Object -FilterScript {
        $_.Name -eq '_DECOM' 
    })[0]
    $TasksCompleted += '[OK] Moved to _DECOM'
  }
  catch 
  {
    $TasksCompleted += '[FAIL] Moved to _DECOM'
  }
  # Rename
  $currentDate = (Get-Date).ToString('MM-dd-yyyy')
  $futureDate = (Get-Date).AddDays(15).ToString('MM-dd-yyyy')
  if ($AlreadyPoweredOff) 
  {
    $newName = '{0}_DECOM-{1}_SHUTDOWN-Previously' -f $vm.Name, $futureDate
  }
  else 
  {
    $newName = '{0}_DECOM-{2}_SHUTDOWN-{1}' -f $vm.Name, $currentDate, $futureDate
  }
  try 
  {
    $null = Set-VM -VM $vm -Name $newName -Confirm:$false -ErrorAction Stop
    $TasksCompleted += '[OK] Renamed'
  }
  catch 
  {
    $TasksCompleted += '[FAIL] Renamed'
  }
  return [PSCustomObject]@{
    VMName         = $vmInfo.VMName
    NewVMName      = $newName
    FQDN           = $VMFQDNIPandADStatus.FQDN
    IPAddress      = $VMFQDNIPandADStatus.IPAddress
    ADStatus       = $VMFQDNIPandADStatus.ADStatus
    NumCPU         = $vmInfo.NumCPU
    MemoryGB       = $vmInfo.MemoryGB
    StorageGB      = $vmInfo.TotalStorageGB
    TasksCompleted = $TasksCompleted -join "`n"
  }
}


# --- Main Execution ---

# Set up export and log file paths
$ticketSafe = $TicketNumber -replace '[^a-zA-Z0-9_-]', '_'
$exportPath = Join-Path -Path (Get-Location) -ChildPath ("$($selectedVM.Name)-$ticketSafe-VMExport.json")
$logPath = Join-Path -Path (Get-Location) -ChildPath ("$($selectedVM.Name)-$ticketSafe-VMDecom.log")
function Write-DecomLog 
{
  param([string]$Message)
  $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  Add-Content -Path $logPath -Value ("[$timestamp] $Message")
}

# Export VM properties for backup/reference
$vmExport = Get-VM -Name $selectedVM.Name |
Select-Object -Property * |
ConvertTo-Json -Depth 5
Set-Content -Path $exportPath -Value $vmExport
Write-DecomLog -Message ('Exported VM properties to {0}' -f $exportPath)

$result = Invoke-VMProcess -VMName $selectedVM.Name -TenantFolder $TenantFolder
if ($result) 
{
  Write-Host "`n===== VM Decommissioning Result ====="
  $result |
  Format-List |
  Out-String |
  Write-Host
  # Log each step
  foreach( $line in $result.TasksCompleted -split "`n") 
  {
    Write-DecomLog -Message $line
  }
}


