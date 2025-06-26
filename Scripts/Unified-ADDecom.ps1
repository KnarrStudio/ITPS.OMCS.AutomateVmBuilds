<#
.SYNOPSIS
  Unified AD decommissioning script: disables, tags, moves, and (after grace period) removes computer objects from AD.
.DESCRIPTION
  - On first run: Exports AD info, disables the computer, moves to Services\Build OU, tags with DecomDate and DecomTicket.
  - On subsequent runs before DecomDate: Alerts that the computer is already marked for decom and exits.
  - On or after DecomDate: Exports a final record and removes the computer from AD.
  - All actions are logged to the console.
.PARAMETER ComputerName
  The name of the computer object in AD.
.PARAMETER TicketNumber
  The tracking ticket number for this decom process.
.PARAMETER ExportPath
  Optional. Path to export the AD object info (default: current directory).
.PARAMETER DecomDays
  Optional. Number of days before final removal (default: 15).
.EXAMPLE
  .\Unified-ADDecom.ps1 -ComputerName 'SRV01' -TicketNumber 'INC123456'
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string]$ComputerName,
  [Parameter(Mandatory)]
  [string]$TicketNumber,
  [string]$ExportPath = (Join-Path -Path (Get-Location) -ChildPath "$ComputerName-ADExport.json"),
  [int]$DecomDays = 15
)

# Moved the target OU to a variable for easier reuse
$targetOU = 'OU=Build,OU=Services,DC=yourdomain,DC=com'

# Ensure running in Windows PowerShell 5.1 or later
if ($PSVersionTable.PSVersion.Major -lt 5 -or ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1)) {
    Write-Error 'This script requires Windows PowerShell 5.1 or later.'
    return
}

# Import AD module if needed
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
  Write-Error 'ActiveDirectory module not found.'
  return
}
Import-Module ActiveDirectory

# Get AD computer
$adComp = Get-ADComputer $ComputerName -Properties * -ErrorAction SilentlyContinue
if (-not $adComp) {
  Write-Error "Computer $ComputerName not found in AD."
  return
}

# Check for DecomDate and DecomTicket in Description
$desc = $adComp.Description
$decomPattern = 'DecomDate=([0-9\-]+);DecomTicket=([^;]+)'
$hasDecomTag = $false
$decomDate = $null
$decomTicket = $null
if ($desc -and ($desc -match $decomPattern)) {
    $hasDecomTag = $true
    $decomDate = $matches[1]
    $decomTicket = $matches[2]
}

# Define log file path (use ExportPath with .log extension)
$logPath = [System.IO.Path]::ChangeExtension($ExportPath, '.log')
function Write-DecomLog {
    param([string]$Message)
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Add-Content -Path $logPath -Value ("[$timestamp] $Message")
}

if ($hasDecomTag) {
  $decomDateObj = [datetime]::Parse($decomDate)
  $now = (Get-Date).Date
  if ($decomDateObj -gt $now) {
    $msg = "Computer $ComputerName is already marked for decom on $decomDate (Ticket: $decomTicket). No action taken."
    Write-Host $msg
    Write-DecomLog $msg
    return
  } else {
    # Finalize: export and remove
    $exportPathFinal = "$ComputerName-FinalADExport.json"
    $adComp | ConvertTo-Json | Set-Content -Path $exportPathFinal
    $msg1 = "Exported final AD computer info to $exportPathFinal"
    $msg2 = "Removed $ComputerName from AD."
    Write-Host $msg1
    Write-Host $msg2
    Write-DecomLog $msg1
    Remove-ADComputer $adComp.DistinguishedName -Confirm:$false
    Write-DecomLog $msg2
    return
  }
}

# First run: export, disable, move, tag
$export = [PSCustomObject]@{
  ComputerName = $adComp.Name
  DistinguishedName = $adComp.DistinguishedName
  Description = $adComp.Description
  Enabled = $adComp.Enabled
  WhenCreated = $adComp.WhenCreated
  MemberOf = $adComp.MemberOf
  ManagedBy = $adComp.ManagedBy
  ntSecurityDescriptor = (Get-ADObject $adComp.DistinguishedName -Properties ntSecurityDescriptor).ntSecurityDescriptor
  Exported = (Get-Date)
  TicketNumber = $TicketNumber
}
$export | ConvertTo-Json | Set-Content -Path $ExportPath
$msg = "Exported AD computer info to $ExportPath"
Write-Host $msg
Write-DecomLog $msg

Set-ADComputer $ComputerName -Enabled:$false
$msg = "Disabled computer account $ComputerName"
Write-Host $msg
Write-DecomLog $msg

try {
  Move-ADObject $adComp.DistinguishedName -TargetPath $targetOU
  $msg = "Moved $ComputerName to $targetOU"
  Write-Host $msg
  Write-DecomLog $msg
} catch {
  $msg = "Could not move $ComputerName to ${targetOU}: $_"
  Write-Warning $msg
  Write-DecomLog $msg
}

$decomDate = (Get-Date).AddDays($DecomDays).ToString('yyyy-MM-dd')
$newDesc = "DecomDate=$decomDate;DecomTicket=$TicketNumber"
if ($adComp.Description) {
    $newDesc = $newDesc + ";" + $adComp.Description
}
Set-ADComputer $ComputerName -Description $newDesc
$msg = "Tagged $ComputerName with $newDesc"
Write-Host $msg
Write-DecomLog $msg
