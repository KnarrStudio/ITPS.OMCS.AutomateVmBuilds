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
$adComp = Get-ADComputer -Identity $ComputerName -Properties * -ErrorAction SilentlyContinue
if (-not $adComp) {
  Write-Error "Computer $ComputerName not found in AD."
  return
}

# Check for DecomDate and DecomTicket
$hasDecomDate = $adComp.PSObject.Properties["DecomDate"] -and $adComp.DecomDate
$hasDecomTicket = $adComp.PSObject.Properties["DecomTicket"] -and $adComp.DecomTicket

if ($hasDecomDate -and $hasDecomTicket) {
  $decomDate = [datetime]::Parse($adComp.DecomDate)
  $now = (Get-Date).Date
  if ($decomDate -gt $now) {
    Write-Host "Computer $ComputerName is already marked for decom on $decomDate (Ticket: $($adComp.DecomTicket)). No action taken."
    return
  } else {
    # Finalize: export and remove
    $exportPathFinal = "$ComputerName-FinalADExport.json"
    $adComp | ConvertTo-Json | Set-Content -Path $exportPathFinal
    Write-Host "Exported final AD computer info to $exportPathFinal"
    Remove-ADComputer -Identity $adComp.DistinguishedName -Confirm:$false
    Write-Host "Removed $ComputerName from AD."
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
  ntSecurityDescriptor = (Get-ADObject -Identity $adComp.DistinguishedName -Properties ntSecurityDescriptor).ntSecurityDescriptor
  Exported = (Get-Date)
  TicketNumber = $TicketNumber
}
$export | ConvertTo-Json | Set-Content -Path $ExportPath
Write-Host "Exported AD computer info to $ExportPath"

Disable-ADAccount -Identity $ComputerName
Write-Host "Disabled computer account $ComputerName"

# Move to Services\Build OU
$targetOU = "OU=Build,OU=Services,DC=$(($adComp.DistinguishedName -split ',DC=')[1..-1] -join ',DC=')"
try {
  Move-ADObject -Identity $adComp.DistinguishedName -TargetPath $targetOU
  Write-Host "Moved $ComputerName to $targetOU"
} catch {
  Write-Warning "Could not move $ComputerName to $targetOU: $_"
}

# Tag with DecomDate and DecomTicket
$decomDate = (Get-Date).AddDays($DecomDays).ToString('yyyy-MM-dd')
Set-ADComputer -Identity $ComputerName -Add @{'DecomDate'=$decomDate; 'DecomTicket'=$TicketNumber}
Write-Host "Tagged $ComputerName with DecomDate=$decomDate and DecomTicket=$TicketNumber"
