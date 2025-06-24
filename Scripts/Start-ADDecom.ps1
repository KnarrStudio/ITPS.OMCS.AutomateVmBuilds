<#
.SYNOPSIS
  Prepares an AD computer account for decommissioning: disables, moves, tags, and exports info.
.DESCRIPTION
  - Checks if the computer exists in AD.
  - Exports the computer object (owner, permissions, group membership, etc.) to a file for backup.
  - Disables the computer account.
  - Moves it to the 'Services\Build' OU.
  - Adds a 'DecomDate' and 'DecomTicket' tag for tracking.
  - Logs all actions.
.PARAMETER ComputerName
  The name of the computer object in AD.
.PARAMETER TicketNumber
  The tracking ticket number for this decom process.
.PARAMETER ExportPath
  Optional. Path to export the AD object info (default: current directory).
.EXAMPLE
  .\Start-ADDecom.ps1 -ComputerName 'SRV01' -TicketNumber 'INC123456'
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string]$ComputerName,
  [Parameter(Mandatory)]
  [string]$TicketNumber,
  [string]$ExportPath = (Join-Path -Path (Get-Location) -ChildPath "$ComputerName-ADExport.json")
)

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

# Export AD object info (owner, permissions, group membership)
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

# Disable the computer
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
$decomDate = Get-Date -Format 'yyyy-MM-dd'
Set-ADComputer -Identity $ComputerName -Add @{'DecomDate'=$decomDate; 'DecomTicket'=$TicketNumber}
Write-Host "Tagged $ComputerName with DecomDate=$decomDate and DecomTicket=$TicketNumber"
