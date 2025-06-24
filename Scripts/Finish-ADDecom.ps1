<#
.SYNOPSIS
  Completes AD decommissioning: searches for, verifies, and removes computer objects tagged for decom.
.DESCRIPTION
  - Searches for computers tagged with DecomDate/DecomTicket.
  - Optionally filters by date or ticket number.
  - Exports a final record if needed.
  - Removes the computer from AD.
  - Logs all actions.
.PARAMETER ComputerName
  The name of the computer object in AD.
.PARAMETER TicketNumber
  The tracking ticket number for this decom process.
.PARAMETER DecomDate
  Optional. The decom date tag to filter on (default: today).
.EXAMPLE
  .\Finish-ADDecom.ps1 -ComputerName 'SRV01' -TicketNumber 'INC123456'
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string]$ComputerName,
  [Parameter(Mandatory)]
  [string]$TicketNumber,
  [string]$DecomDate = (Get-Date -Format 'yyyy-MM-dd')
)

# Import AD module if needed
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
  Write-Error 'ActiveDirectory module not found.'
  return
}
Import-Module ActiveDirectory

# Search for the computer tagged for decom
$adComp = Get-ADComputer -Filter "Name -eq '$ComputerName' -and DecomTicket -eq '$TicketNumber' -and DecomDate -eq '$DecomDate'" -Properties *
if (-not $adComp) {
  Write-Error "No computer $ComputerName tagged for decom with ticket $TicketNumber and date $DecomDate."
  return
}

# Export a final record (optional)
$exportPath = "$ComputerName-FinalADExport.json"
$adComp | ConvertTo-Json | Set-Content -Path $exportPath
Write-Host "Exported final AD computer info to $exportPath"

# Remove from AD
Remove-ADComputer -Identity $adComp.DistinguishedName -Confirm:$false
Write-Host "Removed $ComputerName from AD."
