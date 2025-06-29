<#
.SYNOPSIS
    Export provided values to a tab-delimited CSV file for change tracking.
.DESCRIPTION
    This script takes input values for each column, builds an object, and exports it as a tab-delimited CSV file with the specified headers.
.PARAMETER OutputPath
    The path to the output CSV file.
.PARAMETER TicketNumber
    The change or ticket number.
.PARAMETER DeviceUpdated
    The device that was updated (e.g., DNSserver).
.PARAMETER ChangeType
    The type of change (e.g., DNS).
.PARAMETER Network
    The network or environment (e.g., AntFarm).
.PARAMETER WhatWasDone
    Description of what was done.
.PARAMETER Why
    Reason for the change.
.PARAMETER CreatedBy
    Who created the change.
.PARAMETER Created
    Date/time the change was created.
.PARAMETER ReviewedBy
    Who reviewed the change.
.PARAMETER ItemType
    The type of item (e.g., Item).
.PARAMETER Path
    The path or location (optional).
.EXAMPLE
    .\ExportTo-CsvFile.ps1 -OutputPath .\output.csv -TicketNumber "CHG123654" -DeviceUpdated "DNSserver" -ChangeType "DNS" -Network "AntFarm" -WhatWasDone "Added host records: ServerName 192.168.10.25" -Why "New Build" -CreatedBy "TechName" -Created "2025-06-29 10:00" -ReviewedBy "N/A" -ItemType "Item" -Path ""
#>

param(
    [Parameter(Mandatory)]
    [string]$OutputPath,
    [Parameter(Mandatory)]
    [string]$TicketNumber,
    [Parameter(Mandatory)]
    [string]$DeviceUpdated,
    [Parameter(Mandatory)]
    [string]$ChangeType,
    [Parameter(Mandatory)]
    [string]$Network,
    [Parameter(Mandatory)]
    [string]$WhatWasDone,
    [Parameter(Mandatory)]
    [string]$Why,
    [Parameter(Mandatory)]
    [string]$CreatedBy,
    [Parameter(Mandatory)]
    [string]$Created,
    [Parameter(Mandatory)]
    [string]$ReviewedBy,
    [Parameter(Mandatory)]
    [string]$ItemType,
    [string]$Path = ""
)

# Build the object with the specified headers in the exact order required
$record = [PSCustomObject]@{
    Title                   = $TicketNumber
    'What Device was updated' = $DeviceUpdated
    Date                    = $Created
    'Change Type'           = $ChangeType
    Network                 = $Network
    'What was done'         = $WhatWasDone
    Why                     = $Why
    'Created by'            = $CreatedBy
    Created                 = $Created
    'Reviewed By'           = $ReviewedBy
    'Item Type'             = $ItemType
    Path                    = $Path
}

# Export as tab-delimited CSV, enforcing column order
$headerOrder = @(
    'Title',
    'What Device was updated',
    'Date',
    'Change Type',
    'Network',
    'What was done',
    'Why',
    'Created by',
    'Created',
    'Reviewed By',
    'Item Type',
    'Path'
)

$record | Select-Object $headerOrder | Export-Csv -Path $OutputPath -Delimiter "`t" -NoTypeInformation -Encoding UTF8

Write-Host "Exported to $OutputPath as tab-delimited CSV."
