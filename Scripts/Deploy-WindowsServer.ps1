<#
.SYNOPSIS
    Deploys a Windows Server virtual machine using VMware PowerCLI and a CSV input file.

.DESCRIPTION
    This script automates the deployment of a Windows Server VM in a vSphere environment. It reads server configuration from a CSV file, applies network and domain settings, and runs post-deployment scripts inside the VM. The script supports customization, domain join, and resource configuration.

.PARAMETER ServerDataFile
    Path to the CSV file containing server configuration data. Default is '.\Friday-Power\Inputs\ServerDatafile.csv'.

.EXAMPLE
    .\Deploy-WindowsServer.ps1 -ServerDataFile .\Inputs\MyServerData.csv
    Deploys a Windows Server VM using the specified CSV file for configuration.

.NOTES
    Requires VMware PowerCLI and appropriate permissions in vCenter.
    Prompts for local and domain admin credentials during execution.
    Ensure the CSV file contains the required columns: Hostname, IP, SubnetLength, Gateway, IP_DNS, JoinDomain, Domain, vCenterInstance, Cluster, VMTemplate, CustomSpec, Location, DataStore, DiskStorageFormat, NetworkName, Memory, CPU, DiskCapacity.
    
    Example CSV header:
    Hostname,IP,SubnetLength,Gateway,IP_DNS,JoinDomain,Domain,vCenterInstance,Cluster,VMTemplate,CustomSpec,Location,DataStore,DiskStorageFormat,NetworkName,Memory,CPU,DiskCapacity

.LINK
    VMware PowerCLI documentation: https://developer.vmware.com/powercli
#>
#requires -Version 3.0 -Modules VMware.VimAutomation.Core
# Deploy Windows Server

#### USER DEFINED VARIABLES #
param(
  [string]$ServerDataFile = '.\Friday-Power\Inputs\ServerDatafile.csv'  # Path to CSV with server deployment data
)

Begin{
  Clear-Host
  Write-Verbose -Message 'Deploy Windows server'

  # Initialize the scripts array for Add-Script
  $scripts = @()

  # Import server data from CSV with error handling
  try {
    $ServerData = Import-Csv -Path $ServerDataFile -ErrorAction Stop
  } catch {
    Write-Error "Failed to import CSV file: $ServerDataFile. $_"
    return
  }

  # Assign variables from imported data with validation
  $LocalUser = 'localAdmin'
  $DomainAdmin = 'domainAdmin'
  $VmName = $ServerData.Hostname
  $IP = $ServerData.IP
  $SubnetLength = $ServerData.SubnetLength
  $GW = $ServerData.Gateway
  $IP_DNS = $ServerData.IP_DNS
  $JoinDomainYN = $ServerData.JoinDomain
  $Domain = $ServerData.Domain
  $vCenterInstance = $ServerData.vCenterInstance
  $Cluster = $ServerData.Cluster
  $VMTemplate = $ServerData.VMTemplate
  $CustomSpec = $ServerData.CustomSpec
  $Location = $ServerData.Location
  $DataStore = $ServerData.DataStore
  $DiskStorageFormat = $ServerData.DiskStorageFormat
  $NetworkName = $ServerData.NetworkName
  $Memory = $ServerData.Memory
  $CPU = $ServerData.CPU
  $DiskCapacity = $ServerData.DiskCapacity

  # Validate required fields
  if (-not $VmName -or -not $VMTemplate -or -not $Cluster) {
    Write-Error "Missing required server data (Hostname, VMTemplate, or Cluster). Check your CSV file."
    return
  }

  ### FUNCTION DEFINITIONS ################################################################################################
  # Checks if customization has started for the VM
  Function Test-CustomizationStarted
  {
    param
    (
      [Parameter(Mandatory)]
      [string]$VM
    )
    Write-Verbose -Message ('Verifying that Customization for VM {0} has started' -f $VM)
    $i = 60 # time-out of 5 min
    while($i -gt 0)
    {
      try {
        $vmEvents = Get-VIEvent -Entity $VM -ErrorAction Stop
      } catch {
        Write-Warning "Failed to get events for VM ${VM}: ${_}"
        return $false
      }
      $startedEvent = $vmEvents | Where-Object -FilterScript {
        $_.GetType().Name -eq 'CustomizationStartedEvent'
      }
      if ($startedEvent)
      {
        Write-Verbose -Message ('Customization for VM {0} has started' -f $VM) 
        return $true
      }
      else
      {
        Start-Sleep -Seconds 5
        $i--
      }
    }
    Write-Warning -Message ('Customization for VM {0} has failed' -f $VM)
    return $false
  }

  # Checks if customization has finished for the VM
  Function Test-CustomizationFinished
  {
    param
    (
      [Parameter(Mandatory)]
      [string]$VM
    )
    Write-Verbose -Message ('Verifying that Customization for VM {0} has finished' -f $VM) 
    $i = 60 # time-out of 5 min
    while($true)
    {
      try {
        $vmEvents = Get-VIEvent -Entity $VM -ErrorAction Stop
      } catch {
        Write-Warning "Failed to get events for VM ${VM}: ${_}"
        return $false
      }
      $SucceededEvent = $vmEvents | Where-Object -FilterScript {
        $_.GetType().Name -eq 'CustomizationSucceeded'
      }
      $FailureEvent = $vmEvents | Where-Object -FilterScript {
        $_.GetType().Name -eq 'CustomizationFailed'
      }
      if ($FailureEvent -or ($i -eq 0))
      {
        Write-Warning  -Message ('Customization of VM {0} failed' -f $VM) 
        return $false
      }
      if ($SucceededEvent)
      {
        Write-Verbose -Message ('Customization of VM {0} Completed Successfully' -f $VM) 
        Start-Sleep -Seconds 30
        Write-Verbose -Message ('Waiting for VM {0} to complete post-customization reboot' -f $VM) 
        try {
          Wait-Tools -VM $VM -TimeoutSeconds 300 -ErrorAction Stop
        } catch {
          Write-Warning "Wait-Tools failed for VM ${VM}: ${_}"
        }
        Start-Sleep -Seconds 30
        return $true
      }
      Start-Sleep -Seconds 5
      $i--
    }
  }

  # Restarts the VM and waits for it to come back online
  Function Restart-VM
  {
    param
    (
      [Parameter(Mandatory)]
      [string]$VM
    )
    try {
      $null = Restart-VMGuest -VM $VM -Confirm:$false -ErrorAction Stop
      Write-Verbose -Message ('Reboot VM {0}' -f $VM) 
      Start-Sleep -Seconds 60
      $null = Wait-Tools -VM $VM -TimeoutSeconds 300 -ErrorAction Stop
      Start-Sleep -Seconds 10
    } catch {
      Write-Warning "Failed to restart VM ${VM}: ${_}"
    }
  }

  # Adds a script to the list of scripts to run in the VM
  function Add-Script
  {
    param
    (
      [Parameter(Mandatory)]
      [string]$script,
      [String[]]$parameters = @(),
      [bool]$reboot = $false
    )
    $i = 1
    foreach ($parameter in $parameters)
    {
      if ($parameter.GetType().Name -eq 'String') 
      {
        $script = $script.replace('%'+[string] $i,'"'+$parameter+'"')
      }
      else                                        
      {
        $script = $script.replace('%'+[string] $i,[string] $parameter)
      }
      $i++
    }
    $script:scripts += ,@($script, $reboot)
  }

  ### READ CREDENTIALS ########################################################################################################
  # Prompt for local and domain credentials with error handling
  try {
    $VMLocalCredential = Get-Credential -Message 'Local Admin Account' -UserName ('{0}\{1}' -f $VmName, $LocalUser) -ErrorAction Stop
    $DomainCredential  = Get-Credential -Message 'Domain Admin Account' -UserName ('{0}\{1}' -f $Domain, $DomainAdmin) -ErrorAction Stop
  } catch {
    Write-Error "Failed to get credentials: $_"
    return
  }

  # Get template and customization spec objects with error handling
  try {
    $SourceVMTemplate = Get-Template -Name $VMTemplate -ErrorAction Stop
    $SourceCustomSpec = Get-OSCustomizationSpec -Name $CustomSpec -ErrorAction Stop
  } catch {
    Write-Error "Failed to get template or customization spec: $_"
    return
  }
}
Process{
  # Configure network if IP is specified
  if ($IP) 
  {
    Add-Script -script 'New-NetIPAddress -InterfaceIndex 2 -IPAddress %1 -PrefixLength %2 -DefaultGateway %3' -parameters @($IP, $SubnetLength, $GW)
    Add-Script -script 'Set-DnsClientServerAddress -InterfaceIndex 2 -ServerAddresses %1' -parameters @($IP_DNS)
  }
  # Join domain if specified
  if ($JoinDomainYN) 
  {
    Add-Script -script 'Add-Computer -DomainName %1 -Credential %2'  -parameters @($Domain , $DomainCredential) -reboot $true
  }
  # Enable File and Printer Sharing
  Add-Script -script 'Import-Module NetSecurity; Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -enabled True'
  # Enable Remote Desktop
  Add-Script -script 'Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -name fDenyTSConnections -Value 0;
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop";
  Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -name UserAuthentication -Value 0'

  # Deploy VM with error handling
  try {
    Write-Verbose -Message ('Deploying Virtual Machine with Name: [{0}] using Template: [{1}] and Customization Specification: [{2}] on cluster: [{3}]' -f $VmName, $SourceVMTemplate, $SourceCustomSpec, $Cluster) 
    Write-Verbose -Message ('New Virtual Machine')
    $NewVmSplat = @{
      Name                = $VmName
      Template            = $SourceVMTemplate
      ResourcePool        = $Cluster
      OSCustomizationSpec = $SourceCustomSpec
      Location            = $Location
      Datastore           = $DataStore
      DiskStorageFormat   = $DiskStorageFormat
    }
    $NewHdSplat = @{
      CapacityGB = $DiskCapacity
      Confirm    = $false
    }
    $null = New-VM @NewVmSplat -ErrorAction Stop
  } catch {
    Write-Error "Failed to create new VM: $_"
    return
  }

  # Get the new VM object
  try {
    $VmHost = Get-VM -Name $VmName -ErrorAction Stop
  } catch {
    Write-Error "Failed to get VM object for ${VmName}: ${_}"
    return
  }

  # Set network adapter
  try {
    Write-Verbose -Message ('Settng Network Adapter')
    $null = $VmHost |
    Get-NetworkAdapter |
    Set-NetworkAdapter -Portgroup $NetworkName -Confirm:$false -ErrorAction Stop
  } catch {
    Write-Warning "Failed to set network adapter for ${VmName}: ${_}"
  }

  # Set memory and CPUs
  try {
    Write-Verbose -Message ('Settingg Memory and CPUs')
    $null = Set-VM -VM $VmName -NumCpu $CPU -MemoryGB $Memory -Confirm:$false -ErrorAction Stop
  } catch {
    Write-Warning "Failed to set memory/CPU for ${VmName}: ${_}"
  }

  # Set up second drive
  try {
    Write-Verbose -Message ('Setting up Second Drive')
    $null = $VmHost |
    Get-HardDisk |
    Where-Object {
      $_.Name -eq 'Hard Disk 1'
    } |
    Set-HardDisk @NewHdSplat -ErrorAction Stop
  } catch {
    Write-Warning "Failed to set up second drive for ${VmName}: ${_}"
  }

  # Power on VM
  try {
    Write-Verbose -Message ('Virtual Machine {0} Deployed. Powering On' -f $VmName) 
    $null = Start-VM -VM $VmName -ErrorAction Stop
  } catch {
    Write-Error "Failed to power on VM ${VmName}: ${_}"
    return
  }

  # Wait for customization to start and finish
  if (-not (Test-CustomizationStarted -VM $VmName)) 
  {
    Write-Error "Customization did not start for $VmName."
    return
  }
  if (-not (Test-CustomizationFinished -VM $VmName)) 
  {
    Write-Error "Customization did not finish for $VmName."
    return
  }

  # Run post-deployment scripts in the VM
  foreach ($script in $scripts)
  {
    try {
      $null = Invoke-VMScript -ScriptText $script[0] -VM $VmName -GuestCredential $VMLocalCredential -ErrorAction Stop
      if ($script[1]) 
      {
        Restart-VM -VM $VmName
      }
    } catch {
      Write-Warning "Failed to run script in VM ${VmName}: ${_}"
    }
  }
}
End{
  ### End of Script ##############################
  Write-Verbose -Message ('Deployment of VM {0} finished' -f $VmName) 
}