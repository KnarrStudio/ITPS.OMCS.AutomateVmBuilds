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
#requires -Version 3.0 -Modules VMware.VimAutomation.Core
# Deploy Windows Server

#### USER DEFINED VARIABLES #
param(
  [string]$ServerDataFile = '.\Friday-Power\Inputs\ServerDatafile.csv'  # Path to CSV with server deployment data
  #$Hostname = $ServerData.Hostname
  #$IP = $ServerData.IP
  #$JoinDomainYN = True/False
  <#
      Credentials

      DomainAdmin = "<domain admin username>"
      DomainAdminPassword = "<password domain admin user>"
      LocalUser = "<local admin username>"
      LocalPassword = "<password local admin user>"
      vCenterUser = "administrator@vsphere.local"
      vCenterPass = "<password vCenter admin>"
  #>
)

Begin{
  Clear-Host
  Write-Verbose -Message 'Deploy Windows server'

  # Initialize the scripts array for Add-Script
  $scripts = @()

  # Import server data from CSV
  $ServerData = Import-Csv -Path $ServerDataFile

  # Assign variables from imported data
  $LocalUser = 'localAdmin'
  $DomainAdmin = 'domainAdmin'
  $Hostname = $ServerData.Hostname
  $IP = $ServerData.IP
  $SubnetLength = $ServerData.SubnetLength             # Subnet length in CIDR notation
  $GW = $ServerData.Gateway                            # Gateway address
  $IP_DNS = $ServerData.IP_DNS                         # DNS server address
  #$IP_DNS = '192.168.0.54'   #Test

  $JoinDomainYN = $ServerData.JoinDomain               # Should the VM join a domain?
  $Domain = $ServerData.Domain                         # Domain to join
  #$JoinDomainYN = $true
  #$Domain = 'Test_Domain'

  $vCenterInstance = $ServerData.vCenterInstance       # vCenter instance
  $Cluster = $ServerData.Cluster                       # vCenter cluster
  $VMTemplate = $ServerData.VMTemplate                 # VM template
  $CustomSpec = $ServerData.CustomSpec                 # Customization spec
  $Location = $ServerData.Location                     # Folder location in vCenter
  $DataStore = $ServerData.DataStore                   # Datastore
  $DiskStorageFormat = $ServerData.DiskStorageFormat   # Disk format (Thin/Thick)
  $NetworkName = $ServerData.NetworkName               # Network portgroup
  $Memory = $ServerData.Memory                         # Memory in GB
  $CPU = $ServerData.CPU                               # Number of vCPUs
  $DiskCapacity = $ServerData.DiskCapacity             # Disk size in GB

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
      $vmEvents = Get-VIEvent -Entity $VM
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
      $vmEvents = Get-VIEvent -Entity $VM
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
        Wait-Tools -VM $VM -TimeoutSeconds 300
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
    $null = Restart-VMGuest -VM $VM -Confirm:$false
    Write-Verbose -Message ('Reboot VM {0}' -f $VM) 
    Start-Sleep -Seconds 60
    $null = Wait-Tools -VM $VM -TimeoutSeconds 300
    Start-Sleep -Seconds 10
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
    #$script:scripts = $null
  }


  ### READ CREDENTIALS ########################################################################################################
  # Prompt for local and domain credentials
  $VMLocalCredential = Get-Credential -Message 'Local Admin Account' -UserName ('{0}\{1}' -f $Hostname, $LocalUser)
  $DomainCredential  = Get-Credential -Message 'Domain Admin Account' -UserName ('{0}\{1}' -f $Domain, $DomainAdmin)

  # Get template and customization spec objects
  $SourceVMTemplate = Get-Template -Name $VMTemplate
  $SourceCustomSpec = Get-OSCustomizationSpec -Name $CustomSpec
}
Process{

  ### DEFINE POWERSHELL SCRIPTS TO RUN IN VM AFTER DEPLOYMENT ############################################################################################################
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

  ### DEPLOY VM ############
  Write-Verbose -Message ('Deploying Virtual Machine with Name: [{0}] using Template: [{1}] and Customization Specification: [{2}] on cluster: [{3}]' -f $Hostname, $SourceVMTemplate, $SourceCustomSpec, $Cluster) 
  Write-Verbose -Message ('New Virtual Machine')

  # Prepare parameters for New-VM and Set-HardDisk
  $NewVmSplat = @{
    Name                = $Hostname
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
  $null = New-VM @NewVmSplat

  # Get the new VM object
  $VmHost = Get-VM -Name $Hostname
  Write-Verbose -Message ('Settng Network Adapter')
  $null = $VmHost |
  Get-NetworkAdapter |
  Set-NetworkAdapter -Portgroup $NetworkName -Confirm:$false

  Write-Verbose -Message ('Settingg Memory and CPUs')
  $null = Set-VM -VM $Hostname -NumCpu $CPU -MemoryGB $Memory -Confirm:$false

  Write-Verbose -Message ('Setting up Second Drive')
  $null = $VmHost |
  Get-HardDisk |
  Where-Object {
    $_.Name -eq 'Hard Disk 1'
  } |
  Set-HardDisk @NewHdSplat

  Write-Verbose -Message ('Virtual Machine {0} Deployed. Powering On' -f $Hostname) 
  $null = Start-VM -VM $Hostname

  # Wait for customization to start and finish
  if (-not (Test-CustomizationStarted -VM $Hostname)) 
  {
    break
  }
  if (-not (Test-CustomizationFinished -VM $Hostname)) 
  {
    break
  }

  # Run post-deployment scripts in the VM
  foreach ($script in $scripts)
  {
    $null = Invoke-VMScript -ScriptText $script[0] -VM $Hostname -GuestCredential $VMLocalCredential
    if ($script[1]) 
    {
      Restart-VM -VM $Hostname
    }
  }
}
End{
  ### End of Script ##############################
  Write-Verbose -Message ('Deployment of VM {0} finished' -f $Hostname) 
}