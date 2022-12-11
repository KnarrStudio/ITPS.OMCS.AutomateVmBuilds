#requires -Version 3.0 -Modules VMware.VimAutomation.Core
# Deploy Windows Server

#### USER DEFINED VARIABLES #
param(
  [string]$ServerDataFile = '.\Friday-Power\Inputs\ServerDatafile.csv'  
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

  $ServerData = Import-Csv -Path $ServerDataFile

  $LocalUser = 'localAdmin'
  $DomainAdmin = 'domainAdmin'
  $Hostname = $ServerData.Hostname
  $IP = $ServerData.IP
  $SubnetLength = $ServerData.SubnetLength             #Subnetlength IP address, use CIDR (24 means /24 or 255.255.255.0) for VM
  $GW = $ServerData.Gateway                            #Gateway to use for VM
  $IP_DNS = $ServerData.IP_DNS                         #IP address DNS server to use
  #$IP_DNS = '192.168.0.54'   #Test                         #IP address DNS server to use

  $JoinDomainYN = $ServerData.JoinDomain               # True/False
  $Domain = $ServerData.Domain                         #AD Domain to join
  #$JoinDomainYN = $true               # True/False
  #$Domain = 'Test_Domain'                        #AD Domain to join

  $vCenterInstance = $ServerData.vCenterInstance       #vCenter to deploy VM
  $Cluster = $ServerData.Cluster                       #vCenter cluster to deploy VM
  $VMTemplate = $ServerData.VMTemplate                 #vCenter template to deploy VM
  $CustomSpec = $ServerData.CustomSpec                 #vCenter customization to use for VM
  $Location = $ServerData.Location                     #Folderlocation in vCenter for VM
  $DataStore = $ServerData.DataStore                   #Datastore in vCenter to use for VM
  $DiskStorageFormat = $ServerData.DiskStorageFormat   #Diskformtat to use (Thin / Thick) for VM
  $NetworkName = $ServerData.NetworkName               #Portgroup to use for VM
  $Memory = $ServerData.Memory                         #Memory of VM In GB
  $CPU = $ServerData.CPU                               #number of vCPUs of VM
  $DiskCapacity = $ServerData.DiskCapacity             #Disksize of VM in GB

  ### FUNCTION DEFINITIONS ################################################################################################
  Function Test-CustomizationStarted
  {
    param
    (
      [Parameter(Mandatory)]
      [string]$VM
    )
    Write-Verbose -Message ('Verifying that Customization for VM {0} has started' -f $VM)
    $i = 60 #time-out of 5 min
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

  Function Test-CustomizatonFinished
  {
    param
    (
      [Parameter(Mandatory)]
      [string]$VM
    )
    Write-Verbose -Message ('Verifying that Customization for VM {0} has finished' -f $VM) 
    $i = 60 #time-out of 5 min
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
  $VMLocalCredential = Get-Credential -Message 'Local Admin Account' -UserName ('{0}\{1}' -f $Hostname, $LocalUser)
  $DomainCredential  = Get-Credential -Message 'Domain Admin Account' -UserName ('{0}\{1}' -f $Domain, $DomainAdmin)

  $SourceVMTemplate = Get-Template -Name $VMTemplate
  $SourceCustomSpec = Get-OSCustomizationSpec -Name $CustomSpec
}
Process{

  ### DEFINE POWERSHELL SCRIPTS TO RUN IN VM AFTER DEPLOYMENT ############################################################################################################
  if ($IP) 
  {
    Add-Script -script 'New-NetIPAddress -InterfaceIndex 2 -IPAddress %1 -PrefixLength %2 -DefaultGateway %3' -parameters @($IP, $SubnetLength, $GW)
    Add-Script -script 'Set-DnsClientServerAddress -InterfaceIndex 2 -ServerAddresses %1' -parameters @($IP_DNS)
  }
  if ($JoinDomainYN) 
  {
    Add-Script -script 'Add-Computer -DomainName %1 -Credential %2'  -parameters @($Domain , $DomainCredential) -reboot $true
  }
  Add-Script -script 'Import-Module NetSecurity; Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -enabled True'
  Add-Script -script 'Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -name fDenyTSConnections -Value 0;
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop";
  Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -name UserAuthentication -Value 0'

  ### DEPLOY VM ############
  Write-Verbose -Message ('Deploying Virtual Machine with Name: [{0}] using Template: [{1}] and Customization Specification: [{2}] on cluster: [{3}]' -f $Hostname, $SourceVMTemplate, $SourceCustomSpec, $Cluster) 
  Write-Verbose -Message ('New Virtual Machine')

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

  if (-not (Test-CustomizationStarted -VM $Hostname)) 
  {
    break
  }
  if (-not (Test-CustomizatonFinished -VM $Hostname)) 
  {
    break
  }

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