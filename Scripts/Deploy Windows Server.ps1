# Deploy Windows Server 2008 or higher in vCenter

$ServerDataFile = .\Friday-Power\Outputs\ServerDatafile.csv  # Strts line 137
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

#### USER DEFINED VARIABLES ############################################################################################
$Domain = ''              #AD Domain to join
$vCenterInstance = ''     #vCenter to deploy VM
$Cluster = ''             #vCenter cluster to deploy VM
$VMTemplate = ''          #vCenter template to deploy VM
$CustomSpec = ''          #vCenter customization to use for VM
$Location = ''            #Folderlocation in vCenter for VM
$DataStore = ''           #Datastore in vCenter to use for VM
$DiskStorageFormat = ''   #Diskformtat to use (Thin / Thick) for VM
$NetworkName = ''         #Portgroup to use for VM
$Memory = ''                 #Memory of VM In GB
$CPU =        ''            #number of vCPUs of VM
$DiskCapacity =  ''         #Disksize of VM in GB
$SubnetLength =   ''        #Subnetlength IP address to use (24 means /24 or 255.255.255.0) for VM
$GW = ''                  #Gateway to use for VM
$IP_DNS = ''              #IP address DNS server to use

### FUNCTION DEFINITIONS ################################################################################################
Function Check-CustomizationStarted
{
    
  param
  (
    [string]
    $VM
  )
Write-Verbose -Message ('Verifying that Customization for VM {0} has started' -f $VM)
    $i=60 #time-out of 5 min
	while($i -gt 0)
	{
		$vmEvents = Get-VIEvent -Entity $VM
		$startedEvent = $vmEvents | Where-Object { $_.GetType().Name -eq 'CustomizationStartedEvent' }
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

Function Check-CustomizatonFinished
{
    
  param
  (
    [string]
    $VM
  )
Write-Verbose -Message ('Verifying that Customization for VM {0} has finished' -f $VM) 
    $i = 60 #time-out of 5 min
	while($true)
	{
		$vmEvents = Get-VIEvent -Entity $VM
		$SucceededEvent = $vmEvents | Where-Object { $_.GetType().Name -eq 'CustomizationSucceeded' }
        $FailureEvent = $vmEvents | Where-Object { $_.GetType().Name -eq 'CustomizationFailed' }
		if ($FailureEvent -or ($i -eq 0))
		{
			Write-Warning  -Message ('Customization of VM {0} failed' -f $VM) 
            return $False
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
    [string]
    $VM
  )
$null = Restart-VMGuest -VM $VM -Confirm:$false
    Write-Verbose -Message ('Reboot VM {0}' -f $VM) 
    Start-Sleep -Seconds 60
    $null = Wait-Tools -VM $VM -TimeoutSeconds 300
    Start-Sleep -Seconds 10
}

function Add-Script([string] $script,$parameters=@(),[bool] $reboot=$false){
    $i=1
    foreach ($parameter in $parameters)
    {
        if ($parameter.GetType().Name -eq 'String') {$script=$script.replace("%"+[string] $i,'"'+$parameter+'"')}
        else                                        {$script=$script.replace("%"+[string] $i,[string] $parameter)}
        $i++
    }
    $script:scripts += ,@($script,$reboot)
}


#### Start Script ##############################################################################################
Clear-Host
Write-Verbose -Message 'Deploy Windows server'

$ServerData = Import-Csv $ServerDataFile
$Hostname = $ServerData.Hostname
$IP = $ServerData.IP
$JoinDomainYN = $ServerData.JoinDomain # 

### READ CREDENTIALS ########################################################################################################
Get-Content -Path credentials.txt | Foreach-Object{
   $var = $_.Split('=')
   Set-Variable -Name $var[0].trim('" ') -Value $var[1].trim('" ')
}
$VMLocalUser = ('{0}\{1}' -f $Hostname, $LocalUser)
$VMLocalPWord = ConvertTo-SecureString -String $LocalPassword -AsPlainText -Force
$VMLocalCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $VMLocalUser, $VMLocalPWord

$SourceVMTemplate = Get-Template -Name $VMTemplate
$SourceCustomSpec = Get-OSCustomizationSpec -Name $CustomSpec

### DEFINE POWERSHELL SCRIPTS TO RUN IN VM AFTER DEPLOYMENT ############################################################################################################
if ($IP) {
Add-Script - "New-NetIPAddress -InterfaceIndex 2 -IPAddress %1 -PrefixLength %2 -DefaultGateway %3" @($IP, $SubnetLength, $GW)
Add-Script "Set-DnsClientServerAddress -InterfaceIndex 2 -ServerAddresses %1" @($IP_DNS) }
if ($JoinDomainYN.ToUpper() -eq "Y") {
Add-Script '$DomainUser = %1;
            $DomainPWord = ConvertTo-SecureString -String %2 -AsPlainText -Force;
            $DomainCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $DomainUser, $DomainPWord;
             Add-Computer -DomainName %3 -Credential $DomainCredential' @("$Domain\$DomainAdmin",$DomainAdminPassword, $Domain) $true }
Add-Script 'Import-Module NetSecurity; Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -enabled True'
Add-Script 'Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -name fDenyTSConnections -Value 0;
            Enable-NetFirewallRule -DisplayGroup "Remote Desktop";
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -name UserAuthentication -Value 0'

### DEPLOY VM ############
Write-Verbose -Message ('Deploying Virtual Machine with Name: [{0}] using Template: [{1}] and Customization Specification: [{2}] on cluster: [{3}]' -f $Hostname, $SourceVMTemplate, $SourceCustomSpec, $cluster) 
Write-Verbose -Message ('New Virtual Machine')

$NewVmSplat = @{
  Name = $Hostname
  Template = $SourceVMTemplate
  ResourcePool = $cluster
  OSCustomizationSpec = $SourceCustomSpec
  Location = $Location
  Datastore = $Datastore
  DiskStorageFormat = $DiskStorageFormat
}
$NewHdSplat = @{
  CapacityGB = $DiskCapacity
  Confirm = $false
}
$null = New-VM @NewVmSplat

$VmHost = Get-VM -Name $Hostname
Write-Verbose -Message ('Settng Network Adapter')
$null =  $VmHost | Get-NetworkAdapter | Set-NetworkAdapter -Portgroup $NetworkName -confirm:$false

Write-Verbose -Message ('Settingg Memory and CPUs')
$null = Set-VM -VM $Hostname -NumCpu $CPU -MemoryGB $Memory -Confirm:$false

Write-Verbose -Message ('Setting up Second Drive')
$null = $VmHost | Get-HardDisk | Where-Object {$_.Name -eq 'Hard Disk 1'} | Set-HardDisk @NewHdSplat

Write-Verbose -Message ('Virtual Machine {0} Deployed. Powering On' -f $Hostname) 
$null = Start-VM -VM $Hostname

if (-not (Check-CustomizationStarted -VM $Hostname)) { break }
 if (-not (Check-CustomizatonFinished -VM $Hostname)) { break }

foreach ($script in $scripts)
{
    $null = Invoke-VMScript -ScriptText $script[0] -VM $Hostname -GuestCredential $VMLocalCredential
    if ($script[1]) {Restart-VM -VM $Hostname}
}

### End of Script ##############################
Write-Verbose -Message ('Deployment of VM {0} finished' -f $Hostname) 