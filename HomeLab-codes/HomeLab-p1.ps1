###################################################################
# vWorld
# lab Constructor
# Created by: Łukasz Tworek
# QA: 
#
# 
###################################################################

####################################################
#	variables
####################################################

#MyVMware Credentials
$myUsername = ""
$myPassword = ""

#Host
$localPath = "C:\HomeLabFull"

#ESXI
$esxiHost = "192.168.100.100"
$esxiU = "root"
$esxiP = "VMware1!"

$esxiDatastore = "OS-Data"
$networkName = "VM Network"
$vmPortGroup = "HomeLab"


#jumper
$jumpName = "prereqVM"
$prereqVmIp = "192.168.100.180"
$prereqVmNet = "24"
$prereqVmGw = "192.168.100.4"
$prereqVmDns = "8.8.8.8"

$prereqVmU = "root"
$prereqVmP = "changeme"
$prereqVmPassword = ConvertTo-SecureString $prereqVmP -AsPlainText -Force
$credentialsPrereqVM = New-Object System.Management.Automation.PSCredential($prereqVmU, $prereqVmPassword)

#Global
$globalIPOctet = "192.168.1"

#esxi_nested
$ssdstore_size_GB = "40"
$hddstore_size_GB = "80"
$osstore_size_GB = "20"
$vSphereISO = "VMware-VMvisor-Installer-7.0b-16324942.x86_64.iso"
$vCenterISO = "VMware-VCSA-all-7.0.3-21477706.iso"

#vcsa
$vcsaP = "VMware1!"
$vcsaName = "hl-vcsa.vworld.domain.lab"
$vcsaU = "Administrator@vsphere.local"
$vcsaP = "VMware1!"

####################################################
#	Prerequisits
####################################################

# Specify log file path
$logPath = "$localPath\logs\script.log"

# Create log file if it doesn't exist
if (-not (Test-Path $logPath)) {
    New-Item -ItemType File -Path $logPath -Force | Out-Null
}

function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO'
    )
    $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[ $FormattedDate ] [$Level] $Message"
    Add-Content -Path $logPath -Value $LogMessage
    Write-Host $LogMessage
}


####################################################
#	Prerequisits
####################################################



# Check if NuGet package provider is installed
if ((Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue) -eq $null) {
    try {
        Install-PackageProvider -Name NuGet -Force -Confirm:$false
        Write-Log -Level INFO -Message "NuGet package provider installed successfully"
    } catch {
        Write-Log -Message "Error installing NuGet package provider: $_" -Level ERROR
    }
} else {
    Write-Log -Message "NuGet package provider is already installed" -Level INFO
}

# Check if Posh-SSH module is installed
if ((Get-Module -Name Posh-SSH -ListAvailable -ErrorAction SilentlyContinue) -eq $null) {
    try {
        Install-Module -Name Posh-SSH -Scope AllUsers -Force -Confirm:$false 
        Write-Log -Level INFO -Message "Posh-SSH module installed successfully"
    } catch {
        Write-Log -Message "Error installing Posh-SSH module: $_" -Level ERROR
    }
} else {
    Write-Log -Message "Posh-SSH module is already installed" -Level INFO
}

# Check if VMware PowerCLI module is installed
if ((Get-Module -Name VMware.PowerCLI -ListAvailable -ErrorAction SilentlyContinue) -eq $null) {
    try {
        Install-Module -Name VMware.PowerCLI -Scope AllUsers -Force -Confirm:$false 
        Write-Log -Level INFO -Message "VMware PowerCLI module installed successfully"
    } catch {
        Write-Log -Message "Error installing VMware PowerCLI module: $_" -Level ERROR
    }
} else {
    Write-Log -Message "VMware PowerCLI module is already installed" -Level INFO
}

# Log completion message
Write-Log "Package installation completed" -Level INFO

Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false
Set-PowerCLIConfiguration -DefaultVIServerMode Single -Confirm:$false

# Download VMware Customer Connect CLI
$vccSDK = "https://github.com/vmware-labs/vmware-customer-connect-cli/releases/download/v1.1.4/vcc-windows-v1.1.4.exe"

# Check if File Downloader Exist 
if (Test-Path "$localPath\vcc.exe") {
    Write-Log -Message "File exists!"
} else {
    Write-Log -Message "File does not exist. Downloading a file." -Level INFO
    try {
        Invoke-WebRequest $vccSDK -OutFile "$localPath\vcc.exe"
        Write-Log -Message "Download successful." -Level INFO
    } catch {
        Write-Log -Message "Download failed." -Level ERROR
        Write-Log -Message $_.Exception.Message -Level ERROR
    }
}
# Download OVF Tool
$ovfSDK = "https://github.com/rgl/ovftool-binaries/raw/main/archive/VMware-ovftool-4.5.0-20459872-win.x86_64.zip"
$ovfDestinationPath = "C:\Program Files\VMware\VMware OVF Tool\"

# Check if OVF Tool is already downloaded and extracted
if (Test-Path "$ovfDestinationPath\ovftool.exe") {
    Write-Log "OVF Tool is already downloaded and extracted to '$ovfDestinationPath'."
} else {
    Write-Log "OVF Tool is not downloaded or extracted."
    Write-Log "Downloading OVF Tool."
    
    if (Test-Path "$localPath\VMware-ovftool-4.5.0-20459872-win.x86_64.zip") {
        Write-Log "OVF Tool archive file exists!"
    } else {
        Write-Log "OVF Tool archive file does not exist."
        Write-Log "Downloading OVF Tool archive file."
        Invoke-WebRequest $ovfSDK -OutFile "$localPath\VMware-ovftool-4.5.0-20459872-win.x86_64.zip"
        Write-Log "OVF Tool archive file downloaded."
    }

    if (Test-Path "$ovfDestinationPath\ovftool.exe") {
        Write-Log "OVF Tool is already extracted to '$ovfDestinationPath'."
    } else {
        Write-Log "Extracting OVF Tool to '$ovfDestinationPath'."
        Expand-Archive "$localPath\VMware-ovftool-4.5.0-20459872-win.x86_64.zip" -DestinationPath $ovfDestinationPath 
        Write-Log "OVF Tool extracted to '$ovfDestinationPath'."
    }
}



####################################################
#               PhotonOS - jumper
####################################################

# Specify the URL for the PhotonOS download
$url = "https://packages.vmware.com/photon/5.0/Beta/ova/photon-hw11-5.0-9e778f4090.ova"

# Specify the file name for the PhotonOS download
$filename = "photon-hw11-5.0-9e778f4090.ova"

# Check if PhotonOS  Exist 
if (Test-Path "$localPath\$filename") {
    Write-Log "PhotonOS file exists!"
} else {
    Write-Log "PhotonOS file does not exist."
    Write-Log "Downloading PhotonOS file."
	# Download PhotonOS file to the specified location
    Invoke-WebRequest -Uri $url -OutFile "$localPath\$filename"
}

$cloud_config = @"
#cloud-config
hostname: $jumpName
fqdn: $jumpName
timezone: Europe/Berlin
write_files:
  - path: /etc/systemd/network/10-eth0-static-en.network
    permissions: 0644
    content: |
      [Match]
      Name=eth0

      [Network]
      Address=$prereqVmIp/$prereqVmNet
      Gateway=$prereqVmGw
      DNS=$prereqVmDns
runcmd: 
  - systemctl restart systemd-networkd
  - tdnf update -y
bootcmd:
  - /bin/sed -E -i 's/^root:([^:]+):.*$/root:\1:18947:0:99999:0:::/' /etc/shadow
"@


$bytes = [System.Text.Encoding]::UTF8.GetBytes($cloud_config)
$compressedBytes = [System.IO.MemoryStream]::new()
$gzipStream = [System.IO.Compression.GzipStream]::new($compressedBytes, [System.IO.Compression.CompressionMode]::Compress)
$gzipStream.Write($bytes, 0, $bytes.Length)
$gzipStream.Dispose()
$userDataBase64 = [System.Convert]::ToBase64String($compressedBytes.ToArray())

C:\'Program Files'\VMware\'VMware OVF Tool'\ovftool.exe  --noSSLVerify --acceptAllEulas --X:injectOvfEnv --allowExtraConfig --network=”$networkName” `-ds="$esxiDatastore" -n="$jumpName" "$localPath\$filename" vi://"$esxiU":"$esxiP"@$esxiHost

Connect-VIServer $esxiHost -User $esxiU -Password $esxiP

$vm = Get-VM -Name $jumpName

$vm.ExtensionData.Config.ExtraConfig += New-Object VMware.Vim.OptionValue -Property @{Key="guestinfo.userdata";Value=$userDataBase64}
$vm.ExtensionData.Config.ExtraConfig += New-Object VMware.Vim.OptionValue -Property @{Key="guestinfo.userdata.encoding";Value="gzip+base64"}
$spec = New-Object VMware.Vim.VirtualMachineConfigSpec
$spec.ExtraConfig = $vm.ExtensionData.Config.ExtraConfig
$vm.ExtensionData.ReconfigVM($spec)

Start-VM -VM $vm
do{

    Write-Log "Waiting for cloud-init."
    $vm = Get-VM -Name $jumpName
    Start-Sleep -Seconds 10

}until($vm.Guest.HostName -eq $jumpName)


# Disconnect from the vSphere server
Disconnect-VIServer -Server $esxiHost -Confirm:$false


####################################################
#               Create PortGroup on ESXI
####################################################
Connect-VIServer $esxiHost -User $esxiU -Password $esxiP

# Get all virtual switches
$virtualSwitches = Get-VirtualSwitch -VMHost $esxiHost -Standard
$vm = Get-VM -Name $jumpName

# Loop through the virtual switches
foreach ($vswitch in $virtualSwitches) 
{
    # Check if the virtual switch has at least one port group and one NIC
    if ($vswitch.ExtensionData.Portgroup.Count -gt 0 -and $vswitch.Nic.Count -gt 0) 
    {
        if (-not (Get-VirtualPortGroup -Name "$vmPortGroup" -ErrorAction SilentlyContinue)) {
            New-VirtualPortGroup -Name "$vmPortGroup" -VirtualSwitch $vswitch -Confirm:$false
        } else {
            Write-Log "The port group $vmPortGroup already exists."
        }
        
        # Wait for the port group to become accessible
        $portGroup = Get-VirtualPortGroup -Name "$vmPortGroup" -VirtualSwitch $vswitch -ErrorAction SilentlyContinue
        $timeout = 30  # seconds
        if ($portGroup -eq $null) 
        {
            do{
                $portGroup = Get-VirtualPortGroup -Name "$vmPortGroup" -VirtualSwitch $vswitch -ErrorAction SilentlyContinue
                if ($portGroup -eq $null) 
                {
                    Start-Sleep -Seconds 1
                }
            } until (($portGroup -ne $null) -or ((Get-Date) - $startTime).TotalSeconds -ge $timeout)
        }
        
        if ($portGroup -eq $null) 
        {
            $errorMessage = "Failed to create port group '$portGroup' on virtual switch '$($vswitch.Name)' within $timeout seconds."
            Write-Log -Level ERROR -Message $errorMessage
            Write-Host $errorMessage
        } else 
        {
            $successMessage = "Port group '$portGroup' was created successfully on virtual switch '$($vswitch.Name)'."
            Write-Log -Level INFO -Message $successMessage
            Write-Host $successMessage

            # Assign the port group to the VM

            New-NetworkAdapter -VM $vm -NetworkName "$vmPortGroup" -StartConnected
            $adapter = Get-NetworkAdapter -VM $vm -Name "$vmPortGroup" -ErrorAction SilentlyContinue
            $timeout = 30  # seconds
            if ($adapter -eq $null) 
            {
            do{
                    $adapter = Get-NetworkAdapter -VM $vm -Name "$vmPortGroup" -ErrorAction SilentlyContinue
                    if ($adapter -eq $null) 
                    {
                        Start-Sleep -Seconds 1
                    }
                } until (($adapter -ne $null) -or ((Get-Date) - $startTime).TotalSeconds -ge $timeout)
            }
            Write-Log "Port group '$vmPortGroup' was assigned successfully to VM '$vmName'."
        }
    }
}
# Disconnect from the vSphere server
Disconnect-VIServer -Server $esxiHost -Confirm:$false


####################################################
#               PhotonOS - jumper - SETUP
####################################################
Start-Sleep -Seconds 30

$session = New-SSHSession -ComputerName $prereqVmIp -Credential $credentialsPrereqVM  -AcceptKey -Force


# IP address on second interface
$text = @"
[Match]
Name=eth1

[Network]
Address=$globalIPOctet.2/24
DNS=$globalIPOctet.2
"@

$text = $text -replace "`r`n", "`n"

Write-Log "Removing old network configuration."
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "rm /etc/systemd/network/99-dhcp-en.network"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null
Write-Log "Updating network configuration."
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "echo '$text' > /etc/systemd/network/50-eth1-static-en.network"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "chmod 644 /etc/systemd/network/50-eth1-static-en.network"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "systemctl restart systemd-networkd"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null
Start-Sleep -Seconds 15

Write-Log "Disabling firewall."
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "iptables-legacy -A INPUT -j ACCEPT;iptables-legacy -A OUTPUT -j ACCEPT;iptables-legacy -A FORWARD -j ACCEPT" 
# Log the output of the command
if ($output.Output) {
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "iptables-legacy-save >/etc/systemd/scripts/ip4save" 
# Log the output of the command
if ($output.Output) {
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null



#remove lock file if exist
Write-Log "Removing lock file if it exists."
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "rm -f /var/run/.tdnf-instance-lockfile"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null
Write-Log "Updating package list."
#install required packages for PXE
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "tdnf update" 
# Log the output of the command
if ($output.Output) {
    Write-Log -Message $output.Output -Level INFO
}
if (($output.Error) -and ($output.Error -like "*Nothing to do*")){
    Write-Log -Message $output.Error -Level INFO
}

# Clear the $output variable
$output = $null
Write-Log "Installing required packages for PXE."
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "tdnf install -y dhcp-server atftp syslinux wget tar ntp" 
# Log the output of the command
if($output.GetType().Name -eq "String")
{
    if ($output.Output) {
        Write-Log -Message $output.Output -Level INFO
    }
    if ($output.Error) {
        Write-Log -Message $output.Error -Level ERROR
    }
}


# Clear the $output variable
$output = $null


#setup DHCP Server
Write-Log "Setting up DHCP Server."
$dhcpConf = @"
subnet $globalIPOctet.0 netmask 255.255.255.0 {
  range $globalIPOctet.100 $globalIPOctet.200;
  option routers $globalIPOctet.2;
  option domain-name-servers 8.8.8.8, 8.8.4.4;
  filename "pxelinux.0";
}
"@
$dhcpConf = $dhcpConf -replace "`r`n", "`n"
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "echo '$dhcpConf' > /etc/dhcp/dhcpd.conf"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null

$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "echo 'INTERFACES=eth1' >> /etc/default/dhcpd"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null
Write-Log "DHCP Server setup completed successfully."


#setup TFTP
Write-Log "Setting up TFTP Server."
$tftpdConf = @"
[Unit]
Description=Advanced TFTP server
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/atftpd --user tftp --group tftp --daemon --no-fork --bind-address $globalIPOctet.2 /var/lib/tftpboot
Restart=always

[Install]
WantedBy=multi-user.target
"@
$tftpdConf = $tftpdConf -replace "`r`n", "`n"
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "echo '$tftpdConf' > /usr/lib/systemd/system/atftpd.service"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "Successfully wrote tftpd configuration to /usr/lib/systemd/system/atftpd.service" -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Failed to write tftpd configuration to /usr/lib/systemd/system/atftpd.service. Error: $($output.Error)" -Level ERROR
}

# Clear the $output variable
$output = $null

$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "systemctl daemon-reload;systemctl enable atftpd.service;systemctl start atftpd.service"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "Successfully reloaded daemon, enabled and started atftpd service" -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Failed to reload daemon, enable and start atftpd service. Error: $($output.Error)" -Level ERROR
}

# Clear the $output variable
$output = $null
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "systemctl restart dhcp.service; systemctl restart atftpd.service" 
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "Successfully restarted dhcp and atftpd services" -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Failed to restart dhcp and atftpd services. Error: $($output.Error)" -Level ERROR
}

# Clear the $output variable
$output = $null
Write-Log "TFTP Server setup completed successfully."



#CreatePXE Setup
Write-Log "Setting up PXE."
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "mkdir -p /var/lib/tftpboot/pxelinux.cfg/"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "chmod a+r /var/lib/tftpboot/pxelinux.cfg"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null


$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "mkdir -p /var/lib/tftpboot/images/esx"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "chmod a+r /var/lib/tftpboot/images/esx"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null

$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "cp /usr/share/syslinux/pxelinux.0 /var/lib/tftpboot/"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "cp /usr/share/syslinux/menu.c32 /var/lib/tftpboot/images/esx"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null

#ISO DOWNLOAD
# Check if ESXI ISO Exist 
Write-Log "ESXi ISO Downloading!"
if (Test-Path "$localPath\$vSphereISO") {
    Write-Log "File exists!"
} else {
    Write-Log "ESXi ISO file does not exist."
	Write-Log "Downloading a file"
	$downloadvSphere = "$localPath\vcc.exe download -p vmware_vsphere -s esxi -v 7.* -f $vSphereISO --accepteula --user ""$myUsername"" --pass ""$myPassword"" --output ""$localPath\"""
	$output = Invoke-Expression $downloadvSphere
}

# Test connection to ESXi host
if (Test-Connection $esxiHost -Count 1 -Quiet) {
    Write-Log "Successfully tested connection to $esxiHost." -Level INFO
} else {
    Write-Log "Failed to connect to $esxiHost. Ensure that it is reachable and try again." -Level ERROR
    return
}

try {
    # Connect to the ESXi host
    Connect-VIServer $esxiHost -User $esxiU -Password $esxiP -ErrorAction Stop

    # Log success
    Write-Log "Successfully connected to $esxiHost." -Level INFO
} catch {
    # Log error
    Write-Log "Failed to connect to $esxiHost. $($Error[0].Exception.Message)" -Level ERROR
    return
}

# Get the virtual machine object
$vm = Get-VM -Name $jumpName

# Check if VM exists
if (!$vm) {
    Write-Log "Failed to find VM with name $jumpName." -Level ERROR
    return
}

# Log success
Write-Log "Successfully found VM with name $jumpName." -Level INFO


Copy-VMGuestFile -Source "$localPath\VMware-VMvisor-Installer-7.0b-16324942.x86_64.iso" -Destination "/var/lib/tftpboot/images/esx" -VM $vm -LocalToGuest -GuestUser $prereqVmU -GuestPassword $prereqVmP 
Write-Log "Successfully copied $sourcePath to $destinationPath on VM $jumpName." -Level INFO

# Disconnect from the ESXi host
Disconnect-VIServer -Confirm:$false
# Log that the connection has been closed
Write-Log "Disconnected from $esxiHost"

#unpack ISO

Write-Log -Message "Unpacking ISO..." -Level INFO
$unpackISO = @"
mkdir ~/iso;
mount -o loop /var/lib/tftpboot/images/esx/VMware-VMvisor-Installer-7.0b-16324942.x86_64.iso ~/iso;
cp -rf ~/iso/* /var/lib/tftpboot/images/esx/;
umount ~/iso;
"@
$unpackISO = $unpackISO -replace "`r`n", "`n"
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "$unpackISO"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "Unpack ISO command completed." -Level INFO
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Unpack ISO command failed." -Level ERROR
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null

# Prepare files
Write-Log -Message "Preparing files..." -Level INFO
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "sed -i 's/\///g' /var/lib/tftpboot/images/esx/boot.cfg"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "Prepare files command completed." -Level INFO
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Prepare files command failed." -Level ERROR
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "sed -i 's/prefix=/prefix=\/images\/esx\//' /var/lib/tftpboot/images/esx/boot.cfg"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "Prepare files command completed." -Level INFO
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Prepare files command failed." -Level ERROR
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null

#prepare PXE setup
$esxBoot = @"
default menu.c32
prompt 0
timeout 300

menu title PXE Boot Menu
menu color border 0 #00000000 #00000000 none

label ESXI-Install
    menu label ESXI
    COM32 pxechn.c32
    kernel images/esx/mboot.c32
    APPEND -c images/esx/boot.cfg ks=http://$globalIPOctet.2/ks.cfg
    IPAPPEND 2
LABEL hddboot
    LOCALBOOT 0x80
    MENU LABEL ^Boot from local disk
"@
$esxBoot = $esxBoot -replace "`r`n", "`n"




# Log the start of the task
Write-Log -Message "Starting to setup PXE environment" -Level INFO

# Set default boot options and copy necessary files
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "echo '$esxBoot' > /var/lib/tftpboot/pxelinux.cfg/default"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "Default boot options set successfully" -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Failed to set default boot options" -Level ERROR
}
$output = $null
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "cp /usr/share/syslinux/pxechn.c32 /var/lib/tftpboot/"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "Necessary files copied successfully" -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Failed to copy necessary files" -Level ERROR
}

# Download and extract PXE component
$output = $null
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "wget https://github.com/vWorldLukasz/vmware/raw/main/vmware.tar -P /var/lib/tftpboot/"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "PXE component downloaded successfully" -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Failed to download PXE component" -Level ERROR
}
$output = $null
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "tar -xvf /var/lib/tftpboot/vmware.tar -C /var/lib/tftpboot --strip-components=1"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "PXE component extracted successfully" -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Failed to extract PXE component" -Level ERROR
}

# Set permissions for the PXE directory
$output = $null
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "chown -R tftp:tftp /var/lib/tftpboot/"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "Permissions set for PXE directory" -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Failed to set permissions for PXE directory" -Level ERROR
}
$output = $null
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "chmod -R 755 /var/lib/tftpboot/"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "Permissions set for PXE directory" -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Failed to set permissions for PXE directory" -Level ERROR
}
$output = $null
# Inject Kickstart into boot.cfg
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "sed -i 's/kernelopt=cdromBoot runweasel/kernelopt=ks=ks.cfg/' /var/lib/tftpboot/images/esx/boot.cfg"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "Kickstart injected into boot.cfg successfully" -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Failed to inject Kickstart into boot.cfg" -Level ERROR
}
$output = $null
Write-Log -Message "End of task setup PXE environment" -Level INFO

Start-Sleep -Seconds 10
#Install HTTP server for kickstart
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "tdnf install -y httpd"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "Successfully installed HTTP server for kickstart." -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Failed to install HTTP server for kickstart. Error: $($output.Error)" -Level ERROR
}
Start-Sleep -Seconds 10
# Clear the $output variable
$output = $null
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "systemctl enable httpd;systemctl start httpd"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "Successfully enabled and started HTTP server for kickstart." -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Failed to enable and start HTTP server for kickstart. Error: $($output.Error)" -Level ERROR
}

# Clear the $output variable
$output = $null
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "rm -rf /etc/httpd/html/index.html"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "Successfully removed default index.html file from HTTP server." -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Failed to remove default index.html file from HTTP server. Error: $($output.Error)" -Level ERROR
}

# Clear the $output variable
$output = $null

$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "chmod -R 755 /etc/httpd/html/"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "Successfully set permissions for HTTP server directory." -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Failed to set permissions for HTTP server directory. Error: $($output.Error)" -Level ERROR
}

# Clear the $output variable
$output = $null

#DNS Setup
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "tdnf install unbound -y"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "Successfully installed DNS server." -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Failed to install DNS server. Error: $($output.Error)" -Level ERROR
}

# Clear the $output variable
$output = $null


$dnsFile = @"

server:
    interface: $globalIPOctet.2
    port: 53
    do-ip4: yes
    do-udp: yes
    access-control: $globalIPOctet.0/24 allow
    verbosity: 1

local-zone: "vworld.domain.lab." static
local-data: "hl-vcsa.vworld.domain.lab A $globalIPOctet.9"
local-data: "hl-esxi10.vworld.domain.lab A $globalIPOctet.10"
local-data: "hl-esxi11.vworld.domain.lab A $globalIPOctet.11"
local-data: "hl-esxi12.vworld.domain.lab A $globalIPOctet.12"
local-data: "hl-esxi13.vworld.domain.lab A $globalIPOctet.13"
local-data-ptr: "$globalIPOctet.9 hl-vcsa.vworld.domain.lab"
local-data-ptr: "$globalIPOctet.10 hl-esxi10.vworld.domain.lab"
local-data-ptr: "$globalIPOctet.11 hl-esxi11.vworld.domain.lab"
local-data-ptr: "$globalIPOctet.12 hl-esxi12.vworld.domain.lab"
local-data-ptr: "$globalIPOctet.13 hl-esxi13.vworld.domain.lab"

forward-zone:
   name: "."
   forward-addr: 8.8.4.4
   forward-addr: 8.8.8.8
"@

$dnsFile = $dnsFile -replace "`r`n", "`n"

$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "echo '$dnsFile' > /etc/unbound/unbound.conf"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "systemctl start unbound"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null

$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "systemctl enable unbound"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null

#Setup NTP
$ntpFile = @"

server 0.pl.pool.ntp.org
server 1.pl.pool.ntp.org
server 2.pl.pool.ntp.org
server 3.pl.pool.ntp.org
"@

$ntpFile = $ntpFile -replace "`r`n", "`n"

$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "echo '$ntpFile' >> /etc/ntp.conf"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "systemctl start ntpd"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "systemctl enable ntpd"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null


Remove-SSHSession -SessionId $session.SessionId

####################################################
#               ESXI - nested hosts - SETUP
####################################################

# Connect to the ESXi host
# Test connection to ESXi host
if (Test-Connection $esxiHost -Count 1 -Quiet) {
    Write-Log "Successfully tested connection to $esxiHost." -Level INFO
} else {
    Write-Log "Failed to connect to $esxiHost. Ensure that it is reachable and try again." -Level ERROR
    return
}

try {
    # Connect to the ESXi host
    Connect-VIServer $esxiHost -User $esxiU -Password $esxiP -ErrorAction Stop

    # Log success
    Write-Log "Successfully connected to $esxiHost." -Level INFO
} catch {
    # Log error
    Write-Log "Failed to connect to $esxiHost. $($Error[0].Exception.Message)" -Level ERROR
    return
}
$vmDatastore = Get-Datastore $esxiDatastore

$session = New-SSHSession -ComputerName $prereqVmIp -Credential $credentialsPrereqVM  -AcceptKey -Force
if ($session) {
    Write-Log "SSH session successfully established."
} else {
    Write-Log "Failed to establish SSH session." -Level ERROR
}

# Define the range of numbers to iterate over
$start = 10
$end = 13
for ($i = $start; $i -le $end; $i++) {

##################################################################################################################################
$kickStart=@"
vmaccepteula
install --firstdisk --overwritevmfs --novmfsondisk

network --bootproto=static --device=vmnic0 --ip=$globalIPOctet.$i --netmask=255.255.255.0 --gateway=$globalIPOctet.2 --hostname=hl-esxi$i.vworld.domain.lab --nameserver=$globalIPOctet.2
rootpw VMware1!


reboot

%firstboot --interpreter=busybox

# enable VHV (Virtual Hardware Virtualization to run nested
grep -i "vhv.enable" /etc/vmware/config || echo "vhv.enable = \"TRUE\"" >> /etc/vmware/config
 

# Enable SSH
vim-cmd hostsvc/enable_ssh
vim-cmd hostsvc/start_ssh

#disable ipv6
esxcli network ip set --ipv6-enabled=false

# Enable ESXi Shell
vim-cmd hostsvc/enable_esx_shell
vim-cmd hostsvc/start_esx_shell

# Suppress Shell warning
esxcli system settings advanced set -o /UserVars/SuppressShellWarning -i 1

# NTP
esxcli system ntp set -s $globalIPOctet.2
esxcli system ntp set -e 1

# enter maintenance mode
esxcli system maintenanceMode set -e true

# Needed for configuration changes that could not be performed in esxcli
esxcli system shutdown reboot -d 60 -r "rebooting after host configurations"

"@

$kickStart = $kickStart -replace "`r`n", "`n"

$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "echo '$kickStart' > /etc/httpd/html/ks.cfg"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message $output.Error -Level ERROR
}

# Clear the $output variable
$output = $null

$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "chmod -R 755 /etc/httpd/html/"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "Successfully set permissions for HTTP server directory." -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Failed to set permissions for HTTP server directory. Error: $($output.Error)" -Level ERROR
}

# Clear the $output variable
$output = $null
##################################################################################################################################


# Define virtual machine parameters
$vmName = "hl-esxi$i"

$vmGuestOS = "vmkernel7Guest"
$vmCpuCount = 2
$vmMemoryGB = 48

# Create new virtual machine
Write-Log "Creating virtual machine '$vmName'..."
New-VM -Name $vmName -Datastore $vmDatastore -DiskStorageFormat Thin -DiskGB $osstore_size_GB -MemoryGB $vmMemoryGB  -NumCpu $vmCpuCount -CD -GuestId $vmGuestOS  -Confirm:$false



$vm = Get-VM -Name $vmName
Remove-NetworkAdapter -NetworkAdapter (Get-NetworkAdapter -VM $vm) -Confirm:$false

Start-Sleep -Seconds 30

# Create first SSD on HBA #3
$New_Disk1 = New-HardDisk -vm $vm -CapacityGB $ssdstore_size_GB -StorageFormat Thin -datastore $vmDatastore


# Add one more SSD on HBA #3
$New_Disk2 = New-HardDisk -vm $vm -CapacityGB $hddstore_size_GB -StorageFormat Thin -datastore $vmDatastore


$ExtraOptions = @{
	"disk.EnableUUID"="true";
    "scsi0:1.virtualSSD" = "1";
}

$vmConfigSpec = New-Object VMware.Vim.VirtualMachineConfigSpec

Foreach ($Option in $ExtraOptions.GetEnumerator()) {
    $OptionValue = New-Object VMware.Vim.optionvalue
    $OptionValue.Key = $Option.Key
    $OptionValue.Value = $Option.Value
    $vmConfigSpec.extraconfig += $OptionValue
}

$vmview=get-vm $vmName | get-view
$vmview.ReconfigVM_Task($vmConfigSpec)

Start-Sleep -Seconds 15
# Disable EFI Secure Boot
$spec = New-Object VMware.Vim.VirtualMachineConfigSpec
$bootOptions = New-Object VMware.Vim.VirtualMachineBootOptions
$bootOptions.EfiSecureBootEnabled = $false
$spec.BootOptions = $bootOptions
$vm.ExtensionData.ReconfigVM($spec)
Start-Sleep -Seconds 15

# Change firmware type to BIOS
$spec = New-Object VMware.Vim.VirtualMachineConfigSpec
$spec.Firmware = [VMware.Vim.GuestOsDescriptorFirmwareType]::bios
$vm.ExtensionData.ReconfigVM($spec)

New-NetworkAdapter -VM $vm -NetworkName "$vmPortGroup" -StartConnected:$true -Type "vmxnet3"
Start-Sleep -Seconds 30
New-NetworkAdapter -VM $vm -NetworkName "$vmPortGroup" -StartConnected:$true -Type "vmxnet3"
Start-Sleep -Seconds 30
Start-VM -VM $vm

do{

    Write-Host "Waiting for deployment"
    $vm = Get-VM -Name $vmName
    Start-Sleep -Seconds 20

}until($vm.Guest.HostName -match $vmName)

}
Disconnect-VIServer -Confirm:$false

#Disable DHCP for PXE
$session = New-SSHSession -ComputerName $prereqVmIp -Credential $credentialsPrereqVM -AcceptKey -Force
$output = $null
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "systemctl stop dhcp.service;" 
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "Successfully stopped dhcp services" -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Failed to stop dhcp services. Error: $($output.Error)" -Level ERROR
}
# Close the SSH session
Remove-SSHSession -SessionId $session.SessionId

####################################################
#               vCenter - SETUP
####################################################

# Define variables
$vccSDK = "https://github.com/vmware-labs/vmware-customer-connect-cli/releases/download/v1.1.5/vcc-linux-v1.1.5"


$session = New-SSHSession -ComputerName $prereqVmIp -Credential $credentialsPrereqVM -AcceptKey -Force
$output = $null
#download VCC tool and made is as execute
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "wget $vccSDK -O /tmp/vcc" -ShowStandardOutputStream -ShowErrorOutputStream
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "Successfully download VCC." -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Failed to download VCC. Error: $($output.Error)" -Level ERROR
}

# Clear the $output variable
$output = $null
Invoke-SSHCommand -SessionId $session.SessionId -Command 'chmod +x /tmp/vcc' -ShowStandardOutputStream -ShowErrorOutputStream
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "Successfully set permissions for VCC directory." -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Failed to set permissions for VCC directory. Error: $($output.Error)" -Level ERROR
}

# Clear the $output variable
$output = $null
Invoke-SSHCommand -SessionId $session.SessionId -Command 'mkdir /vcsa' -ShowStandardOutputStream -ShowErrorOutputStream
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "Successfully create directory." -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Failed to create directory. Error: $($output.Error)" -Level ERROR
}

# Clear the $output variable
$output = $null

#download VCSA
Invoke-SSHCommand -SessionId $session.SessionId -Command "/tmp/vcc download -p vmware_vsphere -s vc -v 7.* -f $vCenterISO --accepteula --user $myUsername --pass $myPassword --output /vcsa" -ShowStandardOutputStream -ShowErrorOutputStream -Timeout 2400


#mount ISO

Write-Log -Message "Mounting ISO..." -Level INFO
$unpackISO = @"
mkdir ~/iso-vc;
mount -o loop /vcsa/$vCenterISO ~/iso-vc;
"@
$unpackISO = $unpackISO -replace "`r`n", "`n"
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "$unpackISO"
# Log the output of the command
if ($output.Output) {
    Write-Log -Message "Mount ISO command completed." -Level INFO
    Write-Log -Message $output.Output -Level INFO
}
if ($output.Error) {
    Write-Log -Message "Mount ISO command failed." -Level ERROR
    Write-Log -Message $output.Error -Level ERROR
}


$json = @"
{
    "__version": "2.13.0",
    "new_vcsa": {
        "esxi": {
            "hostname": "$esxiHost",
            "username": "$esxiU ",
            "password": "$esxiP",
            "deployment_network": "$vmPortGroup",
            "datastore": "$esxiDatastore"
        },
        "appliance": {
            "thin_disk_mode": true,
            "deployment_option": "tiny",
            "name": "hl-vcsa"
        },
        "network": {
            "ip_family": "ipv4",
            "mode": "static",
            "system_name": "hl-vcsa.vworld.domain.lab",
            "ip": "$globalIPOctet.9",
            "prefix": "24",
            "gateway": "$globalIPOctet.2",
            "dns_servers": ["$globalIPOctet.2"]
        },
        "os": {
            "password": "$vcsaP",
            "ntp_servers": "$globalIPOctet.2",
            "ssh_enable": false
        },
        "sso": {
            "password": "$vcsaP",
            "domain_name": "vsphere.local"
        }
    },
    "ceip": {
        "settings": {
            "ceip_enabled": true
        }
    }
}
"@



$json = $json -replace "`r`n", "`n"

$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "echo '$json' > /vcsa/template.json"

Invoke-SSHCommand -SessionId $session.SessionId -Command "~/iso-vc/vcsa-cli-installer/lin64/vcsa-deploy install /vcsa/template.json  --accept-eula --acknowledge-ceip --no-ssl-certificate-verification --skip-ovftool-verification -v --log-dir /tmp/log"

# Define the file and pattern to search for
$file = "/tmp/log/workflow_*/vcsa-cli-installer.log"
$pattern_true = "vcsa-deploy execution successfully completed"
$pattern_false = "vCSACliInstallLogger - ERROR "
# Loop until the pattern is found
while ($true) {
    # Get the contents of the file
    $output = Invoke-SSHCommand -SessionId $session.SessionId -Command "tail $file" -ErrorAction SilentlyContinue

    # Search for the pattern in the file contents
    $match_true = $output.Output | Select-String -Pattern $pattern_true
    $match_false = $output.Output | Select-String -Pattern $pattern_false

    # If the pattern is found, exit the loop
    if ($match_true) {
        Write-Host "VCSA Deployment Finished Successfully"
        break
    }
    if ($match_false) {
        Write-Host "VCSA Deplouyment Finished with Error "+$match_false
        break
    }

    # Wait for a few seconds before checking again
    Start-Sleep -Seconds 30
    Write-Host "Waiting for vcsa deployment..."
}



$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "umount ~/iso-vc" -ErrorAction SilentlyContinue
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "rm -rf /vcsa" -ErrorAction SilentlyContinue

# Close the SSH session
Remove-SSHSession -SessionId $session.SessionId


####################################################
#               Accessibility 
####################################################
$session = New-SSHSession -ComputerName $prereqVmIp -Credential $credentialsPrereqVM -AcceptKey -Force

$output = $null

#download VCC tool and made is as execute
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command 'echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/10-ip_forward.conf' -ShowStandardOutputStream -ShowErrorOutputStream
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command 'sysctl -w net.ipv4.ip_forward=1' -ShowStandardOutputStream -ShowErrorOutputStream
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "iptables-legacy -A FORWARD -i eth0 -o eth1 -j ACCEPT" -ShowStandardOutputStream -ShowErrorOutputStream
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "iptables-legacy -t nat -A POSTROUTING -o eth0 -j MASQUERADE" -ShowStandardOutputStream -ShowErrorOutputStream
$output = Invoke-SSHCommand -SessionId $session.SessionId -Command "iptables-legacy-save > /etc/systemd/scripts/ip4save" -ShowStandardOutputStream -ShowErrorOutputStream


route add "$globalIPOctet.0" mask "255.255.255.0" "$prereqVmIp"
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "`n$globalIPOctet.10 hl-esxi10.vworld.domain.lab hl-esxi10"
Start-Sleep -Seconds 2
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "$globalIPOctet.11 hl-esxi11.vworld.domain.lab hl-esxi11"
Start-Sleep -Seconds 2
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "$globalIPOctet.12 hl-esxi12.vworld.domain.lab hl-esxi12"
Start-Sleep -Seconds 2
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "$globalIPOctet.13 hl-esxi13.vworld.domain.lab hl-esxi13"
Start-Sleep -Seconds 2
Add-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "$globalIPOctet.9 hl-vcsa.vworld.domain.lab hl-vcsa"

Remove-SSHSession -SessionId $session.SessionId


####################################################
#               Setup vCenter
####################################################

# Define variables for the virtual machine name and the ESXi host name
$vmNames = @("hl-esxi10","hl-esxi11","hl-esxi12","hl-esxi13")

Connect-VIServer $esxiHost -User $esxiU -Password $esxiP

foreach($vmName in $vmNames)
{
    # Get the virtual machine object
    $vm = Get-VM -Name $vmName 

    # Check if the virtual machine is running
    if ($vm.PowerState -eq "PoweredOn") {
        # If the virtual machine is running, shut it down
        Stop-VM -VM $vm -Confirm:$false
    }

    # Enable virtualization extensions on the virtual machine
    $spec = New-Object VMware.Vim.VirtualMachineConfigSpec
    $spec.nestedHVEnabled = $true
    $vm.ExtensionData.ReconfigVM($spec)

    $vm | Select-Object Name, @{N="HvEnabled";E={$_.ExtensionData.SystemResources.Config.HostFeatureCapability.FeatureName -contains "hv.capable"}}


    Start-Sleep -Seconds 10
    # Power on the virtual machine
    Start-VM -VM $vm
    Start-Sleep -Seconds 180

}

Disconnect-VIServer -Server  $esxiHost -Confirm:$false

Connect-VIServer $vcsaName -User $vcsaU -Password $vcsaP

$datacenterName = "Datacenter"
$location = "Datacenters"

# Create the new datacenter
New-Datacenter -Name $datacenterName -Location (Get-Folder -Name $location)

# Create the new cluster
$clusterName = "Compute"
$datacenter = Get-Datacenter -Name $datacenterName
New-Cluster -Location $datacenter -Name $clusterName -HAEnabled -DrsEnabled -VsanEnabled


#Add Host
$cluster = Get-Cluster -Name $clusterName -Location $datacenter

$hostList = @("hl-esxi10.vworld.domain.lab","hl-esxi11.vworld.domain.lab","hl-esxi12.vworld.domain.lab","hl-esxi13.vworld.domain.lab")
$hostU = "root"
$hostP = "VMware1!"

foreach($esxihost in $hostList)
{
# Add the host to the cluster
    Add-VMHost -Name $esxihost -Location $cluster -User $hostU -Password $hostP -Force
    Write-Host -ForegroundColor GREEN "Adding ESXi host $esxihost to vCenter"
}

# Get all hosts in maintenance mode
$hosts = Get-VMHost | Where-Object {$_.ConnectionState -eq "Maintenance"}

# Exit maintenance mode for each host
foreach ($node in $hosts) {
    Write-Host "Exiting maintenance mode for host $($node.Name)"
    Set-VMHost -VMHost $node -State Connected
}


#Networking
foreach($esxihost in $hostList)
{
    $vSwitch = Get-VirtualSwitch -Name "vSwitch0" -VMHost $esxihost

    $networkAdapter = Get-VMHostNetworkAdapter -Physical -Name "vmnic1" -VMHost $esxihost
    Add-VirtualSwitchPhysicalNetworkAdapter -VirtualSwitch $vSwitch -VMHostPhysicalNic $networkAdapter -Confirm:$false
}


foreach($esxihost in $hostList)
{
# Get the vSwitch0 and vmkernel network adapter
$vSwitch = Get-VirtualSwitch -Name vSwitch0 -VMHost $esxihost
$vmKernelAdapter = Get-VMHostNetworkAdapter -VMKernel -Name vmk0 -VMHost $esxihost

# Change the MTU size on the vSwitch0 network adapter

Set-VirtualSwitch $vSwitch -Mtu 1600 -Confirm:$false

# Change the MTU size on the vmkernel network adapter

Set-VMHostNetworkAdapter -VirtualNic $vmKernelAdapter -Mtu 1600 -VMotionEnabled $true -VsanTrafficEnabled $true -Confirm:$false
}

#VSAN
foreach($esxihost in $hostList)
{
$vsanHost = Get-VMHost | Where-Object {$_.Name -eq $esxihost}
$luns = $vsanHost | Get-ScsiLun | select CanonicalName, CapacityGB

            foreach ($lun in $luns) {
                if(([int]($lun.CapacityGB)).toString() -eq "40") {
                    $vsanCacheDisk = $lun.CanonicalName
                }
                if(([int]($lun.CapacityGB)).toString() -eq "80")  {
                    $vsanCapacityDisk = $lun.CanonicalName
                }
            }
New-VsanDiskGroup -Server $vcsaName -VMHost $vsanHost -SsdCanonicalName $vsanCacheDisk -DataDiskCanonicalName $vsanCapacityDisk 
}



Disconnect-VIServer -Server $vcsaName -Confirm:$false


#disable VCLS
Connect-VIServer $vcsaName -User $vcsaU -Password $vcsaP
$clusterName = 'Compute'
$vClsPresent = $false

$cluster = Get-Cluster -Name $clusterName
$advName = "config.vcls.clusters.$($cluster.ExtensionData.MoRef.Value).enabled"

$advSetting = Get-AdvancedSetting -Entity $global:DefaultVIServer -Name $advName
if($advSetting){
  Set-AdvancedSetting -AdvancedSetting $advSetting -Value $vClsPresent -Confirm:$false
}
else{
  New-AdvancedSetting -Entity $global:DefaultVIServer -Name $advName -Value $vClsPresent -Confirm:$false
}
Disconnect-VIServer -Server $vcsaName -Confirm:$false


#Clear all alarms
Connect-VIServer $vcsaName -User $vcsaU -Password $vcsaP
$alarmMgr = Get-View AlarmManager

$filter = New-Object VMware.Vim.AlarmFilterSpec

$filter.Status += [VMware.Vim.ManagedEntityStatus]::red
$filter.Status += [VMware.Vim.ManagedEntityStatus]::yellow

$filter.TypeEntity = [VMware.Vim.AlarmFilterSpecAlarmTypeByEntity]::entityTypeAll
$filter.TypeTrigger = [vmware.vim.AlarmFilterSpecAlarmTypeByTrigger]::triggerTypeAll

$alarmMgr.ClearTriggeredAlarms($filter)


Disconnect-VIServer -Server $vcsaName -Confirm:$false
