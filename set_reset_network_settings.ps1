$PSDefaultParameterValues = @{ '*:Encoding' = 'utf8' }

# Enable proxy server. Usage: Set-NetProxy -proxy "ip_address: port"
Function Enable-NetProxy
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [AllowEmptyString()]
        [String[]]$Proxy
    )
    Begin
    # If no proxy server is specified, set the default value
    { if (!$Proxy){ $Proxy = "172.30.0.1:3128" } $regKey="HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" }
    Process
    {
        Set-ItemProperty -path $regKey ProxyEnable -value 1
        Set-ItemProperty -path $regKey ProxyServer -value $Proxy
    }
    End
    { Write-Output "Proxy $Proxy enabled successfully." }
}


# Disable proxy server
Function Disable-NetProxy
{
  Begin
    { $regKey="HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" }
    Process
    {
        Set-ItemProperty -path $regKey ProxyEnable -value 0 -ErrorAction Stop
        Set-ItemProperty -path $regKey ProxyServer -value "" -ErrorAction Stop
        Set-ItemProperty -path $regKey AutoConfigURL -Value "" -ErrorAction Stop       
    }
    End
    { Write-Output "Прокси-сервер виключений" }
}


# Set the IP addresses, gateway and DNS servers for the connection specified in the InterfaceAlias parameter
Function Set-NetSettings
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [AllowEmptyString()]
        [String[]]$alias,
        [Parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [String[]]$IP,
        [Parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [String[]]$gateway,
        [Parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [String[]]$MaskBits,
        [Parameter(Mandatory=$True,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [String[]]$Dns
    )
    Begin
    {
       if (!$alias)
         # If $alias is not specified - select an active connection, otherwise what is specified
         { $adapter = Get-NetAdapter|? {$_.Status -eq "Up"} }
         else { $adapter = Get-NetAdapter | ? {$_.InterfaceAlias -eq "$alias"} }
       # From the selected adapter, we get the connection name
       $alias = $adapter.Name
       $IPType = "IPv4"
    }
    Process
    {
        If (($adapter | Get-NetIPConfiguration).IPv4Address.IPAddress) {
            $adapter | Remove-NetIPAddress -AddressFamily "$IPType" -Confirm:$false | Out-Null
        }
        If (($adapter | Get-NetIPConfiguration).Ipv4DefaultGateway) {
            $adapter | Remove-NetRoute -AddressFamily "$IPType" -Confirm:$false | Out-Null
        }
        # IP-address and gateway
        $adapter | New-NetIPAddress -AddressFamily "$IPType" -IPAddress "$IP" -PrefixLength "$MaskBits" | Out-Null
        # DNS ( multiple DNS can be specified via "," )
        $adapter | Set-DnsClientServerAddress -ServerAddresses "$DNS" | Out-Null
        # Set the gateway address via wmi
        New-NetRoute -InterfaceAlias "$alias" -NextHop "$gateway" -destinationprefix "0.0.0.0/0" -confirm:$false | Out-Null
    }
    End
    { Write-Output "The following parameters are set for the $alias network:`r`n`tІР-address: $IP`r`n`tgateway: $gateway`r`n`tmask: $MaskBits`r`n`tDNS: $dns" }
}


# Reset networks settings - DHCP auto & etc
Function Clear-NetSettings
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [AllowEmptyString()]
        [String[]]$alias
    )
    Begin
    {
       if (!$alias)
         # If $alias is not specified - select an active connection, otherwise what is specified
         { 
	   $mac = (Get-NetAdapter | ? {$_.Status -eq "up"}).MACAddress -replace "-", ":"
	   $adapter = Get-WmiObject -Class Win32_NetworkAdapter -Filter "MACAddress='$mac'" }
         else {
	   $ifDesc = (Get-NetAdapter | ? {$_.InterfaceAlias -eq "$alias"}).InterfaceDescription
	   $adapter = Get-WmiObject -Class Win32_NetworkAdapter -Filter "Name='$ifDesc'" }
    }
    Process
    {
	$Nic = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "Index=$($adapter.Index)"
	# on DHCP
	$Nic.EnableDhcp() | Out-Null
	# clear list of DNS servers
	$Nic.SetDNSServerSearchOrder() | Out-Null
    }
    End
    { Write-Output "Network settings reset (get IP via DHCP, DNS - null, gateway - null)" }
}


# Function for menu output
Function MenuMaker{
    param(
        [string]$Title = $null,
        [parameter(Mandatory=$true,
        ValueFromPipeline = $true)][String[]]$Selections
        )

    $Width = if($Title){$Length = $Title.Length;$Length2 = $Selections|%{$_.length}|Sort -Descending|Select -First 1;$Length2,$Length|Sort -Descending|Select -First 1}else{$Selections|%{$_.length}|Sort -Descending|Select -First 1}
    $Buffer = if(($Width*1.5) -gt 78){(78-$width)/2}else{$width/4}
    if($Buffer -gt 4){$Buffer = 4}
    $MaxWidth = $Buffer*2+$Width+$($Selections.count).length
    $Menu = @()
    $Menu += "╔"+"═"*$maxwidth+"╗"
    if($Title){
        $Menu += "║"+" "*[Math]::Floor(($maxwidth-$title.Length)/2)+$Title+" "*[Math]::Ceiling(($maxwidth-$title.Length)/2)+"║"
        $Menu += "╟"+"─"*$maxwidth+"╢"
    }
    For($i=1;$i -le $Selections.count;$i++){
        $Item = "$i`. "
        $Menu += "║"+" "*$Buffer+$Item+$Selections[$i-1]+" "*($MaxWidth-$Buffer-$Item.Length-$Selections[$i-1].Length)+"║"
    }
    $Menu += "╚"+"═"*$maxwidth+"╝"
    $menu
}

# ====================================================================================================
# Set the parameters for the MenuMaker function, specify the network parameters for Set-NetSettings & etc...
# ====================================================================================================
$menu_elements = @("Set the network settings for Terminal-1",
		     "Set the network settings for Terminal-2",
		     "Set the network settings for Terminal-3",
		     "Reset network settings",
		     "Exit")

$Title = "Select the desired network settings of this terminal"

Do{
    MenuMaker -Title $Title -Selections $menu_elements
    $Selection = Read-Host "Make your choice"
}
While( $Selection -notin (1..$menu_elements.count))

# !!! You need to change the network settings and the menu_elements variable !!!
Switch($Selection){
    1 { Set-NetSettings -IP "192.168.80.1" -gateway "192.168.80.250" -MaskBits "24" -Dns "8.8.8.1,8.8.8.2"
        Enable-NetProxy -Proxy "192.168.80.250:3128" }
    2 { Set-NetSettings -IP "192.168.80.2" -gateway "192.168.80.250" -MaskBits "24" -Dns "8.8.8.1,8.8.8.2"
        Enable-NetProxy -Proxy "192.168.80.250:3128" }
    3 { Set-NetSettings -IP "192.168.80.3" -gateway "192.168.80.250" -MaskBits "24" -Dns "8.8.8.1,8.8.8.2"
        Enable-NetProxy -Proxy "192.168.80.250:3128" }
    4 { Clear-NetSettings -alias "Ethernet"
        Disable-NetProxy
      }
    $menu_elements.count {Continue}
}
