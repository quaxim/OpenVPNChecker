#Version 3.13
$WEBGUI_USER_ut="admin"  #username for Utorrent
$WEBGUI_PASS_ut="" #password for Utorrent
$WEBGUI_PORT_ut=801 #port number for Utorrent
$WEBGUI_USER_qb="admin"  #username for qBittorrent
$WEBGUI_PASS_qb="" #password for qBittorrent
$WEBGUI_PORT_qb=9091 #port number for Qbittorrent
$Checkqbittorentstalled = $True # check if qbittorrent stalled
$Checkqbittorentstalledtimer = 15 # check every 15 minites
$checktime=60 # How often to check if still connected in seconds Default 60
$waittime=0 #how long to wait before starting the script, useful if you need time for the vpn to connect default 0
$ENABLEAUTOCHECK = $True # Set to $True to have the service restart to connect to vpn
$EnabledAdvanceRouting = $True  # Set to $true to use this when you have a static ip address and no dns or gateway assigned to your nic
# EnabledAdvanceRouting only works if $Enableautocheck is is $true
$disableportforwarduser=$False # if you don't want to enable port forwarding
$defaultgateway = "192.168.1.1" # Part of Advance routing, change it to your router's ip address
$Applist = @()
$Applistnum = 1 #Default app list to select 0 = utorrent, 1 = qBittorrent, 2 = other
$Applist += ,@("uTorrent","fnutorrent") # first varaible is name of program, second is function to call
$Applist += ,@("qBittorrent", "fnqbittorrent")
$Applist += ,@("Other", "fnother")
$PIAservernum = 0 #default $PIAserver you wish to connect to Must enable AdvanceRouting
$PIAserver = @() # List 10 servers to connect to.
$PIAserver += ,@("france.privateinternetaccess.com",$true)# First variable is server address, second does it support port forwarding
$PIAserver += ,@("ca-toronto.privateinternetaccess.com",$true) 
$PIAserver += ,@("ca.privateinternetaccess.com",$true)
$PIAserver += ,@("israel.privateinternetaccess.com",$true)
$PIAserver += ,@("nl.privateinternetaccess.com",$true)
$PIAserver += ,@("swiss.privateinternetaccess.com",$true)
$PIAserver += ,@("sweden.privateinternetaccess.com",$true)
$PIAserver += ,@("us-california.privateinternetaccess.com",$false)
$PIAserver += ,@("us-midwest.privateinternetaccess.com",$false)
$PIAserver += ,@("us-east.privateinternetaccess.com",$false)
$PIAportsnum = 0 # set to 0 for UDP, 1 for TCP, default 0
$PIAprotocal = @("udp","tcp")
$PIAStrongEncryption = 2 # set to 2 for strong encryption
$PIAcipher = @() #udp port,tcp port, ciper, certificate, revoke list, auth, description
$PIAcipher += ,@(1194,443, "bf-cbc","ca.crt","crl.pem", "sha1" ,"Legacy Encryption ") #Legacy encryption 
$PIAcipher += ,@(1198,502, "aes-128-cbc","ca.rsa.2048.crt","crl.rsa.2048.pem", "sha1","Standard encryption") #Standard encryption
$PIAcipher += ,@(1197,501, "aes-256-cbc","ca.rsa.4096.crt","crl.rsa.4096.pem", "sha256", "Strong encryption") #Strong encryption
$DNSSERVER = "8.8.8.8" # part of Advance Routing, use any dns server, the default is google dns 8.8.8.8
$pathtoovpn = "C:\Program Files\OpenVPN\config\pia.ovpn" # path to pia opvn file, this scripts edits the file and adds piaserver ip address, change to match yours ovpn location
$disableportforwarduser = $False # to temporary disable port forwarding when connected to a non-port forwarding server
#Script below,  be careful changing anything below this line
$Windowswidth = 100
$WindowsHeight = 26
$host.ui.RawUI.WindowTitle = "PIA Port Forwarding for Utorrent/qBittorrent/Other"
$rand = New-Object  System.Random
$chrstg = "abcdef1234567890"
$servererror = $true
$currentip=''
$saveX = [console]::CursorLeft  
$saveY = 0
$strmoving = '|','/','-','\'    
$startline = 1 #which line to start updating on based on function printsettings()
$emptyspaces = ""
$isprocessactive = $False
$portupdatesuccessful = $False
1..$Windowswidth | % {$emptyspaces += " " }

Function clearscreen ($start, $fullclear = $false) {
    if ($fullclear) {
		clear;
		printsettings;
		[console]::SetCursorPosition($savex,$start)
	} else {
		[console]::SetCursorPosition($savex,$start)
		for ($i=$start; $i -le 11;$i++) {
			Write-host $emptyspaces
			if ([Console]::CursorTop -gt 13 ){break}
		}
		[console]::SetCursorPosition($savex,$start)
	}
}
Function printsettings(){
	write-host "Auto Check / Advance Routing are set to:"$ENABLEAUTOCHECK "/" $EnabledAdvanceRouting
}
Function isNumeric ($x) {
    $x2 = 0
    $isNum = [System.Int32]::TryParse($x, [ref]$x2)
    return $isNum
}
Function listservers{
	$SaveY=[Console]::CursorTop-1
	[console]::SetCursorPosition($saveX,$SaveY+4)
	for ($i = $PIAserver.getlowerbound(0);$i -le $PIAserver.getupperbound(0); $i++){
		$temp = " $i  " +  $PIAserver[$i][0] + $emptyspaces
		write-host $temp.substring(0,45) "Port Forwarding="$PIAserver[$i][1] 
	}
	[console]::SetCursorPosition($saveX,$SaveY)
}
Function AdvanceRouting{
    write "Flushing DNS cache"
    ipconfig /flushdns
    write "Adding temporary route for DNS Server:$DNSSERVER by gateway:$defaultgateway"
    route add $DNSSERVER mask 255.255.255.255 $defaultgateway
    $FullAddressList = nslookup -type=a $PIAserver[$PIAservernum][0] $DNSSERVER
	write "Deleting temporary route to DNS Server:$DNSSERVER by gateway:$defaultgateway"
    route delete $DNSSERVER
 	if (test-path $pathtoovpn) {
        foreach ($line in $FullAddressList)    {
            $tempip = "$line" | %{ $_.Split(" ")[2] }
           	$IsValid = ($tempip -As [IPAddress]) -As [Bool] 
            if ($IsValid -and $tempip -ne $DNSSERVER){
               	write "Adding temporary route for PIA Server:$tempip by gateway:$defaultgateway"
                route add $tempip mask 255.255.255.255 $defaultgateway
                (gc $pathtoovpn) -replace 'remote .*', "remote $tempip $($PIAcipher[$PIAStrongEncryption][$PIAportsnum]) " | sc $pathtoovpn
				(gc $pathtoovpn) -replace 'proto .*' , "proto $($PIAprotocal[$PIAportsnum])" | sc $pathtoovpn
				(gc $pathtoovpn) -replace 'cipher .*', "cipher $($PIAcipher[$PIAStrongEncryption][2])" | sc $pathtoovpn
				(gc $pathtoovpn) -replace 'ca .*', "ca $($PIAcipher[$PIAStrongEncryption][3])" | sc $pathtoovpn
				(gc $pathtoovpn) -replace 'crl-verify .*', "crl-verify $($PIAcipher[$PIAStrongEncryption][4])" | sc $pathtoovpn
                (gc $pathtoovpn) -replace 'auth .*', "auth $($PIAcipher[$PIAStrongEncryption][5])" | sc $pathtoovpn
				write "Updating File:$pathtoovpn to connect to PIA Server"
				write "with ip address:$tempip  $($PIAprotocal[$PIAportsnum]) $($PIAcipher[$PIAStrongEncryption][$PIAportsnum]) $($PIAcipher[$PIAStrongEncryption][6])"
               	return
            }
        }
        write "Not a valid DNS Server, or not a valid gateway, or not a valid PIA Server address"
        Start-Sleep -s 60
    } else {
        write-host "Not a valid path to openvpn config file:$pathtoovpn"
        Start-Sleep -s 60
    }
}
Function setwindowsize {
	$pshost = get-host
	$pswindow = $pshost.ui.rawui
	$psWindow.WindowSize = @{Width=1; Height=1}
	$psWindow.BufferSize = @{Width=$Windowswidth; Height=$WindowsHeight}
	$psWindow.WindowSize = @{Width=$Windowswidth; Height=$WindowsHeight}
}
Function resetadapter{
	Stop-Service OpenVPNService
	if ($EnabledAdvanceRouting) {
		clearscreen $startline  $True
		Write-Host $a.toshorttimestring() "Advance Routing Enabled, resetting up routes to connects to PIA server."
		AdvanceRouting
	}
	Start-Service OpenVPNService
	$ip = ''
	$counter = 0
	while ($ip -eq '') {
		try {
			$ip = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.Description -like "TAP*"}).IPAddress[0]
			Write-Host "VPN Connected, waiting to finish"
			Start-Sleep -s 5
		}
		catch {
			clearscreen $startline  $True
			$counter +=1
			Write-Host "Waiting for VPN to connect" $counter
			Start-Sleep -s 1
		}
	}
	clearscreen $startline $True
}

Function Stop-PIAAdapter {
	Stop-Service OpenVPNService
}
Function fnutorrent{
	try {
		clearscreen ($startline + 1)
		$url="http://" + $ip + ":" + $WEBGUI_PORT_ut + "/gui/"
		$Credential = (New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $WEBGUI_USER_ut,  ($WEBGUI_PASS_ut | ConvertTo-SecureString -AsPlainText -Force ))
		$response = Invoke-WebRequest -Uri $url"token.html"  -Credential $Credential -SessionVariable my_session 
		$token = ($response.tostring()).split('>')[2].split('<')[0]
		$response = Invoke-WebRequest -Uri $url"?action=setsetting&s=bind_port&v=$port&token=$token" -WebSession $my_session 
		$response = (Invoke-WebRequest -Uri $url"?action=getsettings&token=$token" -WebSession $my_session).tostring()
		$response= ($Response.substring($Response.indexof("bind_port")-1)).substring(14)
		clearscreen ($startline + 1)
		Write-Host "Utorrent set to=" $response.Substring(0,$Response.indexof(","))
		return $True
	}
	catch [system.exception] {
		$a = get-date
		write-host $_.Exception.Message
		Write-Host $a.toshorttimestring() "Failed to update port via uTorrent WEBGUI."
		return $False
	}
}
Function fnqbittorrent{
	try {
		clearscreen ($startline + 1)
		$url="http://127.0.0.1:" + $WEBGUI_PORT_qb
		$postParams = "username=$WEBGUI_USER_qb&password=$WEBGUI_PASS_qb"
		$response = Invoke-WebRequest -Uri $url"/login" -Method POST -Body $postParams -Headers @{"Referer"= $url } -SessionVariable my_session
		$postData = 'json={"listen_port":' + $port + '}'
		$Response = Invoke-WebRequest -Uri $url"/command/setPreferences" -Method POST -Body $postData -Headers @{"Referer"= $url} -WebSession $my_session |ConvertFrom-Json
		$Response = Invoke-WebRequest -Uri $url"/query/preferences" -Headers @{"Referer"= $url} -WebSession $my_session |ConvertFrom-Json
		Write-Host "qBitTorrent set to=" $Response.listen_port
		$Response = Invoke-WebRequest -Uri $url"/logout" -Method POST -Body $postParams -Headers @{"Referer"= $url}
		return $True
	}
	catch [system.exception] {
		$a = get-date
		write-host $_.Exception.Message
		Write-Host $a.toshorttimestring() "Failed to update port via qbittorrent WEBGUI."
		Write-Host $a.toshorttimestring() "Check the settings you gave the script for qBitTorrent"
		return $False
		}
	
}
Function fnother{
	try{
		# $port is the varible for port write what you need here
		Write-Host $a.toshorttimestring() "you need to update function fnother to use another application"
		return $True
	}
	catch [system.exception] {
		$a = get-date
		Write-Host $a.toshorttimestring() "Failed to update Other"
		write-Host "Please check the information you've given this script for Other."
		Start-Sleep -s 60
		return $False
	}
}
Function setapp{
	try{
		return invoke-expression  $Applist[$Applistnum][1]
	}
	catch [system.exception] {
		Write-Host $a.toshorttimestring() "Unable to call function script error. This is an unrecoverable error."
		$error[0].ToString() + $error[0].InvocationInfo.PositionMessage
		Start-Sleep -s 60
		return $False
	}
	
}
Function fnqbittorrentstalling{
	try {
		$url = "http://" + $ip + ":" + $WEBGUI_PORT_qb
		$web = New-Object System.Net.WebClient
		$Headers = "Referer=http://" + $ip + ":" + $WEBGUI_PORT_qb
		$postParams = "username=$WEBGUI_USER_qb&password=$WEBGUI_PASS_qb"
		$Response = Invoke-WebRequest -Uri $url"/login" -Method POST -Body $postParams -Headers @{"Referer"="http://" + $ip + ":" + $WEBGUI_PORT_qb}  -SessionVariable my_session
		$Response =  Invoke-WebRequest -Uri $url"/query/torrents?filter=downloading" -Headers @{"Referer"= $url} -WebSession $my_session |ConvertFrom-Json
		$Response1 = Invoke-WebRequest -Uri $url"/query/transferInfo" -Headers @{"Referer"= $url} -WebSession $my_session |ConvertFrom-Json
		$i=0
		foreach ($state in $Response.state){ if ($state  -eq "stalledDL") { $i+=1}}
		if (($i -gt 0) -and ($i -eq $Response.count) -and ($response1.total_peer_connections -eq 0)) 
		{ Write-Host "Qbittorrent is stalled, restarting"
		  $qbitorrentpath = Get-Process "qBittorrent" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
			if($qbitorrentpath -ne $null ) {                 
				$Response=  Invoke-WebRequest -Uri $url"/command/shutdown" -Headers @{"Referer"= $url} -WebSession $my_session
				$SaveY=[Console]::CursorTop
				for ($i = 1; $i -le 24; $i++) {
					[console]::SetCursorPosition($saveX,$SaveY)
					Write-Host "Waiting for qBittorent to close " $i
					Start-Sleep -s 1
					$isitclosed= Get-Process "qBittorrent" -ErrorAction SilentlyContinue 
					if($isitclosed -eq $null ) {
						Write-Host "Restarting qBitTorrent"
						start-process $qbitorrentpath
						Start-Sleep -s 5
						[console]::SetCursorPosition($saveX,$SaveY)
						break
					}
				}
			} else {
				 throw ("Error getting path")
			}
		}
	}
	catch [system.exception] {
		$a = get-date
		write-host $_.Exception.Message
		Write-Host $a.toshorttimestring() "Failed to check for stalled qbittorrent."
		Start-Sleep -s 60
	}
}

setwindowsize
printsettings
if ($waittime -gt 0) {
	Write-Host "Waiting $waittime seconds before continuing"
	Start-Sleep -s $waittime
}

$disableportforward = !$PIAserver[$PIAservernum][1]

while($true) {
	try {
        $ip = (Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object {$_.Description -like "TAP*"}).IPAddress[0]
		if(($ip -ne $currentip) -and (-not $servererror)){
			clearscreen ($startline)
			$servererror = $true
			Write-Host $a.toshorttimestring() "IP Address changed Detected" 
		}
		$currentip = $ip
		$portupdatesuccessful = $false
	}
	catch [system.exception] {
		$a = get-date
		if ($ENABLEAUTOCHECK) {
			clearscreen $startline  $True
			Write-Host $a.toshorttimestring() "VPN is not connected. Restarting service."
			resetadapter
		} else {
			Write-Host $a.toshorttimestring() "VPN is not connected. Checking again in 1 minute."
			Start-Sleep -s 60
		}
		continue
	}

	$ProcessActive = Get-Process $Applist[$Applistnum][0] -ErrorAction SilentlyContinue
	
	if($ProcessActive -eq $null) {
		$isprocessactive = $False
		$portupdatesuccessful = $False
	} else {
		$isprocessactive = $True
	}
	
	if($disableportforward -or $disableportforwarduser) {
		clearscreen $startline 
		$a= get-date
		$servererror = $false
		if ($disableportforward){
			Write-host $a.toshorttimestring() "Port forwarding is disabled on this server."
		} elseif ($disableportforwarduser ){
			Write-host $a.toshorttimestring() "You have disabled port forwarding."
		} 

    } elseif ($servererror) {
		try {
			$a= get-date
			Write-Host $a.toshorttimestring() "Trying to connect to the PIA port server."
			$response = $null
			$CLIENT_ID = ""
			1..64 | % {$CLIENT_ID += $chrstg.substring($rand.next(0,$chrstg.length),1) }
			$response1 = Invoke-WebRequest -URI http://209.222.18.222:2000/?client_id=$CLIENT_ID
			$response = $response1.tostring()
			if ([string]::IsNullOrEmpty($response)  ) {
				Write-Host $a.toshorttimestring() "Did not get a response from the server. Retrying in 1 minute."
				Write-Host $response
			} else {
				$port = $response.Substring($response.IndexOf(":")+1,$response.IndexOf("}")-$response.IndexOf(":")-1)
				if (isNumeric ($port) ) {
					clearscreen ($startline)
					Write-Host "Port given is $port"
					$servererror = $false
				} else {
					clearscreen ($startline)
					Write-Host $a.toshorttimestring() "Server returned an error, you must request the port within 2 minutes of connecting!"
					Write-host -ForegroundColor "Yellow" $a.toshorttimestring() "You are currently set to connect to PIA server" $PIAserver[$PIAservernum][0]"."
				}
			}
			if ($servererror) {Start-Sleep -s 10}
		}
		catch [system.exception] {
			$a= get-date
			if ($ENABLEAUTOCHECK) {
				$error[0].ToString() + $error[0].InvocationInfo.PositionMessage
				Write-Host $a.toshorttimestring() "Server returned an error, you must request the port within 2 minutes of connecting!"
				Write-Host $a.toshorttimestring() "Unable to connect to the PIA port server. Restarting service."
				Start-Sleep -s 10
				resetadapter
				$servererror = $true
			} else {
				Write-Host $a.toshorttimestring() "Unable to connect to the remote host. Retrying in 20 seconds."
				$error[0].ToString() + $error[0].InvocationInfo.PositionMessage
				Start-Sleep -s 20
			}
			continue 
		}
	}
	if (!$portupdatesuccessful -and !$servererror) {
		if ($isprocessactive) {
			$portupdatesuccessful = setapp
		} else {
			Write-host $a.toshorttimestring() $Applist[$Applistnum][0] "is not running."
		}
	}
	if ($Checkqbittorentstalled ){
		if ($isprocessactive){
			if ($Checkqbittorentstalledtime -eq $null) {
				$Checkqbittorentstalledtime = (get-date).Addminutes($Checkqbittorentstalledtimer).Addseconds(-1)
				write-host "Checking if qBittorrent is stalled at " $Checkqbittorentstalledtime.toshorttimestring()
			}else {
				if ($Checkqbittorentstalledtime -le (get-date)){
					fnqbittorrentstalling
					$Checkqbittorentstalledtime = (get-date).Addminutes($Checkqbittorentstalledtimer)
					Write-Host $a.toshorttimestring() "qBitTorrent is fine, check again at " $Checkqbittorentstalledtime.toshorttimestring()
				} Else {
					write-host "Checking if qBittorrent is stalled at " $Checkqbittorentstalledtime.toshorttimestring()
				}
			}
		} else {
			write-host $a.toshorttimestring() "qBittorrent is not active, can't check for stalled torrents"
		}
	}

	if ($ENABLEAUTOCHECK) {
		$saveY =  [console]::CursorTop
		clearscreen $saveY $false
		$a= get-date
		Write-Host $a.toshorttimestring() "Checking to see if VPN is still active."
		$EnableAutoCheckrespone = ping -S $ip www.privateinternetaccess.com -n 3 -4 | Out-String
		if 	($EnableAutoCheckrespone.indexof("Average") -lt 1) {
			Write-Host $a.toshorttimestring() "VPN is connected, but ping response was $EnableAutoCheckrespone , restarting service."
			Start-Sleep -s 10
			resetadapter
			$servererror = $true 
		} else {
			$EnableAutoCheckrespone = $EnableAutoCheckrespone.substring($EnableAutoCheckrespone.indexof("Average"))
			$EnableAutoCheckrespone = $EnableAutoCheckrespone.substring(0,$EnableAutoCheckrespone.length -2)
			clearscreen $saveY $false
			Write-Host $a.toshorttimestring() "VPN is still active and ping $EnableAutoCheckrespone."
		}
	} 
	$saveY =  [console]::CursorTop
	if ($ENABLEAUTOCHECK) {$saveY -= 1 } #minus one for ping response
	if ($Checkqbittorentstalled) {$saveY -= 1 } #minus one for stalled qbittorent check
	if (!$isprocessactive)  {$saveY -= 1 } #minus one for message torrent process not active
	if ($EnabledAdvanceRouting) {Write-host -ForegroundColor "Yellow" "You are currently connected to"$PIAserver[$PIAservernum][0] $PIAcipher[$PIAStrongEncryption][$PIAportsnum] ($PIAprotocal[$PIAportsnum]).ToUpper() $PIAcipher[$PIAStrongEncryption][6]}
	Write-host "Checking every $checktime seconds to see if your connected."
	Write-Host "Press 'q' to quit, 'p' to enable/disabled port forwarding,"
	Write-Host "Press 'a' to cycle between Utorrent and qBittorrent, 'r' to stop and reconnect to PIA,"
	Write-Host "'l' to list PIA severs, '0-9' to connected to a specific PIA server,"
	Write-Host "'t' to change protocols, 'e' to increase encryption, or any other key to refresh."
	$counter = 0
	while(!$Host.UI.RawUI.KeyAvailable -and ($counter++ -le  $checktime) -and !$servererror) {
		$strmoving | ForEach-Object {
			Write-Host -Object $_ -NoNewline
			[Threading.Thread]::Sleep( 200 )
			[console]::SetCursorPosition($saveX,[Console]::CursorTop)
		}
	}
	if ($Host.UI.RawUI.KeyAvailable) {
		$key = $host.UI.RawUI.ReadKey('NoEcho,IncludeKeyUp')
		if ($key.character -eq "Q") {
			Stop-PIAAdapter
			break;
		}
		if ($key.character -eq "Z") {
			Stop-PIAAdapter
		}
		if ($key.character -eq "R") {
			resetadapter
			$servererror = $true
		}
		if ($key.character -eq "P") {
			$disableportforwarduser=!$disableportforwarduser
			if (!$disableportforwarduser){
				if (isNumeric ($port) ) {
                    clearscreen ($startline)
                    Write-Host "Port given before was $port"
					$portupdatesuccessful = setapp
					$savey +=1
				} else {
					$servererror = $true
				}
			}
		}
		if ($key.character -eq "A") {
			if ($Applistnum -eq 0) { 
				$Applistnum = 1	
			} else {
				$Applistnum = 0
			}
			Write-host  "Changing app to update to" $Applist[$Applistnum][0]
			$portupdatesuccessful = setapp
		}
		if ($key.character -eq "T") {
			if ($EnabledAdvanceRouting) {
				if ($PIAportsnum -eq 0) { 
					$PIAportsnum = 1	
				} else {
					$PIAportsnum = 0
				}
				write-Host "Changing Protocol to" ($PIAprotocal[$PIAportsnum]).ToUpper()
				Start-Sleep -s 5
				resetadapter
				$servererror = $true
			} else {
				Write-host  "Enable Advance Routing to use this"
				Start-Sleep -s 10
			}
		}
		if ($key.character -eq "E") {
			if ($EnabledAdvanceRouting) {
				if ($PIAStrongEncryption -eq $PIAcipher.getupperbound(0)) { 
					$PIAStrongEncryption = 0	
				} else {
					$PIAStrongEncryption += 1
				}
				write-Host "Changing Encryption to" $PIAcipher[$PIAStrongEncryption][6]
				Start-Sleep -s 5
				resetadapter
				$servererror = $true
			} else {
				Write-host  "Enable Advance Routing to use this"
				Start-Sleep -s 10
			}
		}
		if (isnumeric($key.character)) {
			if ($EnabledAdvanceRouting) {
				$PIAservernum = [convert]::ToInt16($key.character, 10)
				write-Host "Changing Server to"  $PIAserver[$PIAservernum][0]
				$disableportforward = !$PIAserver[$PIAservernum][1]
				Start-Sleep -s 5
				resetadapter
				$servererror = $true
			} else {
				Write-host  "Enable Advance Routing to use this"
				Start-Sleep -s 10
			}
		}
		if ($key.character -eq "L" ) {listservers;}
			[Threading.Thread]::Sleep(500)
			$Host.UI.RawUI.FlushinputBuffer()
		} 
	if ($servererror){
			clearscreen $startline
		} else {
			clearscreen $savey
		}
}