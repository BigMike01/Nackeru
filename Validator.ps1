# Just a script to check what LAN Segment we are on 
# And if our Main Security Agents are running.


$SECURITY_POSTURE = 0;
$SECURITY_POSTURE_BASELINE = 2;
$AV_SERVICENAME = "McC*";
$AV_ENGINE_URL = "https://software.IT.LAN/AVENGINE.EXE"
$AV_AGENT_URL = "https://software.IT.LAN/AVAGENT.EXE"
$AV_CMD_LINE_URL = "https://software.IT.LAN/STINGER.EXE"
$MAX_DEF_AGE = 14;
$QUARANTINE_ALLOW = "192.168.69.*";
$QUARANTINE_DENY =  "192.168.200.*";
$TARGET_LAN = "192.168.2.*";
$IP_ACTUAL 
$IN_SCOPE = "NO";
$SERVICE_DESK_NUMBER = "0208 888 8888";

# This loop will just see if we are in the TARGET_LAN IE: part of the more private LAN segment.

Get-WmiObject -Class Win32_NetworkAdapterConfiguration | foreach-object{
if ( $_.IPAddress -like $TARGET_LAN )

 {
 
  $IP_ACTUAL = $_.IPAddress 

  $IN_SCOPE = "YES"
  

 }

}

#

Get-Service | foreach-object{

# Find AV service and Assert that is At least running.
if ( $_.Name -like $AV_SERVICENAME )

 {
  write-host
  write-host $_.Name
  
     # If we are here the service is installed.
  
    $SECURITY_POSTURE ++
  
         if ( $_.Status -eq 'Running' )

            {

           
            # If we are here the service is running.
         $SECURITY_POSTURE ++

       }
       
      Write-host "Is Installed and.."$_.Status

   }


#

}  


  Write-Host 
  Write-Host  
   
# Just Echo the status so far.  
  
  Write-Host  "IP_ACTUAL" $IP_ACTUAL
  Write-Host  "IN_SCOPE " $IN_SCOPE
  Write-Host  "SECURITY_POSTURE SCORE:["$SECURITY_POSTURE"/$SECURITY_POSTURE_BASELINE]"
  
  
  
  
#  
  
  
if ( $SECURITY_POSTURE -lt $SECURITY_POSTURE_BASELINE ) 

# IF we are AV / Security products are not installed or not running
# WE are going to download a zero Install AV engine and kick off a scan
# WE are going to Blacklist some systems the machine can connect to.

   {
   Write-Host ":: ACTION CALL REMEDIATION SCRIPT"
  
   

   # Point Your Proxy and other secure servers to a webserver that has a link to AV and probably the HELP DESK.
   Add-Content "C:\windows\system32\drivers\etc\hosts" " 192.168.69.69    PCI-SERVER01.LAN     # Added By Sudo SHV" 
   Add-Content "C:\windows\system32\drivers\etc\hosts" " 192.168.69.69    PCI-SERVER02.LAN     # Added By Sudo SHV"
   Add-Content "C:\windows\system32\drivers\etc\hosts" " 192.168.69.69    PCI-SERVER03.LAN     # Added By Sudo SHV"
   # Drop webproxy internet Access (the workstations should not be able to communicate outside the LAN/WAN without it)
   Add-Content "C:\windows\system32\drivers\etc\hosts" " 192.168.69.69    WEBPROXY.LAN         # Added By Sudo SHV" 
   # Just Make sure the cache is dropped
   Add-Content "C:\windows\system32\SHV00001.bat" "IPCONFIG /FLUSHDNS"
    
   ## this bit may be overkill to actually drop thier IP?
   ## Add-Content "C:\windows\system32\SHV00001.bat", "IPCONFIG /RELEASE"
   
   START "C:\windows\system32\SHV00001.bat"
   
   Add-Content "C:\Servicedesk01.html" "<!Doctype html><html><head><title>Sorry for the interuption</title><body><h1> Please call the Service Desk team on : $SERVICE_DESK_NUMBER </h1><a href='$AV_ENGINE_URL'>Problem Type: AV ENGINE NOT RUNNING</a> </body></title></head></html>"
   start "C:\Servicedesk01.html"       
   
   }
   
# 
