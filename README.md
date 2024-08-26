I'm a support analyst\help desk technician by trade.

I use this script as part of my diagnostic process to streamline information gathering, minimize redundant communications, and enhance case note documentation. 
It saves a lot of time by eliminating guesswork about system architecture and reducing unnecessary communications to obtain details I should have had initially.

The script extracts, formats, and writes the following data elements into a text file named ‘System Inventory.txt’ saved in the logged-on user’s Downloads folder:

* OS Details
* OEM Serial Number
* GPU specs
* Storage Capacity
* Optional Windows Features or Server Roles (contingent upon platform)
* ISP Details & External IP Addresses (both IPv4 & IPv6)
* Antivirus details
* PowerShell & .NET Framework versions
* Browser URL associations - 'What did you say your default browser was?'
* Critical & Error events over the past 24 hours
* Updates & Hotfixes

So, how exactly do I use the script? Real basic:

1) Share the script with the client
2) Walk them through running the script
3) Retrieve the results (if remotely assisting) or have the client send the System Inventory.txt file to me via email
4) Post the client's system inventory as an internal case note in whatever ITSM\CRM platform (SalesForce, ServiceNow, Remedy, etc) my shop is using
5) Diagnose, reproduce, and fix the client's issue

Sample results from my personal system:

# Current Date

Friday, August 23, 2024 4:45:35 PM

# Operating System

Host Name:                 WHAMILL-W10
OS Name:                   Microsoft Windows 11 Pro
OS Version:                10.0.22631 N/A Build 22631
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          noirawjh@live.com
Registered Organization:   N/A
Product ID:                00330-80000-00000-AA447
Original Install Date:     10/5/2022, 7:46:26 AM
System Boot Time:          8/23/2024, 7:56:51 AM
System Manufacturer:       Dell Inc.
System Model:              G7 7588
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 158 Stepping 10 GenuineIntel ~2208 Mhz
BIOS Version:              Dell Inc. 1.21.0, 4/15/2022
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume3
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-06:00) Central Time (US & Canada)
Total Physical Memory:     16,177 MB
Available Physical Memory: 10,390 MB
Virtual Memory: Max Size:  17,201 MB
Virtual Memory: Available: 10,676 MB
Virtual Memory: In Use:    6,525 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\WHAMILL-W10
Hotfix(s):                 5 Hotfix(s) Installed.
                           [01]: KB5042099
                           [02]: KB5012170
                           [03]: KB5027397
                           [04]: KB5041585
                           [05]: KB5041584
Network Card(s):           3 NIC(s) Installed.
                           [01]: Intel(R) Wireless-AC 9560 160MHz
                                 Connection Name: Wi-Fi
                                 DHCP Enabled:    Yes
                                 DHCP Server:     192.168.1.1
                                 IP address(es)
                                 [01]: 192.168.1.35
                                 [02]: fe80::ecf6:debf:636b:f0bc
                                 [03]: fd00:f85b:3bc0:b38:113d:15e5:e218:a948
                                 [04]: 2603:8080:1f05:4f8e:113d:15e5:e218:a948
                                 [05]: fd00:f85b:3bc0:b38:b71e:8302:c915:7e7c
                                 [06]: fd00:f85b:3bc0:b38::11c8
                                 [07]: 2603:8080:1f05:4f8e:8037:9ca6:e6b9:dd0e
                           [02]: Killer E2400 Gigabit Ethernet Controller
                                 Connection Name: Ethernet
                                 Status:          Media disconnected
                           [03]: DisplayLink Network Adapter NCM
                                 Connection Name: Ethernet - Dock
                                 Status:          Media disconnected
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.


# OEM Identifier

SerialNumber
------------
9GS1XS2 

# Graphic Cards

Device Name                               Video RAM Driver Version Install Date & Time 
-----------                               --------- -------------- ------------------- 
NVIDIA GeForce GTX 1060 with Max-Q Design      4095 31.0.15.3179   4/24/2023 7:00:00 PM
Intel(R) UHD Graphics 630                      1024 27.20.100.9664 5/31/2021 7:00:00 PM
DisplayLink USB Device                            0 11.0.2412.0    12/8/2022 6:00:00 PM
DisplayLink USB Device                            0 11.0.2412.0    12/8/2022 6:00:00 PM

# Storage Capacity

SystemName  DeviceID VolumeName Free Space (GB) Total Size (GB) Free Space %
----------  -------- ---------- --------------- --------------- ------------
WHAMILL-W10 C:       OS         145.65          237.71          61.27       
WHAMILL-W10 D:       Storage    457.77          465.75          98.29      

# Windows Client - Active Optional Features

FeatureName                                
-----------                                
MediaPlayback                              
Microsoft-RemoteDesktopConnection          
MSRDC-Infrastructure                       
NetFx3                                     
NetFx4-AdvSrvs                             
Printing-Foundation-Features               
Printing-Foundation-InternetPrinting-Client
Printing-PrintToPDFServices-Features       
Printing-XPSServices-Features              
SearchEngine-Client-Package                
SmbDirect                                  
WCF-Services45                             
WCF-TCP-PortSharing45                      
WindowsMediaPlayer                         

# Network Adapters & Mac Addresses

Name            InterfaceDescription                     ifIndex Status       MacAddress         LinkSpeed
----            --------------------                     ------- ------       ----------         ---------
Wi-Fi           Intel(R) Wireless-AC 9560 160MHz              20 Up           A2-3F-57-4F-8D-14 866.7 Mbps
Ethernet - Dock Dell Giga Ethernet                            10 Disconnected 9C-EB-E8-A0-02-CC    10 Mbps
Ethernet        Killer E2400 Gigabit Ethernet Controller       5 Disconnected 3C-2C-30-C8-D3-29      0 bps

# ISP Details & External IP Addresses

ip       : 68.203.15.108
hostname : syn-068-203-015-108.res.spectrum.com
city     : Austin
region   : Texas
country  : US
loc      : 30.4300,-97.8326
org      : AS11427 Charter Communications Inc
postal   : 78726
timezone : America/Chicago
readme   : https://ipinfo.io/missingauth

2603:8080:1f05:4f8e:113d:15e5:e218:a948

# Antivirus Details

Display Name : Windows Defender
Install Path : %ProgramFiles%\Windows Defender\MsMpeng.exe
Enabled      : True
Updated      : True
Latest Scan  : Friday, 23-Aug-2024 07:59:14 AM
Computer     : WHAMILL-W10

# PowerShell

Major  Minor  Build  Revision
-----  -----  -----  --------
5      1      22621  3958    

# .Net Framework

Client                       Version Release
------                       ------- -------
Full                         4.8.1    533320
Microsoft.NETCore.App        6.0.33         
Microsoft.WindowsDesktop.App 6.0.33         

# Browser URL Associations

Name                           Value                                                                                                                                                                                                                             
----                           -----                                                                                                                                                                                                                             
callto                                                                                                                                                                                                                                                           
webcal                         AppX4vt5c8cbxd42btbp6br6zs9v25a1kh5j                                                                                                                                                                                              
mswindowsvideo                 AppX6w6n4f8xch1s3vzwf3af6bfe88qhxbza                                                                                                                                                                                              
mailto                         AppXbx2ce4vcxjdhff3d1ms66qqzk12zn827                                                                                                                                                                                              
ms-screenclip                  AppXfeq5vwnakrw6cy02kzhq8ekhhsremh62                                                                                                                                                                                              
bingmaps                       AppXp9gkwccvk6fa6yyfq3tmsk8ws2nprk1p                                                                                                                                                                                              
mswindowsmusic                 AppXtggqqtcfspt6ks3fjzyfppwc05yxwtwy                                                                                                                                                                                              
ftp                            ChromeHTML                                                                                                                                                                                                                        
http                           ChromeHTML                                                                                                                                                                                                                        
https                          ChromeHTML                                                                                                                                                                                                                        
mms                            ChromeHTML                                                                                                                                                                                                                        
sms                            ChromeHTML                                                                                                                                                                                                                        
tel                            ChromeHTML                                                                                                                                                                                                                        
microsoft-edge                 MSEdgeHTM                                                                                                                                                                                                                         
microsoft-edge-holographic     MSEdgeHTM                                                                                                                                                                                                                         
ms-xbl-3d8b930f                MSEdgeHTM                                                                                                                                                                                                                         
read                           MSEdgeHTM                                                                                                                                                                                                                         
sip                            ZoomMeeting.sip                                                                                                                                                                                                                   
IM                             ZoomPbx.im                                                                                                                                                                                                                        
ZoomPhoneCall                  ZoomPbx.zoomphonecall                                                                                                                                                                                                             

# Event Log Activity

LevelDisplayName    Id TimeCreated          ProviderName                                Message                                                                                                                                                                  
----------------    -- -----------          ------------                                -------                                                                                                                                                                  
Critical         10110 8/22/2024 8:57:55 PM Microsoft-Windows-DriverFrameworks-UserMode A problem has occurred with one or more user-mode drivers and the hosting process has been terminated.  This may temporarily interrupt your ability to access the        
                                                                                        devices.                                                                                                                                                                 
Critical         10111 8/22/2024 8:57:55 PM Microsoft-Windows-DriverFrameworks-UserMode The device Dell Universal Dock D6000 (location 0000.0014.0000.017.001.000.000.000.000) is offline due to a user-mode driver crash.  Windows will attempt to restart the  
                                                                                        device 5 more times.  Please contact the device manufacturer for more information about this problem.                                                                    
Critical         10111 8/22/2024 8:57:55 PM Microsoft-Windows-DriverFrameworks-UserMode The device Dell Universal Dock D6000 (location 0000.0014.0000.017.001.000.000.000.000) is offline due to a user-mode driver crash.  Windows will attempt to restart the  
                                                                                        device 5 more times.  Please contact the device manufacturer for more information about this problem.                                                                    
Error               13 8/23/2024 7:56:19 AM VSS                                         Volume Shadow Copy Service information: The COM Server with CLSID {4e14fba2-2e22-11d1-9964-00c04fbbb345} and name CEventSystem cannot be started. [0x8007045b, A system  
                                                                                        shutdown is in progress.]                                                                                                                                                                        

# Updates & Hotfixes

KB Number Installed             Title                                                                                                                    
--------- ---------             -----                                                                                                                    
KB5042099 8/13/2024 5:56:51 PM  2024-08 Cumulative Update for .NET Framework 3.5 and 4.8.1 for Windows 11, version 23H2 for x64 (KB5042099)              
KB5042131 8/13/2024 5:56:13 PM  2024-08 .NET 6.0.33 Update for x64 Client (KB5042131)                                                                    
KB890830  8/13/2024 5:56:01 PM  Windows Malicious Software Removal Tool x64 - v5.127 (KB890830)                                                          
KB5041585 8/13/2024 5:54:41 PM  2024-08 Cumulative Update for Windows 11 Version 23H2 for x64-based Systems (KB5041585)                                  
KB4052623 8/8/2024 12:48:59 AM  Update for Microsoft Defender Antivirus antimalware platform - KB4052623 (Version 4.18.24070.5) - Current Channel (Broad)
          8/7/2024 12:22:31 PM  Intel Corporation - Extension - 27.20.100.8935                                                                           
          8/7/2024 12:22:28 PM  Intel Corporation - Extension - 26.20.100.8141                                                                           
          8/7/2024 12:22:26 PM  Intel Corporation - Extension - 8/15/2018 12:00:00 AM - 24.20.100.6287                                                   
          8/6/2024 10:09:24 PM  Intel Corporation - Extension - 27.20.100.8935                                                                           
          8/6/2024 10:09:21 PM  Intel Corporation - Extension - 26.20.100.8141                                                                           
          8/6/2024 10:09:20 PM  Intel Corporation - Extension - 8/15/2018 12:00:00 AM - 24.20.100.6287                                                   
KB5041080 7/22/2024 11:33:21 PM 2024-07 .NET 6.0.32 Security Update for x64 Client (KB5041080)                                                           
KB4052623 7/16/2024 4:23:26 AM  Update for Microsoft Defender Antivirus antimalware platform - KB4052623 (Version 4.18.24060.7) - Current Channel (Broad)
KB890830  7/10/2024 3:06:02 AM  Windows Malicious Software Removal Tool x64 - v5.126 (KB890830)                                                          
KB5040442 7/10/2024 2:54:24 AM  2024-07 Cumulative Update for Windows 11 Version 23H2 for x64-based Systems (KB5040442)                                  
KB5039895 7/10/2024 2:49:16 AM  2024-07 Cumulative Update for .NET Framework 3.5 and 4.8.1 for Windows 11, version 23H2 for x64 (KB5039895)              
KB5041080 7/10/2024 1:59:00 AM  2024-07 .NET 6.0.32 Security Update for x64 Client (KB5041080)                                                           
KB890830  6/12/2024 4:34:56 AM  Windows Malicious Software Removal Tool x64 - v5.125 (KB890830)                                                          
KB5039212 6/12/2024 4:33:38 AM  2024-06 Cumulative Update for Windows 11 Version 23H2 for x64-based Systems (KB5039212)                                  
KB4052623 6/4/2024 9:10:37 PM   Update for Microsoft Defender Antivirus antimalware platform - KB4052623 (Version 4.18.24050.7) - Current Channel (Broad)
KB5039843 5/29/2024 4:22:11 AM  2024-05 .NET 6.0.31 Security Update for x64 Client (KB5039843)
