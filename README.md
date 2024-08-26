I'm a support analyst\help desk technician by trade.

I use this script, System Inventory - Code.txt, as part of my diagnostic process to streamline information gathering, minimize redundant communications, and enhance case note documentation. 
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
