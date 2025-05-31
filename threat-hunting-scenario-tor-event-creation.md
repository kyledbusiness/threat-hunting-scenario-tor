# Threat Event (Unauthorized TOR Usage)
**Unauthorized TOR Browser Installation and Use**

## Steps the "Bad Actor" took to Create Logs and IoCs:
1. **Downloaded the TOR browser installer:** (https://www.torproject.org/download/)
2. **Silently installed the TOR browser:**
   ```tor-browser-windows-x86_64-portable-14.0.1.exe /S```
3. **Launched the TOR browser** from the installed folder.
4. **Connected to TOR and browsed several .onion sites:**
   - Current Dread Forum: `g66ol3eb5ujdckzqqfmjsbpdjufmjd5nsgdipvxmsh7rckzlhywlzlqd.onion`
   - Dark Markets Forum: `g66ol3eb5ujdckzqqfmjsbpdjufmjd5nsgdipvxmsh7rckzlhywlzlqd.onion/d/DarkNetMarkets`
   - Current Elysium Market: `https://elysiumutkwscnmdohj23gkcyp3ebrf4iio3sngc5tvcgyfp4nqqmwad.top/login`
   - **Note:** Onion links may change. For updated links, check: [Dread Forum](https://dread-forum.com/)
5. **Created a file named `tor-shopping-list.txt` on the desktop** and added a list of fake illicit items.
6. **Deleted the shopping list file** to "cover tracks."

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|[DeviceFileEvents Table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table)|
| **Purpose**| Detects TOR download, installation, and the creation/deletion of the shopping list. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|[DeviceProcessEvents Table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table)|
| **Purpose**| Detects silent installation of TOR and when TOR browser/services are launched.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|[DeviceNetworkEvents Table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table)|
| **Purpose**| Detects TOR network activity, especially outgoing connections over known TOR ports (9001, 9030, 9040, 9050, 9051, 9150).|

---

## Related Queries:
```kql
// Detect the TOR installer being downloaded
DeviceFileEvents
| where FileName startswith "tor"

// Detect silent installation of TOR browser
DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe  /S"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

// Detect TOR browser or service present on the disk
DeviceFileEvents
| where FileName has_any ("tor.exe", "firefox.exe")
| project  Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine

// Detect TOR browser or service launch
DeviceProcessEvents
| where ProcessCommandLine has_any("tor.exe","firefox.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// Detect TOR browser or service creating network connections
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// Detect if user created, modified, or deleted a shopping list file
DeviceFileEvents
| where FileName contains "shopping-list.txt"
```

---
