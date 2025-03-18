# Threat Hunt Report: Unauthorized TOR Usage

![TOR Logo](https://github.com/user-attachments/assets/070499e5-3a21-4f33-92af-2b4f3aee3879)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

## Detection of Unauthorized TOR Browser Installation and Use on Workstation

### Example Scenario:
Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-related IoC Discovery Plan:
- Check `DeviceFileEvents` for any `tor(.exe)` or `firefox(.exe)` file events.
- Check `DeviceProcessEvents` for any signs of installation or usage.
- Check `DeviceNetworkEvents` for any signs of outgoing connections over known TOR ports.

## Steps Taken

### Step 1: Identified Potential TOR Installation Files
- Conducted an advanced hunting query to search for TOR installation files in `DeviceFileEvents`.
- Queried for file names such as `tor.exe`, `firefox.exe`, and common TOR package installers.
- Noted timestamps, user accounts, and device names associated with these events.

**KQL Query Used:**
```kql
DeviceFileEvents
| where FileName has_any ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine
```

**Screenshot Placeholder:** *[Insert screenshot of query results]*

### Step 2: Tracked TOR Browser Installation Process
- Checked `DeviceProcessEvents` for silent TOR installations.
- Looked for process executions that included `/S` (silent install flag).
- Verified whether TOR was launched post-installation.

**KQL Query Used:**
```kql
DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```

**Screenshot Placeholder:** *[Insert screenshot of process event query results]*

### Step 3: Investigated TOR Network Connections
- Queried `DeviceNetworkEvents` for outgoing connections made by `tor.exe` or `firefox.exe`.
- Focused on remote ports commonly associated with TOR (9001, 9030, 9040, 9050, 9051, 9150).
- Recorded timestamps, remote IP addresses, and connection attempts.

**KQL Query Used:**
```kql
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc
```

**Screenshot Placeholder:** *[Insert screenshot of network connections query results]*

### Step 4: Confirmed TOR-Related File Activity
- Checked `DeviceFileEvents` for any user-created files related to TOR activity.
- Identified suspicious files such as `tor-shopping-list.txt` and monitored changes or deletions.

**KQL Query Used:**
```kql
DeviceFileEvents
| where FileName contains "shopping-list.txt"
| project Timestamp, DeviceName, RequestAccountName, ActionType
```

**Screenshot Placeholder:** *[Insert screenshot of file activity query results]*

### Step 5: Correlated Findings & Reported to Management
- Analyzed all collected data to confirm unauthorized TOR activity.
- Isolated the compromised endpoint and escalated the issue to management.
- Suggested security controls to prevent future unauthorized TOR usage.

## Chronological Events
- **[Timestamp]** TOR browser installer detected in `DeviceFileEvents`.
- **[Timestamp]** TOR installation process confirmed in `DeviceProcessEvents`.
- **[Timestamp]** TOR browser launched by the user.
- **[Timestamp]** Network activity detected on known TOR ports.
- **[Timestamp]** User deleted `tor-shopping-list.txt` file.

## Summary
- Unauthorized TOR usage was confirmed on endpoint **[Device Name]**.
- The user was actively browsing TOR and attempting to bypass security controls.
- Network connections to known TOR nodes were identified and blocked.

## Response Taken
- The device was **isolated** to prevent further unauthorized activity.
- Management was **notified**, and an internal investigation was initiated.
- Recommended policy updates to restrict TOR installations in the environment.

---

- [Scenario Creation](https://github.com/kyledbusiness/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)
