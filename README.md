# Threat Hunt Report: Unauthorized TOR Usage

![TOR Logo](*image here*)

## Overview
Management has detected unusual encrypted traffic patterns and connections to known TOR entry nodes. Anonymous reports suggest employees may be using TOR browsers to bypass security controls. This investigation aims to confirm unauthorized TOR usage and analyze related security incidents.

## Platforms and Tools
- **Operating System:** Windows 10 Virtual Machines (Microsoft Azure)
- **EDR Platform:** Microsoft Defender for Endpoint
- **Analysis Language:** Kusto Query Language (KQL)
- **Target Application:** TOR Browser

---

## Investigation Steps & Findings

### **1. Detection of TOR Installer Download**
**Objective:** Identify any instances where the TOR installer was downloaded.
- **Query Used:** Checked `DeviceFileEvents` for filenames containing "tor".
- **Findings:**
  - User `employee` downloaded `tor-browser-windows-x86_64-portable-14.0.1.exe` to `C:\Users\employee\Downloads`.
  - Several related files were copied to the desktop, suggesting an installation attempt.
- **Timestamp:** *[Insert Time]*
- **Action Taken:** Further investigation into process execution.

![File Activity Query](*image here*)

---

### **2. TOR Browser Installation and Execution**
**Objective:** Verify if the downloaded installer was executed.
- **Query Used:** Checked `DeviceProcessEvents` for `ProcessCommandLine` containing "tor-browser-windows-x86_64-portable-14.0.1.exe /S".
- **Findings:**
  - At *[Insert Time]*, `employee` executed the installer using a silent installation flag (`/S`).
  - The installation process spawned `firefox.exe` and `tor.exe`, indicating a successful setup.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`
- **Action Taken:** Tracked process tree for further activity.

![Process Execution Query](*image here*)

---

### **3. Execution of TOR Browser**
**Objective:** Confirm if the user launched the TOR browser after installation.
- **Query Used:** Checked `DeviceProcessEvents` for `tor.exe` and `firefox.exe`.
- **Findings:**
  - User `employee` executed `tor.exe`, spawning multiple instances of `firefox.exe`.
  - The processes ran from `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`.
- **Timestamp:** *[Insert Time]*
- **Action Taken:** Monitored network traffic to confirm external TOR connections.

![TOR Execution Query](*image here*)

---

### **4. TOR Network Connections**
**Objective:** Determine whether the TOR browser established outbound connections.
- **Query Used:** Checked `DeviceNetworkEvents` for TOR-specific ports (9001, 9050, 9150).
- **Findings:**
  - At *[Insert Time]*, `employee` connected to a known TOR relay IP: *[Insert IP]* over port *[Insert Port]*.
  - Additional encrypted traffic was observed to multiple external servers.
- **Process Responsible:** `tor.exe`
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`
- **Action Taken:** Escalated for policy violation review.

![Network Activity Query](*image here*)

---

### **5. File Creation – TOR Shopping List**
**Objective:** Identify user behavior related to TOR activities.
- **Query Used:** Checked `DeviceFileEvents` for file creation and deletion activities.
- **Findings:**
  - User created a file named `tor-shopping-list.txt` at *[Insert Time]*, potentially listing items of interest.
  - The file was deleted shortly after.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`
- **Action Taken:** Recorded evidence for further review.

![File Creation Query](*image here*)

---

## **Response Actions**
- **Device Isolation:** Endpoint `threat-hunt-lab` isolated from the network.
- **User Notification:** `employee`'s activity reported to management.
- **Security Policy Review:** Recommendations made to restrict unauthorized TOR usage.

---

# **Scenario Creation (Threat Simulation)**

## **Steps Taken to Generate Logs**
1. **Downloaded** TOR installer from [torproject.org](https://www.torproject.org/download/).
2. **Installed Silently:**
   ```sh
   tor-browser-windows-x86_64-portable-14.0.1.exe /S
   ```
3. **Executed TOR Browser:** Opened `tor.exe` from desktop folder.
4. **Connected to TOR Network:** Browsed several onion sites.
5. **Created a File:** `tor-shopping-list.txt` with mock content.
6. **Deleted the File:** To simulate an attempt at covering tracks.

---

## **Tables Used for Detection**
| **Table** | **Purpose** |
|-----------|-------------|
| `DeviceFileEvents` | Identifies TOR installer download and file modifications. |
| `DeviceProcessEvents` | Tracks installation and execution of TOR browser. |
| `DeviceNetworkEvents` | Detects TOR network connections and activity. |

---

## **Key Detection Queries (KQL)**
```kql
// Detect TOR Installer Download
DeviceFileEvents
| where FileName startswith "tor"

// Detect Silent Installation
DeviceProcessEvents
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe  /S"

// Detect TOR Execution
DeviceProcessEvents
| where ProcessCommandLine has_any("tor.exe", "firefox.exe")

// Detect TOR Network Connections
DeviceNetworkEvents
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9050, 9150)

// Detect Creation of Shopping List File
DeviceFileEvents
| where FileName contains "shopping-list.txt"
```

---

## **Summary**
This investigation confirmed unauthorized TOR usage through file, process, and network analysis. The sequence of events demonstrated that an employee downloaded, installed, and used the TOR browser, attempting to cover their tracks. The case has been escalated for policy enforcement and future mitigation strategies.

