# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/massandr/threat-hunting-scenario-TOR/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Observed `DeviceFileEvent` table for any files containing string “tor” in the name. Discovered file “tor-browser-windows-x86_64-portable-14.5.1.exe” that appeared on `2025-05-16T03:34:08.7142964Z`. After that timestamp multiple files containing “tor” were created. One more interesting file was found - `wtb-tor.txt` on `2025-05-20T15:29:22.7734522Z`. Looks like user “massadmin” downloaded "tor" installer and possibly installed it.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "massandr-new-vm"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "massadmin"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account=InitiatingProcessAccountName
| order by Timestamp desc
```
Query results - [1-Tor-download.csv](https://github.com/massandr/threat-hunting-scenario-TOR/blob/main/1-Tor-download.csv)
https://github.com/massandr/threat-hunting-scenario-TOR/blob/f96ed16865b75cec8800011f4f8e80307a981173/1-Tor-download.csv#L47-L49
https://github.com/massandr/threat-hunting-scenario-TOR/blob/f96ed16865b75cec8800011f4f8e80307a981173/1-Tor-download.csv#L7

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string “tor-browser-windows-x86_64-portable-14.5.1.exe”. Found process with command line “tor-browser-windows-x86_64-portable-14.5.1.exe  /S” started `2025-05-16T03:37:02.3446276Z`, which means user “massandr” executed tor installer file using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "massandr-new-vm"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.1.exe"
| project Timestamp, ActionType, DeviceName, FileName, FolderPath, SHA256, AccountName, ProcessCommandLine
| order by Timestamp desc
```
Query results - [2-Tor-installer-launched.csv](https://github.com/massandr/threat-hunting-scenario-TOR/blob/main/2-Tor-installer-launched.csv)
https://github.com/massandr/threat-hunting-scenario-TOR/blob/176cc37a6789b99d0138104092b856eb0400d99c/2-Tor-installer-launched.csv#L2

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indications that user “massadmin” launched Tor browser on his machine. At `2025-05-16T03:37:44.4936257Z` file `firefox.exe` from the folder “C:\Users\massadmin\Desktop\Tor Browser\Browser\firefox.exe” was opened. After that multiple processes with `firefox.exe` and `tor.exe` were started, which can indicate that the browser was launched.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "massandr-new-vm"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, ActionType, DeviceName, FileName, FolderPath, SHA256, AccountName, ProcessCommandLine
| order by Timestamp desc
```
Query results - [3-Tor-launched.csv](https://github.com/massandr/threat-hunting-scenario-TOR/blob/main/3-Tor-launched.csv)
https://github.com/massandr/threat-hunting-scenario-TOR/blob/538f3a9ee953e133794ba7632130fb8955a7c6b4/3-Tor-launched.csv#L38-L44

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indications of TOR browser usage through establishing connection via known TOR ports. `2025-05-16T03:37:50.7357034Z`, on a computer called "massandr-new-vm," a user named "massadmin" successfully established a connection. This connection originated from the "firefox.exe" program and was directed to the computer itself (specifically, its local address 127.0.0.1) on port `9151`. There were few other connections. This event strongly suggests that the Tor Browser was running and active on the "massandr-new-vm" computer. 

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "massandr-new-vm"
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "9151", "80", "443")
| where InitiatingProcessFileName has_any ("tor", "firefox")
| order by Timestamp
```
Query results - [4-Tor-connection.csv](https://github.com/massandr/threat-hunting-scenario-TOR/blob/main/4-Tor-connection.csv)
https://github.com/massandr/threat-hunting-scenario-TOR/blob/aabc77b99bad6dc1bc2fae4b42e7cd8617b46830/4-Tor-connection.csv#L8-L11

---
## Chronological Timeline of Events

**Timestamp:** 2025-05-16 03:34:08Z

**Event:** Tor Browser installer file detected.

**Details:** The file tor-browser-windows-x86_64-portable-14.5.1.exe appeared on the device massandr-new-vm. This action was initiated by the account massadmin. This is the first indication of the Tor Browser software being introduced to the system.


**Timestamp:** 2025-05-16 03:37:02Z
**Event:** Tor Browser installer executed.
**Details:** The process tor-browser-windows-x86_64-portable-14.5.1.exe was started with the command line argument /S. This indicates a silent installation of the Tor Browser by the user massadmin.

**Timestamp:** 2025-05-16 03:37:44Z
**Event:** Tor Browser launched.
**Details:** The file firefox.exe located at C:\Users\massadmin\Desktop\Tor Browser\Browser\firefox.exe was opened. Following this, multiple processes associated with firefox.exe (the Tor Browser executable) and tor.exe (the Tor network client) were initiated by massadmin. This signifies the Tor Browser application being actively started.

**Timestamp:** 2025-05-16 03:37:50Z
**Event:** Tor Browser establishes local proxy connection.
**Details:** A network connection was successfully established by the firefox.exe process (Tor Browser). The connection was made to the local address 127.0.0.1 on port 9151. This port is commonly used by Tor Browser for its internal proxy communication with the Tor client, confirming the browser was active and attempting to route traffic through the Tor network. Several other related connections were also observed around this time.

**Timestamp:** 2025-05-20 15:29:22Z
**Event:** Potentially related text file found.
**Details:** A file named wtb-tor.txt was found on the system, associated with the user massadmin. While the contents are unknown, its name and timestamp (occurring after initial Tor activity) make it noteworthy in the context of Tor usage.

---

## Summary

The user "massadmin" on the "massandr-new-vm" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `wtb-tor.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "wtb-tor" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `massandr-new-vm` by the user `massadmin`. The device was isolated, and the user's direct manager was notified.

---
