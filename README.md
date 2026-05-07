# Threat Hunt Report: SIGNALS BEFORE THE NOISE

**Analyst:** Sambou Kamissoko  
**Date:** 02 MAY-9

---

# Platforms and Technologies Used

## Platforms
- Microsoft Defender for Endpoint (MDE)
- Microsoft Sentinel / Log Analytics Workspace
- Windows Endpoint: azwks-phtg-02

## Languages & Tools
- Kusto Query Language (KQL)
- Microsoft Defender XDR Advanced Hunting
- Windows Event Analysis
- File Rename Chain Analysis
- Process and Persistence Investigation

---

# Scenario

A suspicious successful RDP authentication originating from Uruguay was identified on the endpoint azwks-phtg-02. The investigation focused on identifying the external source IPs, early user interaction, payload execution behavior, file rename activity, and persistence mechanisms used by the attacker.

The attacker leveraged disguised payloads, extension manipulation, and a repurposed legitimate internal service directory to establish persistence while blending malicious activity with trusted infrastructure.

---

# Key Findings

- Successful RDP authentication events originated from Uruguay.
- Two external IP addresses were associated with successful authentication activity.
- The first notable user-driven process observed after authentication was:
  
  ```text
  notepad.exe
  ```

- The attacker used extension manipulation to disguise payload execution.
- The payload initially appeared as:

  ```text
  Sarah_Chen_Notes.exe.Txt
  ```

- The payload later transitioned into an executable form:

  ```text
  Sarah_Chen_Notes.exe
  ```

- Additional payload-related files observed:
  - PHTG.exe
  - Launch.bat

- The attacker repurposed a legitimate internal service directory named:

  ```text
  HealthCloud
  ```

- Persistence-related files were stored inside:

  ```text
  C:\ProgramData\PHTG\HealthCloud\
  ```

- Evidence suggested the attacker attempted to blend malicious files with recently deployed internal infrastructure to avoid detection.

---

# Investigation Timeline

## Phase 1 — Identifying Successful RDP Authentication

The investigation began by reviewing successful authentication activity associated with the compromised endpoint.

### Query Used

```kql
DeviceLogonEvents
| where DeviceName == "azwks-phtg-02"
| where ActionType == "LogonSuccess"
```

The analysis revealed successful authentication events originating from Uruguay, indicating potential unauthorized remote access.

---

## Phase 2 — Identifying User Interaction

After identifying the successful logon events, process activity was reviewed to distinguish normal Windows startup activity from meaningful user interaction.

### Query Used

```kql
DeviceProcessEvents
| where DeviceName == "azwks-phtg-02"
| sort by TimeGenerated asc
```

The earliest notable process indicating purposeful user interaction was identified as:

```text
notepad.exe
```

This process was considered significant because it represented clear human interaction beyond standard Windows session initialization behavior.

---

## Phase 3 — File Rename Chain Investigation

The investigation then shifted toward identifying suspicious payload transformation behavior using FileRenamed events.

### Query Used

```kql
DeviceFileEvents
| where DeviceName == "azwks-phtg-02"
| where ActionType == "FileRenamed"
| sort by TimeGenerated asc
```

The analysis revealed a suspicious file rename chain involving extension manipulation.

### Key Transition Observed

```text
Sarah_Chen_Notes.exe.Txt
→ Sarah_Chen_Notes.exe
```

This represented the first point where Windows would treat the file as executable.

The behavior suggested intentional masquerading designed to conceal malicious execution.

---

## Phase 4 — Executable and Payload Analysis

Additional executable artifacts were identified during the investigation.

### Observed Payload Files

```text
PHTG.exe
Launch.bat
```

These files were associated with later stages of execution and persistence activity.

---

## Phase 5 — Persistence Investigation

Further analysis identified that the attacker leveraged a legitimate internal service directory for persistence.

### Suspicious Directory

```text
C:\ProgramData\PHTG\HealthCloud\
```

The attacker stored payload-related files inside the HealthCloud directory to blend malicious activity with trusted operational infrastructure.

This technique reduced the likelihood of immediate detection by security analysts and endpoint monitoring tools.

---

# MITRE ATT&CK Techniques Observed

| Technique ID | Technique |
|---|---|
| T1021.001 | Remote Services: Remote Desktop Protocol |
| T1036 | Masquerading |
| T1036.003 | Rename Legitimate Utilities |
| T1059 | Command and Scripting Interpreter |
| T1105 | Ingress Tool Transfer |
| T1547 | Boot or Logon Autostart Execution |

---

# Conclusion

The investigation confirmed unauthorized remote access originating from Uruguay, followed by staged payload execution and persistence activity on the endpoint azwks-phtg-02.

The attacker disguised malicious files through extension manipulation techniques and leveraged a legitimate internal service directory (HealthCloud) to conceal persistence-related payloads.

The hunt demonstrated the importance of correlating authentication telemetry, process execution activity, file rename chains, and persistence artifacts to uncover stealthy attacker behavior within enterprise environments.

---

# Skills Demonstrated

- Threat Hunting
- Kusto Query Language (KQL)
- Microsoft Defender XDR Advanced Hunting
- File Rename Chain Analysis
- Persistence Investigation
- Endpoint Telemetry Analysis
- Process Investigation
- RDP Intrusion Analysis
- MITRE ATT&CK Mapping
