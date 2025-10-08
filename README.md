# CorpseFinder

CorpseFinder is a PowerShell script designed for Active Directory administrators and security professionals to audit and remediate computer object ownership and permissions in AD. It allows searching for computer accounts owned by a specific user, optionally replacing ownership, and removing risky "Full Control" permissions.

---

## Features

- Search all or specific AD computer accounts by owner
- Replace ownership of matched objects
- Remove "Full Control" (GenericAll) permissions from owners when needed
- Identify potential inactive computers based on `pwdLastSet` attribute older than 30 days
- Works for both domain-wide and single-host scenarios

---

## Installation

Download `CorpseFinder.ps1` and run it from a PowerShell session with Active Directory module loaded. You need appropriate credentials to modify ownership and permissions.

---

## Usage Examples

**List all computers owned by user `tyron.lannister`:**
```powershell
Invoke-CorpseFinder -owner tyron.lannister
```

<img width="623" height="328" alt="image" src="https://github.com/user-attachments/assets/bb275075-4da0-42d3-9675-9d1e0e0abad3" />


**List owned computers for a specific host:**
```powershell
Invoke-CorpseFinder -owner tyron.lannister -computerName THEWALL
```
<img width="655" height="320" alt="image" src="https://github.com/user-attachments/assets/0c5725e8-462c-40ac-911a-3fb6b688d6ee" />

**Remove "Full Control" permissions for the owner on a host:**
```powershell
Invoke-CorpseFinder -owner tyron.lannister -computerName THEWALL -RemoveFullControl $true
```

**Replace ownership and remove Full Control for a host (requires domain admin permissions):**
```powershell
Invoke-CorpseFinder -owner tyron.lannister -computerName THEWALL -RemoveFullControl $true -replace "Domain Admins"
```

<img width="727" height="381" alt="image" src="https://github.com/user-attachments/assets/1be3c2e9-4eaf-433f-8634-2b3efe6146f7" />
