# AD Network Simulation - Red Team Training

An interactive web-based simulation tool for learning and practicing Active Directory attack techniques and defensive strategies. This tool provides a visual representation of AD network interactions and various attack scenarios commonly used in red team operations.

[CLICK HERE FOR THE ONLINE PAGE](https://elvisgraho.github.io/ad-simulator/)

## Features

### Interactive Visualization

- Real-time visualization of AD network components and interactions
- Dynamic graph-based representation of:
  - Domain Controllers (DCs)
  - Certificate Authorities (CAs)
  - Users and Admin accounts
  - Service Accounts
  - Workstations and Servers
  - Attack vectors and flows

### Attack Scenarios

The simulation includes multiple categories of attack scenarios:

#### Initial Access & Credential Attacks

- Password Spray
- Kerberoasting
- AS-REP Roasting
- NTLM Relay
- LLMNR/NBT-NS Poisoning

#### Enumeration & Discovery

- SharpHound/Enum
- LDAP Recon
- DNS Recon
- SMB Share Enum

#### Lateral Movement & Privilege Escalation

- Pass-the-Ticket
- Pass-the-Hash
- Unconstrained Delegation
- RBCD Abuse
- Remote Service Execution
- Scheduled Task Abuse
- WMI Abuse

#### Certificate & PKI Attacks

- ESC1 (Template Abuse)
- ESC2 (Any Purpose)
- ESC3 (Enrollment Agent)
- ESC4 (Template ACL)
- ESC6 (NTLM Auth)
- ESC8 (Web Enrollment)

#### Domain Compromise & Persistence

- DCSync
- Golden Ticket
- Silver Ticket
- Shadow Credentials
- Skeleton Key
- DSRM Abuse

#### Service & Protocol Abuse

- PrintNightmare
- PetitPotam
- ZeroLogon
- MS14-068
- SAMR Abuse
- NTDS.dit Extraction

### Legitimate Actions

The simulation also includes legitimate AD operations for comparison:

- Standard User Logon
- Admin Group Management
- GPO Updates
- Certificate Requests
- File Share Access

## Technical Details

### Dependencies

- Cytoscape.js for network visualization
- Bootstrap for UI components
- Font Awesome for icons

### Browser Support

- Modern web browsers (Chrome, Firefox, Edge, Safari)
- No server-side components required

## Usage

1. Open `index.html` in a web browser
2. Use the control panel to:
   - Toggle manual step mode
   - Reset the simulation
   - Execute various attack scenarios
3. Observe the visualization and log output to understand the attack flow

## Legend

### Node Types

- 💾 DC (Domain Controller)
- 📜 CA (Certificate Authority)
- 👤 User
- 👑 Admin
- ⚙️ Service Account
- 💻 Workstation
- 🏢 Server
- 💀 Attacker

### Edge Types

- —→ Kerberos
- ––→ LDAP
- ···→ DRSUAPI
- ···→ RPC
- ––→ SMB
- ––→ NTLM
- ···→ DNS
- —→ HTTP(S)
- —→ Attack Flow

## Educational Value

This tool is designed to help:

- Security professionals understand AD attack vectors
- Red team members practice attack techniques
- Blue team members learn defensive strategies
- Security students visualize AD security concepts

## Disclaimer

This tool is for educational purposes only. The techniques demonstrated should only be used in authorized security testing environments with proper permissions.
