![A description of the image](Tor.svg.png)
# Tor-threat-hunting-scenario
Threat Hunt Report: Unauthorized TOR Usage

## Platforms and Languages Leveraged
- Azure VM creation (corporate-style)
- Defender for Endpoint onboarding
- Baseline activity (normal user behavior)
- Threat simulation (TOR install & use)
- Threat hunting (KQL)
- Evidence correlation
- Response actions
- Final documentation

## Scenario
Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

## 1 Create the Azure Windows 11 VM
## Step 1: Create the VM
In Azure Portal:
- Go to Virtual Machines → Create
- Image: Windows 10 Enterprise
- Size: Any basic size (this is a workstation, not a server)
- Authentication: Username + password
    - Example:
    - Username: employee
    - Password: strong password
 
## Step 2: Networking
- Public IP: Enabled
- NSG: Default outbound allowed
- Inbound: Allow RDP (3389)

This mimics a corporate workstation with internet access.

## 2 Onboard the VM to Microsoft Defender for Endpoint
### Enable Defender
- Go to Microsoft Defender Portal
- Navigate to:
  Settings → Endpoints → Onboarding
- Choose:
  - OS: Windows 10
  - Deployment: Local script
- Download the onboarding script

### Run Onboarding Script
- RDP into the VM
- Open PowerShell as Administrator
- Run the onboarding script
- Wait 5–10 minutes

### Verify
In Defender Portal:
- Go to Assets → Devices
- Confirm:
  - Device name appears (e.g. threat-hunt-lab)
  - Status = Active
