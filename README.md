![A description of the image](Tor.svg.png)
# Tor-threat-hunting-scenario
Threat Hunt Report: Unauthorized TOR Usage

# Platforms and Languages Leveraged
- Azure VM creation (corporate-style)
- Defender for Endpoint onboarding
- Baseline activity (normal user behavior)
- Threat simulation (TOR install & use)
- Threat hunting (KQL)
- Evidence correlation
- Response actions
- Final project documentation

## Scenario
Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.
