# Detection-as-Code Lab : Wazuh + Sysmon + ATT&CK

A home SOC lab that detects 8 MITRE ATT&CK techniques with custom Wazuh rules,
validates them against independent attack replays, measures false positives over
a baseline window, and triggers an automated response. Built on an 8 GB laptop,
fully isolated, at zero cost.

## Summary

- **8/8 techniques detected** — custom rules validated at unit level (`wazuh-logtest`)
  and live, then replayed with Atomic Red Team and manual technique replays.
- **2 false positives identified → 0** after surgical exclusions, with detection
  preserved (verified: real attacks still fire).
- **Automated response** (Wazuh active response, simulation mode), reaction time ~4 s.
- Detection logic versioned as code, with positive/negative test fixtures.

## Stack (versions used)

| Component | Version |
|-----------|---------|
| Wazuh manager (standalone, no indexer/dashboard) | 4.14.9 |
| Sysmon (sysmon-modular config, Olaf Hartong) | 15.22 |
| Windows endpoint | Windows Server 2025 (Eval) |
| Domain Controller | Windows Server 2025 (Eval), AD DS |
| Manager OS | Ubuntu Server 24.04 LTS |
| Hypervisor | VirtualBox 7.2 |

## Architecture

Standalone Wazuh manager (analysis + rules + active response), no indexer and no
dashboard — detection happens in `wazuh-analysisd` and alerts are read from
`alerts.json`. This fits an 8 GB host and keeps the project fully "as code".
