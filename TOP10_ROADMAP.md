# ShadowLab Top 10 Roadmap

This is the highest-value next-step backlog for turning ShadowLab into a stronger defensive security product.

## 1. Fleet & Agent Mode

- Add a lightweight endpoint agent
- Support multiple hosts in one console
- Show host inventory, health, and incident count per endpoint

## 2. Incident Lifecycle

- Add full incident detail pages
- Support owner, status, notes, tags, and closure workflow
- Export incident reports with findings, evidence, and actions

## 3. Detection Correlation

- Move from single events to multi-step behavior chains
- Add ATT&CK mapping and confidence scoring
- Deduplicate related alerts into one incident

## 4. Persistence Remediation

- Disable suspicious scheduled tasks
- Remove suspicious Run / RunOnce keys
- Stop or disable malicious services

## 5. Real Timeline View

- Build a visual process, network, persistence, and response timeline
- Show investigation flow in chronological order
- Link artifacts and evidence to the same timeline

## 6. Memory Forensics Upgrade

- Integrate real Volatility 3 execution
- Parse plugin output into structured findings
- Store dumps and analysis results in the evidence workflow

## 7. Quarantine Center

- Track quarantined files and metadata
- Restore or purge quarantined items
- Add hash reputation and chain-of-custody notes

## 8. Threat Intel Expansion

- Add domain and URL reputation
- Cache verdicts locally
- Enrich IPs with ASN, hosting, and context labels

## 9. Operator Safety & Hardening

- Add guarded response flows for dangerous actions
- Improve audit logging and tamper visibility
- Introduce safer defaults for lab-only offensive workflows

## 10. Release Engineering

- Finalize EXE packaging
- Add installer, icon, version metadata, and code signing path
- Add diagnostics and startup self-checks

## Recommended Build Order

1. Incident Lifecycle
2. Persistence Remediation
3. Real Timeline View
4. Memory Forensics Upgrade
5. Fleet & Agent Mode
