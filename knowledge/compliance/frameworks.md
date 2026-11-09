# Compliance frameworks and the shared responsibility model

## Shared responsibility
The provider secures the cloud (facilities, hypervisor, managed-service internals). The customer secures what
they put **in** the cloud: identities, configuration, network exposure, data, encryption settings and logging.
Almost every public cloud breach is a customer-side misconfiguration. That's exactly what posture scanning
(CSPM) targets.

## CIS Foundations Benchmarks
Consensus-based, prescriptive configuration baselines. Cloud Copilot maps AWS rules to **CIS AWS Foundations
v3.0** (sections: 1 IAM, 2 Storage, 3 Logging, 4 Monitoring, 5 Networking) and Azure rules to **CIS Microsoft
Azure Foundations v2.0**. Mappings are indicative. A formal audit should use the benchmark text and evidence.

## NIST SP 800-53 rev5
A control catalog used by US federal systems and widely referenced elsewhere. Families most relevant to cloud
posture: AC (access control), AU (audit), CM (configuration management), CP (contingency planning),
IA (identification & authentication), SC (system & communications protection), SI (system integrity).

## Other frameworks you will meet
- **ISO/IEC 27001:2022** Annex A (A.5.15 access control, A.8.15 logging, A.8.24 cryptography).
- **SOC 2** Trust Services Criteria (CC6 logical access, CC7 system operations).
- **PCI DSS v4.0** for card data (req. 1 network controls, 3 protect stored data, 8 strong authentication,
  10 logging).
- **GDPR**: Art. 32 security of processing; Art. 33 breach notification within 72h.

## Reading the score
The posture score is the severity-weighted share of evaluated controls that pass (CRITICAL=10, HIGH=6, MEDIUM=3,
LOW=1). Cost and informational rules don't affect it. Suppressed findings (accepted risk with a reason and
optional expiry) don't count as failures but remain visible for audit.
