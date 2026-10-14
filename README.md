# A3-PS011-TC363
# PS-011: Authorised Attack-Surface Inventory and Change Monitor

**Category:** Cybersecurity  
**Project:** PS-011  
**Focus:** Attack-Surface Discovery, Inventory, Change Detection and Security Monitoring

## Overview

Organisations operating across multiple cloud environments often accumulate exposed digital assets, including forgotten subdomains, expired TLS certificates, unexpected network services and DNS records pointing to decommissioned infrastructure.

The **Authorised Attack-Surface Inventory and Change Monitor** is a defensive security monitoring system designed to maintain an inventory of approved domains and hosts, detect configuration changes, and generate actionable alerts for potentially risky conditions.

The system establishes a baseline of known assets and periodically compares new observations against it. It focuses on identifying expired certificates, unexpected services and potential dangling DNS records while documenting evidence, uncertainty and false positives.

All monitoring activities are restricted to a written, organiser-approved target scope.

## Problem Statement

Organisations often lack a centralised, continuously updated inventory of their externally exposed assets. Manual inspection can miss newly exposed services, certificate expiry and DNS records that reference decommissioned infrastructure.

This project addresses the problem through automated inventory collection, scheduled comparisons and change-based alerting, helping security teams identify and investigate potentially risky changes before they are overlooked.

## Objectives

- Monitor up to **20 approved lab domains and 10 approved hosts**.
- Discover and track relevant public DNS records.
- Inspect TLS certificates and identify expired certificates.
- Check selected service ports using four documented checks.
- Establish and maintain a baseline inventory.
- Perform scheduled inventory comparisons.
- Detect seeded expired certificates, unexpected services and potential dangling DNS records.
- Generate actionable alerts and inventory change reports.
- Evaluate detection accuracy, false positives and missed findings.
- Produce the required technical report and prototype demonstration.

## Key Features

### 1. Attack-Surface Inventory
Maintains a structured inventory of approved domains, hosts, DNS records, TLS certificates and observed services.

### 2. DNS Monitoring
Collects relevant DNS records, including A, AAAA, CNAME, MX and TXT records where applicable. Compares observations to identify additions, removals and modifications.

### 3. TLS Certificate Monitoring
Inspects certificates presented by approved TLS endpoints and records validity periods, expiry dates, issuer and subject information where available. Flags expired certificates and configurable expiry thresholds.

### 4. Exposed-Service Monitoring
Checks only explicitly approved hosts and configured ports. Compares observed services with the baseline to identify newly exposed or unexpected services.

### 5. Potential Dangling DNS Detection
Identifies DNS records whose targets may reference unavailable or decommissioned infrastructure. Flags these as candidates for investigation rather than treating them as proof of exploitability.

### 6. Baseline and Change Detection
Stores a baseline inventory and periodically compares new observations against previous snapshots. Classifies differences as additions, removals, modifications or potentially suspicious changes.

### 7. Alerts and Reporting
Generates findings containing the affected asset, observation time, detection reason, supporting evidence, severity and recommended next action.

### 8. False-Positive Analysis
Documents uncertain findings, validation outcomes and possible false positives to distinguish confirmed observations from suspected misconfigurations.

## System Architecture

The system follows a modular monitoring pipeline:

1. **Scope Validation:** Loads the written, organiser-approved domains, hosts and permitted ports.
2. **Discovery Engine:** Collects permitted DNS, TLS and service observations.
3. **Data Normalisation:** Converts observations into a consistent inventory format.
4. **Inventory Storage:** Maintains baseline records and subsequent snapshots.
5. **Change-Detection Engine:** Compares current observations with the stored baseline.
6. **Finding Classification:** Identifies expired certificates, unexpected services and potential dangling DNS records.
7. **Alerting and Reporting:** Generates actionable findings and change summaries.
8. **Scheduler:** Triggers recurring inventory collection and comparison.

## Monitoring Checks

The prototype will document and execute four permitted service checks within the approved lab scope.

| Check | Purpose |
|---|---|
| TCP connectivity | Determines whether an approved TCP port accepts a connection. |
| Service identification | Identifies services using explicitly permitted, non-invasive protocol checks where supported. |
| TLS certificate inspection | Collects and validates certificate information on configured TLS endpoints. |
| Baseline comparison | Identifies newly observed or changed services relative to the stored inventory. |

DNS monitoring operates as a separate inventory function. Each check produces a defined result that can be stored, compared and reviewed.

## Detection Methodology

### Expired Certificates
Compare the certificate's validity period with the observation timestamp. Generate a finding when the certificate has expired.

### Unexpected Services
Compare observed host-and-port combinations with the approved baseline. Flag newly observed services for investigation instead of automatically classifying every change as malicious.

### Potential Dangling DNS Records
Identify suspicious CNAME targets using DNS resolution results and additional target-state evidence where available. An unresolved target alone does not establish that a record is dangling or exploitable.

### Inventory Changes
Compare normalised inventory snapshots to identify new, removed or modified assets. Preserve timestamps and supporting observations for reproducibility.

## Pseudocode

```text
INPUT:
    approved_domains
    approved_hosts
    permitted_ports
    stored_baseline

VALIDATE approved target scope

IF scope is not approved:
    STOP monitoring

FOR each approved domain and host:
    collect permitted DNS observations
    inspect configured TLS endpoints
    execute documented service checks
    normalise and store observations

    detect expired certificates
    identify unexpected services
    identify potential dangling DNS candidates

    record findings with timestamps and evidence

current_inventory = collected observations

changes = compare(current_inventory, stored_baseline)

FOR each detected change:
    classify the change
    assess confidence and possible false positives
    generate an actionable finding when appropriate

save current inventory
generate inventory and change reports
update baseline according to the approved workflow
```

## Security and Scope Restrictions

- Monitor only written, organiser-approved domains, hosts and ports.
- Validate scope before executing network checks.
- Restrict monitoring to the defined portfolio of up to 20 domains and 10 hosts.
- Do not perform exploitation, credential attacks or unrestricted scanning.
- Do not automatically claim or take over suspected dangling DNS resources.
- Do not claim that an unresolved DNS record is necessarily exploitable.
- Preserve supporting evidence and timestamps.
- Document uncertainty, limitations and false positives.

## Validation and Evaluation

The prototype will be tested against organiser-provided lab assets and seeded issues.

| Test Scenario | Expected Result |
|---|---|
| Seeded expired certificate | Generate a finding with certificate validity details. |
| Seeded unexpected service | Identify the service as a change from the baseline. |
| Seeded potential dangling DNS record | Flag a candidate with supporting evidence and uncertainty noted. |
| Unchanged inventory | Avoid generating unnecessary change alerts. |
| Legitimate DNS or service change | Record and classify the change for review. |
| Out-of-scope target | Reject the monitoring request. |
| False-positive candidate | Document the validation outcome or unresolved status. |

Evaluation will document detection counts, false positives, missed seeded issues and limitations observed during testing. Actual results will be included after execution and verification.

## Expected Deliverables

1. **Attack-Surface Inventory:** Records of approved domains, hosts, DNS, TLS and services.
2. **Scheduled Change Detection:** Repeatable collection and baseline comparison.
3. **Monitoring Checks:** Documented DNS, TLS and selected-service checks.
4. **Alert and Change Reports:** Findings with evidence, timestamps and recommended actions.
5. **Seeded-Issue Detection Results:** Validation against the required test scenarios.
6. **False-Positive Analysis:** Documented uncertainty, validation outcomes and limitations.
7. **Final Technical Report:** Architecture, methodology, implementation, testing and evaluation.
8. **Prototype Demonstration:** Working demonstration accompanied by a pseudocode snippet.
9. **Hackathon Documentation:** PDF prepared according to the organiser-provided `Proposed-structure-hackathon.pdf` guidelines.

## Technology Stack

The implementation may use the following technologies, depending on the final design:

- **Python:** Monitoring and detection logic.
- **DNS libraries:** DNS record collection and resolution.
- **TLS/SSL libraries:** Certificate inspection and validity checks.
- **Networking libraries:** Controlled TCP connectivity and permitted service checks.
- **SQLite or PostgreSQL:** Inventory, baseline and finding persistence.
- **Scheduler:** Periodic monitoring execution.
- **JSON, CSV or HTML:** Inventory exports and reports.
- **pytest:** Unit and integration testing.

Only technologies actually used should be listed as completed implementation dependencies.

## Project Status

**Stage:** Prototype development and validation.

Implementation status, test coverage, seeded-issue detection results and performance measurements will be documented as the corresponding components are completed and verified.

## Disclaimer

This project is intended exclusively for authorised security inventory and defensive monitoring. All targets and ports must be explicitly approved by the organisers. Findings describe observed conditions and potential risks; they do not automatically establish malicious activity or exploitability.
