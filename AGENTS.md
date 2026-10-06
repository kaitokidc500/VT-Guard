# VT-Guard — project instructions and agreed context

Context frozen: 2026-10-06, Asia/Bangkok (UTC+7).
This file transfers decisions from a prior research discussion into a new repository.
Do not assume access to that conversation, the user's VMs, credentials, or prior code.
Communicate with the user in Vietnamese. Code identifiers may be English.

## 1. Objective and constraints

Working project name: **VT-Guard: Adaptive Hybrid Detection for Volt Typhoon TTPs**.
The final Vietnamese thesis title has not been fixed in this handoff.
Owner: Trần Văn Tiến, cybersecurity student at Học viện An ninh nhân dân.
One-person project, target submission 2026-10-26, approximately 15-minute demo.
All activity is for research on owned/authorized lab infrastructure.

Three required product capabilities:
1. Automatically induce detection rules from training data.
2. Combine those generated rules with an AI model in an operational fusion engine.
3. Apply a customized AI model and evaluate its contribution.

Proposed baseline design, agreed as the implementation direction:
- Explainable rule induction: Decision Tree -> candidate conditions -> validated rules.
- Customized model: GRU with attention, multi-task attack detection and TTP prediction.
- Hybrid fusion: AI attack score, TTP probabilities, and generated-rule match vector.
- Docker-deployable detection service and dashboard consuming Wazuh telemetry.

Scope is behavior detection for selected techniques associated with Volt Typhoon.
Do not describe this as attribution of a real intrusion to Volt Typhoon or coverage of
the entire campaign. These techniques are shared with other actors and legitimate admins.

## 2. Exactly five target techniques

| ID | Name | Representative lab behavior |
|---|---|---|
| T1016 | System Network Configuration Discovery | ipconfig /all, route print, arp -a |
| T1049 | System Network Connections Discovery | netstat -ano, Get-NetTCPConnection |
| T1018 | Remote System Discovery | domain/computer discovery, scoped lab host discovery |
| T1087.002 | Account Discovery: Domain Account | net user /domain, AD account queries |
| T1654 | Log Enumeration | wevtutil queries, Get-WinEvent, Get-EventLog |

Do not confuse T1087.002 with local accounts or domain group discovery. T1654 concerns
reading/enumerating logs, not clearing them. A DNS lookup or use of a tool alone does
not prove malicious intent; labels require scenario context and evidence.
Pin the ATT&CK reference/version used by the dataset and document mapping decisions.

## 3. Existing infrastructure (user-reported complete)

VMware lab network VMnet2: 10.20.30.0/24. Domain: corp.vtlab.test.

| Machine | IP | Role |
|---|---|---|
| VT-SIEM01 | 10.20.30.10 | Ubuntu, NAT + host-only, Docker Wazuh stack |
| DC01 | 10.20.30.20 | Windows AD DS + DNS, Wazuh Agent |
| WIN10-01 | 10.20.30.30 | Windows 10 domain client, Wazuh Agent |

Windows DNS points to DC01. Both agents reported active and all three channels were
reported visible in wazuh-archives-*. This is prior user evidence, not a fresh test.

Collected channels:
- Security: 4624, 4634, 4672 when applicable, 4688.
- Microsoft-Windows-Sysmon/Operational: 1, 3, 22; other IDs can also be present.
- Microsoft-Windows-PowerShell/Operational: 4103, 4104.

Wazuh manager: logall_json=yes; Filebeat archives forwarding enabled.
Raw archive path in manager: /var/ossec/logs/archives/archives.json.
Indexer input: wazuh-archives-*.
Existing Wazuh Compose directory on SIEM:
~/vt-guard/infra/wazuh-docker/single-node
Existing services: wazuh.manager, wazuh.indexer, wazuh.dashboard.

Do not overwrite the existing Wazuh stack or its volumes. No docker compose down -v,
volume prune, broad log deletion, or direct edits to VM disks/snapshots.
The SIEM has approximately 12 GB RAM; disk pressure has occurred. Measure consumption,
use bounded caches/queues, configurable retention, and download selected datasets only.
Wazuh version, port exposure, certificates, credentials and exact Compose configuration
must be inspected before integration; they are not established here.

## 4. Agreed workflow and deployment

1. Develop a single repository locally in VS Code with Codex.
2. Version source code with Git; GitHub is the intended transfer mechanism to Colab.
   Repository URL and public/private visibility are not yet specified.
3. Train on public datasets using Google Colab, with durable checkpoints in Google Drive.
4. Export a complete versioned detector bundle.
5. Deploy CPU inference on VT-SIEM01 alongside Wazuh, using separate VT-Guard containers.
6. Evaluate on new benign/admin and five-TTP lab runs. Collect and independently label them.
7. Use only the designated lab adaptation/train split to improve training and rules.
8. Compare v1/v2 on a fixed held-out lab test and check public-data performance retention.

No model is installed on DC01/WIN10-01. They generate telemetry and run Wazuh Agent.
No training is planned on the SIEM. Colab is not expected to reach private 10.20.30.x IPs.
Transfer exported artifacts through the host to SIEM; no Internet tunnel is needed.
Do not train until data quality and a small end-to-end smoke run have been checked.

## 5. Public dataset findings and limitations

Sources below were verified at documentation level in the prior conversation. They have
NOT been fully downloaded/audited as a training corpus. Validate actual files and licenses,
record provenance/commit/version/checksum, and report counts before claiming coverage.

Primary repository: https://github.com/splunk/attack_data

| Technique | Verified source | Repository path |
|---|---|---|
| T1016 | Discovery Commands; Sysmon | datasets/attack_techniques/T1016/discovery_commands/windows-sysmon.log |
| T1049 | AD Discovery; Sysmon | datasets/attack_techniques/T1049/AD_discovery/windows-sysmon.log |
| T1018 | AD Discovery; Sysmon | datasets/attack_techniques/T1018/AD_discovery/windows-sysmon.log |
| T1087.002 | ADSI Discovery; PowerShell | datasets/attack_techniques/T1087.002/adsi_discovery/windows-powershell-xml.log and xml1/xml2 variants |
| T1654 | EventLog Enumeration; Sysmon | datasets/attack_techniques/T1654/eventlog_enumeration/eventlog_enumeration.log |

Source documentation:
- https://research.splunk.com/attack_data/cc9b25e5-efc9-11eb-926b-550bf0943fbb/
- https://research.splunk.com/attack_data/61da8e36-d038-4a92-900e-8f726bfc1b05/
- https://research.splunk.com/attack_data/82e395f1-71d8-4cfc-8757-2dd3ab527e77/
- https://research.splunk.com/attack_data/acd06afa-c6d6-11ec-9d0f-acde48001122/
- https://research.splunk.com/endpoint/dc167f8b-3f9d-4460-9c98-8b6e703fd628/

The T1654 file was opened: it includes wevtutil, Get-WinEvent and WMIC log queries, but
also an Amazon SSM Agent log-query process. Do not blanket-label the file malicious.
The T1049 source describes a PowerShell implant. Prevent learning emulator/tool identity
instead of the intended behavior. Detection unit-test data may be selected positive
examples, not continuous representative sessions. Audit before sequence training.

Additional candidate: Windows-APT 2025 v3.
- https://data.mendeley.com/datasets/b8fmtzvpy8/3
- https://cybersciencelab.com/datasets/windows-apt-2025/
Authors describe Windows 10, Caldera, Wazuh/Sysmon, 36 scenarios, approximately 102k
records in 19 CSVs, CC BY 4.0. Coverage of all five target TTPs, label origin, session
boundaries and availability of non-alert/background events are UNVERIFIED.

Optional secondary sources (not mandatory dependencies):
- https://github.com/OTRF/Security-Datasets
- https://github.com/skrghosh/apt-dataset (CAR/eCAR schema; inspect mapping quality).

Prefer selected relevant downloads. Do not claim a ready-to-train full five-TTP dataset
merely because a repository has matching directory names. No fixed public/lab percentage
or guaranteed minimum number of training examples has been established.

## 6. Data contracts and leakage prevention

Maintain raw, normalized and model-ready layers. Preserve raw references and distinguish
event time from ingestion time. For Sysmon retain both System/TimeCreated and EventData/
UtcTime where available; document the canonical time used for ordering.

Normalized schema should cover, where available:
- event UID, source dataset/version/file, host, host role, channel, event ID, record ID;
- event_time_utc, ingest_time_utc, user, logon ID;
- process GUID, parent GUID, PID, image, parent image, command line;
- script block text/ID and fragment information;
- destination IP/port, DNS query;
- run/scenario metadata, activity label, TTP labels, label confidence and evidence.

Missing fields remain missing with explicit masks; never fabricate values. Handle script
block fragmentation, duplicates, PID reuse, clock differences and arrival delays.
Security 4688 and Sysmon 1 for the same process are related observations, not identical
duplicate events. Link them when feasible and preserve provenance.

Keep metadata and labels separate from model inputs. Exclude dataset names, run IDs,
scenario markers, rule IDs/levels, pre-existing ATT&CK labels, user/host shortcuts and
automation identifiers from learned features when they expose the answer.
Do not use model predictions or Wazuh rule matches as unquestioned ground truth.
Allow unknown/ambiguous/background/automation-control labels for review.

Split by independent run/session/scenario family before making overlapping windows.
Keep replicas, augmentations and shared-origin exports in the same split. Fit vocabularies,
scalers and feature selectors on train only. Deduplicate across sources where needed.
Do not make all attack data public and all benign data local with a random event split.
Do not join unrelated technique files into an asserted real attack sequence. Synthetic
sequences, if used, are explicitly flagged, training-only supplements.

Sequence starting hypothesis: group by host and reliable user/logon context, up to 64
events over up to five minutes, padding/masking. These are tunable values, not proven
defaults. Online and offline transformations must share code and remain causal.
The TTP head is multi-label. Technique-like behavior can occur in benign administration;
the attack head predicts scenario risk, not intent knowable only to the operator.

## 7. Models, rules and fusion

Implement a small CPU-friendly baseline before the customized GRU-Attention. Document
what is customized (e.g. event/context encoding, time features, attention, dual heads)
and evaluate against a simpler baseline; do not claim architectural novelty without evidence.

Rule induction learns on train. Existing Sigma/Splunk rules are reference/baseline only.
Store candidate conditions, support, validation metrics, schema and provenance. Restrict
the induction feature space to conditions the deployed rule engine can actually evaluate.
Single-event conditions may map to Sigma; temporal/count/sequence conditions require
correlation support. Do not blindly translate every tree branch into ordinary Sigma.
Initially run generated rules inside VT-Guard. Wazuh XML integration is optional later.

Use out-of-fold training predictions for learned fusion where appropriate. Validation is
used for selection and thresholds; final test is untouched. No tuning to improve a test
score after inspecting it without declaring the new evaluation protocol.

Evaluate rule-only, AI-only, hybrid; GRU baseline versus customized model; v1 versus v2.
Report attack precision/recall/F1/PR-AUC, per-TTP and macro metrics, benign-admin false
positives, alerts per benign hour, session detection and end-to-end latency in lab.
Report sample/run counts and variability. Never invent results or assume v2 improves.

## 8. Artifact and inference contract

Versioned bundle must include weights, architecture config, preprocessing/vocabulary/
scaler, sequence config, labels, generated rules, fusion parameters and thresholds,
schema version, code commit, data/split provenance, dependency versions, metrics and
checksums. Training-only resume checkpoints may remain in Drive rather than the SIEM bundle.
Load on CPU and compare reference inference on fixed examples before deployment.
Mount bundles read-only; record detector version in every result. Reject incompatible
schema/artifact versions explicitly and preserve a path back to the previous version.

Proposed service path: Wazuh Indexer -> incremental collector -> shared normalizer ->
sequence builder -> AI + generated rules -> fusion -> results store/API/dashboard.
Collector must persist cursor/checkpoint, deduplicate IDs, handle late data and retries,
and avoid feedback loops from its own result indices. Input access should be read-only.
Choose poll interval and measure latency; describe this as near-real-time when polling.
Keep credentials in environment/secrets configuration, not Git or notebooks.
Use configured certificate trust rather than disabling TLS checks as the production default.
Dashboard address http://10.20.30.10:8080 is a proposal, not an existing endpoint.
Dashboard: host, time, predicted TTPs, AI score, rule matches, hybrid score, evidence, version.

## 9. Proposed repository layout and Colab workflow

Suggested layout (not already implemented):

    pyproject.toml
    src/vtguard/{data,features,models,training,rule_induction,fusion,inference,evaluation}/
    configs/{train_public.yaml,inference.yaml}
    notebooks/train_colab.ipynb
    tests/
    deployment/{Dockerfile,compose.yaml}
    docs/{architecture.md,data_contract.md,experiment_protocol.md,STATUS.md}

Keep implementation in importable Python modules; notebook orchestrates those modules.
Use one shared preprocessing implementation for offline and online. Use configurable
cross-platform paths, never hard-code C:\... or /content throughout core modules.
Lock/document compatible dependency environments for Colab GPU training and SIEM CPU.
Use a tested PyTorch configuration; do not indiscriminately reinstall Colab CUDA packages.

Colab notebook: fetch pinned code -> install training dependencies -> verify hardware ->
mount Drive -> stage data on /content -> validate/prepare -> train -> induce rules ->
fit fusion -> evaluate -> export. Save checkpoints durably; /content is disposable.
Source resides in Git; large data/weights/checkpoints are excluded from normal Git.
Colab GPU availability is variable. Provide resume and a small CPU smoke-run path.
GitHub is intended but no repository is created/authorized for public publication here.

## 10. Prior pilot result and lesson

A P01 GUI automation script was run once; its files are not assumed to exist in this repo.
Run: WIN10-01, VTLAB\Administrator, elevated, runner PID 2712.
UTC: 2026-10-06T14:28:57.1823905Z to 2026-10-06T14:30:31.1015456Z (~94 s).
Opened Notepad PID 1964, typed/corrected notes, verified 106-byte save, closed Notepad.
Failed to identify a new Documents Explorer window; reopening note and Calculator never ran.
Manifest status: failed_partial_evidence_retained. Three of six core GUI activities complete.
Local export: Security 4688 x3; Sysmon 1 x3, 3 x12, 5 x2; PowerShell 4103 x312, 4104 x14.
Total 346. All 326 PowerShell events belonged to runner PID 2712 (~94.2% of all events).
Background Edge used VTLAB\user01. New Explorer process was observed, but GUI recognition
failed; exact cause unproven. One exported PowerShell event predates start by ~139 ms.
This pilot did not independently verify Wazuh Indexer receipt.

Keep this as a partial/debugging case, not a completed training session. Do not disable
PowerShell logging to hide automation noise. Preserve raw data and filter/tag controller
telemetry in the model view. Retain relevant child app events. Manual benign lab sessions
may be simpler and more representative than further GUI automation.
Current priority is project + public dataset workflow, not expanding P01 scripts.

## 11. Execution rules for the coding agent

- Inspect the current folder and instructions first. Never assume it is empty or the
  existing ~/vt-guard on SIEM. Preserve unrelated files and existing infrastructure.
- Restate fixed decisions and unresolved implementation assumptions briefly in Vietnamese.
- Keep a concrete plan and implement useful runnable slices. Do not stop at a plan when
  the user requested implementation. Ask only for missing facts that actually block work.
- First slice: package/config/schema, input adapters, data-quality report, a small fixture
  and an end-to-end CPU smoke path toward artifact loading. Build before expensive training.
- Fixtures may be synthetic for parser tests, clearly marked, never reported as real evidence.
- Audit public data before committing to a full training run: provenance, exact IDs, event
  counts, independent sessions, labels, class/source balance, missing fields and duplicate data.
- Prefer meaningful tests for parsers, split leakage, sequence ordering, rule semantics,
  artifact loading and offline/online parity. Never claim Windows/Colab/SIEM tests ran locally
  if they did not. Report commands executed and outstanding platform validation.
- Do not claim an untrained random model is a completed detector. UI/mock results are labeled.
- Do not add Kafka, Redis, Kubernetes, LLM agents or paid services without a demonstrated need.
- Do not publish, upload lab credentials, change logging policy or deploy to live VMs unless
  authorized for that action. Routine local implementation and tests may proceed.
- Update docs/STATUS.md after milestones: implemented, tested, unresolved, next action.
  Record any changed architecture/data assumption in docs with reason and evidence.
- User decisions after this handoff supersede its proposals. No requirement to reuse a
  previous unrelated project's step-gating rules (e.g. c500cyber).

## 12. Current starting point

No complete VT-Guard repository, validated public training dataset, trained model or Docker
deployment has been delivered in the preceding conversation. Most CLI names and layouts
were architectural examples. Treat them as interfaces to implement, not existing commands.
The existing Wazuh lab is the completed foundation. Build the software around its contracts.
