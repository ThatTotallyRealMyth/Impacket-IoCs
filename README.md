# Dissecting Impacket

A public reference of protocol-level and implementation-level indicators of compromise(IoCs) for detecting Impacket-driven activity.

Feel free to open an issue if you find something you think I incorrectly stated, for any feedback or if you have a specific protocol or implementation youd like me to add fingerprints for

## Overview

This repository contains a part of my notes from an internal rewrite/fork of Impacket that I had undertaken at my current job. I had taken alot of the internal signals produced by Impacket and several of its example tools and provided them here for other blue and red teamers to benefit from. 

The goal is to help defenders understand what Impacket activity can look like at the protocol, authentication, and implementation layers beyond just at the command-line or artifact level. For red teamers, I hope that this repo servers as an inspiration for operators to undertake similar iniatives to improve the operational security of their toolkits as well as serve as a blueprint for how to approach dissecting tooling to understand normal from abnormal.

Much of offensive tooling detection focuses on things like filenames, service names, temporary paths, command output redirection, scheduled task names, and other surface-level artifacts. Those detections are useful, but they are also often easy to change.

While there is some of them, this project tries to focuse on deeper signals: Kerberos request construction, NTLMSSP fields, SPNEGO wrapping, SMB negotiation behavior, DCE/RPC authentication trailers, WMI/DCOM activation details, LDAP object creation patterns, and example-script defaults.

The intent is to give defenders, especially smaller teams without access to expensive commercial detection content, practical signals they can use to build stronger fingerprints for Impacket abuse. Similarly its to showcase to red teamers the sort of artifacts and signals their tooling could or may leave behind and to better showcase approaching that to improve engagment delivery.

## What is included

This research currently documents **67 Impacket-related IoCs** across the following categories:

| Category | Count | Examples |
| --- | ---: | --- |
| Kerberos and ticketing | 15 | AS-REQ differences, TGS-REQ etype ordering, AP-REQ wrapping, forged ticket defaults |
| SMB | 3 | SMB2/3 ClientGuid, negotiate context behavior, SMB1 dialect negotiation |
| NTLM and SPNEGO | 11 | NTLMSSP omissions, NTLMv2 challenge shape, NTLM class spec deviations/violations, SPNEGO wrapping differences |
| LDAP and Active Directory objects | 2 | Default computer/object creation naming patterns |
| DCE/RPC, DCOM, and WMI | 15 | `auth_context_id`, missing verification trailers, WMI/DCOM activation behavior, dummy/fake OpNum use in RPC relay clients |
| Example-script execution artifacts | 7 | `psexec.py`, `smbexec.py`, `atexec.py`, `dcomexec.py`, RemCom artifacts |
| secretsdump, DRSUAPI, and VSS | 4 | DRSBind behavior, DRSGetNCChanges defaults, VSS execution patterns |
| MSSQL | 4 | LOGIN7 metadata, PRELOGIN behavior, SQL Agent job creation |
| ntlmrelayx HTTP, WebDAV, RDP, and SCCM | 6 | WPAD, WebDAV, RDP relay certificate, SCCM policy strings |

## How to read this research

Not every IoC in this repository should be interpreted the same way.

Some indicators are strong standalone fingerprints. Others are best treated as enrichment signals, weak features, or noise reducers that become valuable when combined with additional evidence.

A good detection strategy should separate these into three rough groups:

### 1. High-confidence standalone signals

These are indicators that are unusual enough to be meaningful on their own in many environments.

Examples include:

- Authenticated DCE/RPC using `auth_context_id = 79231 + ctx_id`
- DCE/RPC authentication padding using `0xff`
- LDAP Kerberos bind placing a raw Kerberos `AP-REQ` directly in the SPNEGO `mechToken`
- SMB2/3 negotiate requests with ASCII-letter `ClientGuid` values
- WMI `IWbemLevel1Login::NTLMLogin` using non spec compliant namespacing slashes `//./root/cimv2`
- Hardcoded Kerberos noonce value

These should still be validated in your own environment, but they are the types of signals that may justify higher-confidence alerting when seen in the right context.

### 2. Cluster-based signals

Some indicators are not reliable enough alone, but become powerful when several appear together from the same source host, user, session, or time window.

Examples include:

- Sparse Kerberos AS-REQ encryption type lists
- Missing or unusual Kerberos `PA-DATA`
- TGS-REQ encryption type ordering differences/duplicate entries
- NTLM Type 1 messages missing version information
- NTLM Type 3 messages with null host names
- Raw NTLMSSP in DCE/RPC instead of SPNEGO
- Missing DCE/RPC verification trailers
- Mismatch in Kerberos Auth OIDs specified between the mechList and the KRB_OID/TOK values

These are well-suited for scoring models, correlation searches, or detection logic that says: “This activity has multiple Impacket-like implementation traits.”

### 3. Noise reducers and supporting context

Some IoCs are better used to reduce noise, enrich other detections, or explain why an alert is suspicious.

Examples include:

- Default filenames or output paths
- Random service naming patterns
- Temporary batch file names
- Default computer account names
- Tool-specific HTTP, WebDAV, RDP, or MSSQL strings
- DCE/RPC UUID Entries that dont confer with Microsoft patterns of Versioning/Variants

These are useful, but they are also more operator-controllable. Treat them as supporting evidence rather than the only reason an alert fires.

## Why protocol-level detection matters

Many Impacket fingerprints exist below the level most operators interact with.

An operator can rename a service, change an output file, modify a command string, or patch an example script. They may not notice that the library is still shaping Kerberos, NTLM, SMB, LDAP, or DCE/RPC traffic in a way that differs from normal Windows behavior.

That is where durable detection often lives.

The best detections come from understanding three things at the same time:

1. What the protocol allows
2. What Windows normally emits
3. Where Impacket consistently behaves differently enough that it can be a statical anomoly

This research attempts to document those differences in a way that defenders can turn into practical network, endpoint, or telemetry-driven detections. While also in a way for red teamers to learn from, and expand on in their own tooling

## Recommended usage

Use this repository as a reference for building, validating and (if youre a red teamer) defeating detections, not as a direct copy/paste alert library.

For each IoC, consider:

- Does this field appear in my telemetry?
- Can I decode or extract it reliably?
- Does my environment have legitimate software that behaves similarly?
- Is this strong enough to alert on alone?
- Should this instead be used as a correlation feature?
- Does the signal become stronger when paired with Kerberos, SMB, NTLM, LDAP, or DCE/RPC activity from the same host?
- Would I be able to leverage statistical modeling and data analysis tricks to elevate the effectiveness of the signal?

Whenever possible, build detections around clusters of behavior rather than a single field.

For example, a single missing NTLM version field may not be enough. But a client that also shows raw NTLMSSP over DCE/RPC, missing verification trailers, an Impacket-style `auth_context_id`, and unusual WMI activation behavior is much more interesting and almost always garunteed to be an impacket user as opposed to a real windows device. 

## Caveats

This research should be interpreted with context.

- Some behaviors may vary by Impacket version, fork, or local modification. I used the last/most current main
- Some behaviors may vary by Windows version, domain policy, authentication type, or service being accessed. Testing was done on Windows server 2022 and Windows Server 2012
- Some indicators may overlap with Samba, Linux clients, legacy software, appliances, or custom implementations.
- Some detections require decrypted traffic, endpoint telemetry, ETW, Zeek-style protocol parsing, PCAP analysis, or service-side visibility.
- Line numbers in source references may drift over time as Impacket changes.
- A single protocol field rarely tells the whole story.

The safest way to operationalize this work is to test against your own baseline and then promote detections gradually from enrichment, to hunting, to alerting.

## Suggested detection philosophy

A practical approach is:

1. Use high-confidence protocol quirks as direct alerts where your environment supports it.
2. Use weaker implementation quirks as scoring features.
3. Correlate across protocol layers.
4. Prefer clusters over single-field assumptions.
5. Treat tool defaults as supporting evidence, not the whole detection.
6. Re-test detections when Impacket or Windows behavior changes.

As these things usually are, its a cat and mouse game. I have no doubt that the detections spelled out here will soon become obselete but when they do, I hope that the next person out does me and the rest : ) 
