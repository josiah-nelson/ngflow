# Extreme Networks exporter notes

This collector includes vendor-specific fidelity and enrichment for the following platforms:

- **EXOS X435 (EXOS 33.5)**
- **5120 Switch Engine (EXOS 33.5.2)**
- **5520 Fabric Engine (9.3.1.0)**

The goal is to keep NetFlow v9/IPFIX/sFlow output aligned with ntopng expectations while preserving Extreme-specific fields and adding optional SNMP interface enrichment.

## Templates and fixtures

Example templates and flows live in `testdata/extreme`:

- `testdata/extreme/templates/exos_switch_engine.json`
- `testdata/extreme/templates/fabric_engine.json`
- `testdata/extreme/flows/exos_flow.json`
- `testdata/extreme/flows/fabric_flow.json`

These are used by tests to ensure that application telemetry, observation point/domain IDs, and interface metadata are represented consistently.

## Exporter configuration examples

> The exact CLI differs by platform and release. Treat these as representative configurations.

### EXOS Switch Engine (X435 / 5120)

```shell
# NetFlow v9
configure netflow add exporter collector 192.0.2.50 port 2055
configure netflow add exporter collector 192.0.2.50 version 9
configure netflow add exporter collector 192.0.2.50 source-interface vlan 10
configure netflow add flow ip

# IPFIX
configure ipfix add exporter collector 192.0.2.50 port 2055
configure ipfix add exporter collector 192.0.2.50 source-interface vlan 10
configure ipfix add flow ip

# sFlow
enable sflow
configure sflow collector 192.0.2.50 6343
configure sflow agent ipaddress 192.0.2.10
configure sflow port all sample-rate 1024
```

### Fabric Engine (5520)

```shell
# IPFIX
ipfix enable
ipfix collector add 192.0.2.50 2055
ipfix exporter source-interface vlan 10
ipfix flow add ip

# sFlow
sflow enable
sflow collector add 192.0.2.50 6343
sflow agent ipaddress 192.0.2.20
sflow sampling-rate 1024
```

## SNMP enrichment

Enable SNMP enrichment to map `ifIndex` values to interface metadata:

- **ifName** via `ifName` (IF-MIB `1.3.6.1.2.1.31.1.1.1.1`)
- **ifAlias** via `ifAlias` (IF-MIB `1.3.6.1.2.1.31.1.1.1.18`)
- **ifSpeed** via `ifHighSpeed` (IF-MIB `1.3.6.1.2.1.31.1.1.1.15`, Mbps) with a fallback to `ifSpeed` (IF-MIB `1.3.6.1.2.1.2.2.1.5`, bps)

The collector injects interface metadata into the flow payload as:

- `in_ifName`, `in_ifAlias`, `in_ifSpeed`
- `out_ifName`, `out_ifAlias`, `out_ifSpeed`

SNMP enrichment is optional and disabled by default. See the CLI flags in the README to enable it.

## L7 classification (nDPI)

The collector performs **lightweight nDPI-style classification** using exported application telemetry only. It never inspects payloads or enforces policy. Supported categories are limited to:

- `sip`
- `video`
- `audio`
- `control`

Classification is derived from application names (e.g., SIP, RTSP, RTP, SNMP). General user/web traffic is intentionally excluded. Categories can be controlled via `--ndpi-categories`.

## Gotchas and field behavior

- **Template churn**: EXOS and Fabric Engine change templates when policy/telemetry features are enabled or disabled. Watch the `/templates` endpoint and refresh caches after configuration changes.
- **Observation domain & point**: Treat `(exporter IP, observationDomainId, observationPointId)` as a tuple. Observation IDs can map to logical chassis/ports and may be reused across stack members.
- **CLEAR-FLOW fields**: CLEAR-FLOW metadata is exported as enterprise-specific fields. Capture those templates in `testdata/extreme/templates` and update them if new fields appear.
- **Application telemetry**: Application IDs/names may be absent on some flow types or in sFlow. nDPI classification only runs when application telemetry is present.
- **Missing SNMP data**: If a switch returns empty `ifAlias` or `ifName`, enrichment is skipped for that interface without blocking flow export.
- **Interface speed**: Prefer `ifHighSpeed` (Mbps) for 10G+ interfaces. Falling back to `ifSpeed` (bps) avoids under-reporting.

## ntopng compatibility

The JSON/TLV payloads aim to remain compatible with the latest two minor ntopng releases at the time of this change (6.4 and 6.5). If ntopng adds new parsing requirements, update the templates and fixtures accordingly.
