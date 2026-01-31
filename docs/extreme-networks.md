# Extreme Networks Support

This document covers vendor-specific support for Extreme Networks devices in ngflow.

> **Documentation Sources**: Configuration defaults and CLI examples are derived from official Extreme Networks documentation.

## Supported Platforms

| Device | OS | Flow Protocol | Status |
|---|---|---|---|
| X435 | ExtremeXOS 33.x (Value Edge) | sFlow v5 | Supported |
| 5120 | Switch Engine 33.5.x | sFlow v5 | Supported |
| 5520 | Fabric Engine 9.3.x | IPFIX | Supported |
| 5520 | Switch Engine 33.5.x | sFlow v5 | Supported |

## Templates and Fixtures

Example templates and flows live in `testdata/extreme`:

- `testdata/extreme/templates/exos_switch_engine.json`
- `testdata/extreme/templates/fabric_engine.json`
- `testdata/extreme/flows/exos_flow.json`
- `testdata/extreme/flows/fabric_flow.json`

These fixtures cover application telemetry, observation point/domain IDs, and interface metadata fields that matter for ntopng.

## Quick Start

### Switch Engine / EXOS (sFlow)

```bash
# On the switch
enable sflow
configure sflow agent ipaddress 192.0.2.10
configure sflow collector 192.0.2.50 port 6343
configure sflow sample-rate 4096
enable sflow ports all

# Start the collector
netflow2ng --sflow-listen 0.0.0.0:6343 \
  --snmp-enabled \
  --snmp-community public \
  --ndpi-categories "sip,video,audio,control,services" \
  --l7-enabled
```

### Fabric Engine (IPFIX)

```bash
# On the switch
enable
configure terminal
ip ipfix enable
ip ipfix collector 1 192.0.2.50 exporter-ip 192.0.2.10 dest-port 2055
ip ipfix ports 1/1-1/48 enable

# Start the collector
netflow2ng -a 0.0.0.0:2055 \
  --snmp-enabled \
  --snmp-community public \
  --ndpi-categories "sip,video,audio,control,services" \
  --l7-enabled
```

## Switch Engine / EXOS sFlow Configuration

### CLI Commands

| Command | Description | Default |
|---|---|---|
| `enable sflow` | Enable sFlow globally | disabled |
| `configure sflow agent ipaddress <ip>` | Set agent IP | none (required) |
| `configure sflow collector <ip> port <port>` | Configure collector | port 6343 |
| `configure sflow sample-rate <rate>` | Global sampling rate (1:N) | 4096 |
| `configure sflow poll-interval <seconds>` | Counter polling interval | 20 seconds |
| `enable sflow ports <port-list>` | Enable on ports | disabled |

### Documented Defaults

- **sFlow version**: 5
- **Polling interval**: 20 seconds (range: 0-300, 0 disables)
- **Sampling rate**: 1:4096
- **UDP port**: 6343

## Fabric Engine IPFIX Configuration

### CLI Commands

| Command | Description | Default |
|---|---|---|
| `ip ipfix enable` | Enable IPFIX globally | disabled |
| `ip ipfix collector <id> <ip> exporter-ip <ip> dest-port <port>` | Configure collector | none |
| `ip ipfix slot <slot> aging-interval <seconds>` | Flow aging timeout | 30 seconds |
| `ip ipfix export-interval <seconds>` | Export interval | varies |
| `ip ipfix template-refresh-interval <seconds>` | Template refresh | 1800 (30 min) |
| `ip ipfix ports <port-list> enable` | Enable on ports | disabled |

### Documented Defaults

- **Aging interval**: 30 seconds
- **Template refresh**: 1,800 seconds (also refreshes every 10,000 packets)
- **Max collectors**: 2 (data not load balanced between them)

### Limitations (per vendor documentation)

- **IPv4 only**: IPFIX monitors IPv4 traffic flows only
- **Ingress only**: Only ingress sampling is supported
- **Mac-in-Mac**: Traversing flows (L2 only) are not captured
- **L3 VSN**: Flows on NNI ports are not learned

## SNMP Enrichment

Enable SNMP enrichment to map `ifIndex` values to interface metadata:

- **ifName** via IF-MIB `1.3.6.1.2.1.31.1.1.1.1`
- **ifDescr** fallback via IF-MIB `1.3.6.1.2.1.2.2.1.2`
- **ifAlias** via IF-MIB `1.3.6.1.2.1.31.1.1.1.18`
- **ifSpeed** via `ifHighSpeed` (Mbps) with fallback to `ifSpeed` (bps)

The collector injects interface metadata into the flow payload as:

- `in_ifName`, `in_ifAlias`, `in_ifSpeed`
- `out_ifName`, `out_ifAlias`, `out_ifSpeed`

SNMP enrichment is optional and disabled by default. Exporters are discovered automatically as they send flows unless `--snmp-auto-discover=false` is set.

## L7 Classification

The collector performs lightweight classification using application telemetry (IPFIX) and port heuristics (L7). It never inspects payloads or enforces policy.

- App telemetry classification: enabled via `--ndpi-enabled` and controlled by `--ndpi-categories`
- Port heuristics: enabled via `--l7-enabled` and controlled by `--l7-categories`

Supported categories include voice, video, audio, control/management, and network services.

## Gotchas

- **Template churn**: Extreme templates change when telemetry features are enabled/disabled. Refresh caches after changes.
- **Observation domain & point**: Treat `(exporter IP, observationDomainId, observationPointId)` as a tuple.
- **CLEAR-FLOW fields**: CLEAR-FLOW metadata is exported as enterprise-specific fields; capture templates in `testdata/extreme/templates`.
- **Missing SNMP data**: If a switch returns empty interface metadata, enrichment is skipped without blocking flow export.

## Validation Checklist

### Connectivity
- Collector IP reachable from switch
- Correct VR/VRF specified
- UDP port not blocked by ACLs

### Template Reception (IPFIX)
- Templates received before data (check `/templates` endpoint)
- Template contains expected fields
- Refresh interval is reasonable

### Sampling Rate
- Sampling rate visible to collector (`/sampling` endpoint)
- sFlow: rate in datagram header
- IPFIX: rate in options template

### Observation Domain
- Observation domain ID is consistent
- Stack members identified via sub-agent ID (EXOS)
