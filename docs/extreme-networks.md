# Extreme Networks Support

This document covers vendor-specific support for Extreme Networks devices in netflow2ng.

> **Documentation Sources**: All configuration examples and default values in this document are derived from official Extreme Networks documentation. See references at the bottom.

## Supported Platforms

| Device | OS | Flow Protocol | Status |
|--------|-----|---------------|--------|
| X435 | ExtremeXOS 33.x (Value Edge license) | sFlow v5 | Supported |
| 5120 | Switch Engine 33.5.x | sFlow v5 | Supported |
| 5520 | Fabric Engine 9.3.x | IPFIX | Supported |
| 5520 | Switch Engine 33.5.x | sFlow v5 | Supported |

## Quick Start

### Switch Engine / EXOS (sFlow)

```bash
# On the switch
enable sflow
configure sflow agent ipaddress 10.0.0.1
configure sflow collector 192.168.1.100 port 6343
configure sflow sample-rate 4096
enable sflow ports all

# Start the collector
netflow2ng --sflow-listen 0.0.0.0:6343
```

### Fabric Engine (IPFIX)

```bash
# On the switch
enable
configure terminal
ip ipfix enable
ip ipfix collector 1 192.168.1.100 exporter-ip 10.0.0.1 dest-port 2055
ip ipfix ports 1/1-1/48 enable

# Start the collector
netflow2ng -a 0.0.0.0:2055
```

## Switch Engine / EXOS sFlow Configuration

### CLI Commands

| Command | Description | Default |
|---------|-------------|---------|
| `enable sflow` | Enable sFlow globally | disabled |
| `configure sflow agent ipaddress <ip>` | Set agent IP | none (required) |
| `configure sflow collector <ip> port <port>` | Configure collector | port 6343 |
| `configure sflow sample-rate <rate>` | Global sampling rate (1:N) | 4096 |
| `configure sflow poll-interval <seconds>` | Counter polling interval | 20 seconds |
| `enable sflow ports <port-list>` | Enable on ports | disabled |

### Documented Defaults

- **sFlow version**: 5 (per RFC 3176)
- **Polling interval**: 20 seconds (range: 0-300, 0 disables)
- **Sampling rate**: 1:4096
- **UDP port**: 6343

### Notes

- Counter polling is distributed over the interval (not all ports at once)
- Per-port sampling rate can override global: `configure sflow ports <port> sample-rate <rate>`
- Disabling global sFlow disables all ports

## Fabric Engine IPFIX Configuration

### CLI Commands

| Command | Description | Default |
|---------|-------------|---------|
| `ip ipfix enable` | Enable IPFIX globally | disabled |
| `ip ipfix collector <id> <ip> exporter-ip <ip> dest-port <port>` | Configure collector | none |
| `ip ipfix slot <slot> aging-interval <seconds>` | Flow aging timeout | 30 seconds |
| `ip ipfix export-interval <seconds>` | Export interval | varies |
| `ip ipfix template-refresh-interval <seconds>` | Template refresh | 1800 (30 min) |
| `ip ipfix ports <port-list> enable` | Enable on ports | disabled |

### Documented Defaults

- **Aging interval**: 30 seconds (range: 0-2,147,400)
- **Template refresh**: 1,800 seconds (also refreshes every 10,000 packets)
- **Max collectors**: 2 (data not load balanced between them)

### Limitations (per vendor documentation)

- **IPv4 only**: IPFIX monitors IPv4 traffic flows only
- **Ingress only**: Only ingress sampling is supported
- **Mac-in-Mac**: Traversing flows (L2 only) are not captured
- **L3 VSN**: Flows on NNI ports are not learned

## Validation Checklist

Use this checklist to verify flow export is working correctly.

### Connectivity
- [ ] Collector IP is reachable from switch (`ping <collector-ip>`)
- [ ] Correct VR/VRF specified (EXOS: verify with `show vr`)
- [ ] UDP port not blocked by ACLs

### Template Reception (IPFIX)
- [ ] Templates received before data (check `/templates` endpoint)
- [ ] Template contains expected fields (source/dest IP, protocol, bytes)
- [ ] Template refresh interval is reasonable (<= 300s recommended)

### Sampling Rate
- [ ] Sampling rate visible to collector (`/sampling` endpoint)
- [ ] sFlow: Rate in datagram header (automatic)
- [ ] IPFIX: Rate in options template (may need configuration)

### Observation Domain
- [ ] Observation domain ID is consistent
- [ ] Stack members identified via sub-agent ID (EXOS)

### Exporter Identification
- [ ] Exporter IP appears in flow records (samplerAddress)
- [ ] SNMP sysDescr available (for device type detection)

## Troubleshooting

### No flows received

1. Verify connectivity: `ping <collector-ip>` from switch
2. Check VR (EXOS): Ensure collector is reachable via specified VR
3. Verify UDP port not blocked
4. Check enable status: `show sflow` or `show ip ipfix`

### IPFIX template not decoded

1. Wait for template (default: up to 30 minutes)
2. Reduce template refresh: `ip ipfix template-refresh-interval 300`
3. Check `/templates` endpoint on collector

### Sampling rate incorrect

1. sFlow: Rate is in datagram header (automatic)
2. IPFIX: Check options template export is enabled
3. Use manual override if needed: `--default-sample-rate <rate>`

## IANA Information Element IDs

These are standard IETF-defined field IDs exported by Fabric Engine:

| ID | Name | Description |
|----|------|-------------|
| 1 | octetDeltaCount | Total bytes |
| 2 | packetDeltaCount | Total packets |
| 4 | protocolIdentifier | IP protocol |
| 7 | sourceTransportPort | L4 source port |
| 8 | sourceIPv4Address | IPv4 source |
| 10 | ingressInterface | Input ifIndex |
| 11 | destinationTransportPort | L4 dest port |
| 12 | destinationIPv4Address | IPv4 dest |
| 14 | egressInterface | Output ifIndex |
| 152 | flowStartMilliseconds | Flow start (ms since epoch) |
| 153 | flowEndMilliseconds | Flow end (ms since epoch) |

Full list: https://www.iana.org/assignments/ipfix/ipfix.xhtml

## References

### Official Documentation

- [Fabric Engine User Guide - IPFIX](https://documentation.extremenetworks.com/FABRICENGINE/SW/810/FabricEngineUserGuide/GUID-844D127A-E959-4177-BD0B-BA73ED623F65.shtml)
- [ExtremeXOS User Guide - sFlow](https://documentation.extremenetworks.com/exos_32.7.1/GUID-C22DF001-16D7-4B6D-8044-DB4ECAAEDC85.shtml)
- [X435 Product Page](https://www.extremenetworks.com/products/switches/extremexos-switches/x435)
- [IANA IPFIX Registry](https://www.iana.org/assignments/ipfix/ipfix.xhtml)

### Extreme Enterprise ID

- **IANA Private Enterprise Number**: 1916
- **Registry**: https://www.iana.org/assignments/enterprise-numbers/
