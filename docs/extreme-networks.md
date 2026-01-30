# Extreme Networks Support

This document covers vendor-specific support for Extreme Networks devices in netflow2ng.

## Supported Devices

| Device/Platform | OS Version | Flow Protocol | Status |
|-----------------|------------|---------------|--------|
| X435 | EXOS 33.5+ / Switch Engine | sFlow v5 | Fully Supported |
| 5120 | Switch Engine 33.5.x | sFlow v5 | Fully Supported |
| 5520 | Fabric Engine 9.3.x | IPFIX | Fully Supported |
| 5520 | Switch Engine 33.5.x | sFlow v5 | Fully Supported |
| Legacy EXOS | EXOS 15.4+ | sFlow v5 | Supported |

## Quick Start

### Switch Engine / EXOS (sFlow)

```bash
# Enable sFlow on your Extreme switch
enable sflow
configure sflow agent ipaddress 10.0.0.1
configure sflow collector 192.168.1.100 port 6343 vr "VR-Default"
configure sflow sample-rate 1024
enable sflow ports all both

# Start the collector
netflow2ng --sflow-listen 0.0.0.0:6343 \
  --snmp-enabled --snmp-community public \
  --l7-enabled
```

### Fabric Engine (IPFIX)

```bash
# Enable IPFIX on your 5520 Fabric Engine switch
enable
configure terminal
ip ipfix enable
ip ipfix collector 1 192.168.1.100 exporter-ip 10.0.0.1 dest-port 2055
ip ipfix template-refresh-time 300
ip ipfix ports 1/1-1/48 ingress-and-egress

# Start the collector
netflow2ng -a 0.0.0.0:2055 \
  --snmp-enabled --snmp-community public \
  --l7-enabled
```

## Features

### SNMP Interface Enrichment

When SNMP polling is enabled, flows are enriched with:

- **ifName**: Interface name (e.g., "1:1", "1/1/1")
- **ifAlias**: User-configured interface description
- **ifSpeed**: Interface speed in Mbps
- **sysName**: Device hostname

Configuration:
```bash
netflow2ng --snmp-enabled \
  --snmp-community "your-community" \
  --snmp-poll-interval 5m \
  --snmp-auto-discover
```

### L7 Application Classification

Limited L7 classification focused on specific traffic categories:

| Category | Protocols |
|----------|-----------|
| Voice | SIP, RTP, RTCP |
| Video | RTP (video streams) |
| Audio | RTP (audio streams) |
| Control | SSH, Telnet, SNMP |
| Network Services | DNS, DHCP, NTP |

Enable with:
```bash
netflow2ng --l7-enabled
```

### CLEAR-FLOW Integration

CLEAR-FLOW ACL-based sampling is supported for selective traffic monitoring:

1. Configure CLEAR-FLOW rules on your EXOS switch
2. Enable sFlow mirroring in CLEAR-FLOW actions
3. The collector parses enterprise-specific sFlow records (Enterprise ID 1916)

Example CLEAR-FLOW policy:
```
entry voip_traffic {
    if match all {
        protocol udp;
        destination-port 5060;
    } then {
        count voip_counter;
        mirror-destination 1;
    }
}
```

## Configuration Examples

### Basic sFlow (Switch Engine)

```
enable sflow
configure sflow agent ipaddress 10.0.0.1
configure sflow collector 192.168.1.100 port 6343 vr "VR-Default"
configure sflow sample-rate 1024
configure sflow poll-interval 30
enable sflow ports all both
```

### Basic IPFIX (Fabric Engine)

```
enable
configure terminal
ip ipfix enable
ip ipfix collector 1 192.168.1.100 exporter-ip 10.0.0.1 dest-port 2055
ip ipfix observation-domain 1
ip ipfix template-refresh-time 300
ip ipfix options-template-refresh-time 300
ip ipfix ports 1/1-1/48 ingress-and-egress
```

### Optimized for X435 (Edge Switch)

```
enable sflow
configure sflow agent ipaddress 10.0.0.100
configure sflow collector 192.168.1.100 port 6343 vr "VR-Mgmt"
configure sflow sample-rate 2048
configure sflow poll-interval 60
enable sflow backoff-threshold
configure sflow backoff-threshold 200
enable sflow ports 1:49,1:50 both
```

## Known Issues and Gotchas

### sFlow (EXOS / Switch Engine)

| Issue | Severity | Description | Workaround |
|-------|----------|-------------|------------|
| EXOS-SFLOW-001 | High | EXOS < 15.4 only supports egress sFlow | Upgrade to 15.4+ |
| EXOS-SFLOW-002 | Medium | Sampling rate is per-port, not per-interface | Use per-port configuration |
| EXOS-SFLOW-003 | Medium | Backoff throttles sampling under load | Adjust backoff-threshold |
| EXOS-SFLOW-005 | Medium | Interface numbers may differ from SNMP ifIndex | Enable SNMP enrichment |

### IPFIX (Fabric Engine)

| Issue | Severity | Description | Workaround |
|-------|----------|-------------|------------|
| FE-IPFIX-001 | High | IPFIX must be explicitly enabled globally | Run `ip ipfix enable` |
| FE-IPFIX-002 | Medium | Templates sent infrequently (30 min default) | Set template-refresh-time 300 |
| FE-IPFIX-003 | Medium | Sampling rate in options templates only | Track options templates |
| FE-IPFIX-005 | Medium | LAG reports member port, not LAG ifIndex | Use SNMP for LAG mapping |

### General

| Issue | Severity | Description | Workaround |
|-------|----------|-------------|------------|
| COMPAT-001 | Info | 5520 can run Switch Engine or Fabric Engine | Check OS with `show system` |
| COMPAT-002 | Medium | VR affects flow export reachability | Specify correct VR in config |
| COMPAT-003 | Low | X435 has limited resources | Use conservative sampling |

## Observation Domain Semantics

### Fabric Engine
- Default domain (0): GlobalRouter VRF
- Non-zero: Maps to VRF ID (configured via `ip ipfix observation-domain`)

### Switch Engine / EXOS
- Default (0): Single switch or stack primary
- Non-zero: Stack member number (sub-agent ID)

## Template Reference

### Fabric Engine IPFIX IPv4 Template (ID 256)

| Field | ID | Length | Description |
|-------|----|--------|-------------|
| sourceIPv4Address | 8 | 4 | Source IP |
| destinationIPv4Address | 12 | 4 | Destination IP |
| ipNextHopIPv4Address | 15 | 4 | Next hop |
| ingressInterface | 10 | 4 | Input ifIndex |
| egressInterface | 14 | 4 | Output ifIndex |
| packetDeltaCount | 2 | 8 | Packet count |
| octetDeltaCount | 1 | 8 | Byte count |
| flowStartMilliseconds | 152 | 8 | Flow start time |
| flowEndMilliseconds | 153 | 8 | Flow end time |
| sourceTransportPort | 7 | 2 | Source port |
| destinationTransportPort | 11 | 2 | Destination port |
| tcpControlBits | 6 | 1 | TCP flags |
| protocolIdentifier | 4 | 1 | IP protocol |
| ipClassOfService | 5 | 1 | ToS/DSCP |
| samplingInterval | 34 | 4 | Sampling rate |

### Enterprise-Specific sFlow Records (Enterprise ID 1916)

| Format | ID | Description |
|--------|----|-------------|
| ExtremeSwitchData | 1 | Extended switch statistics |
| ExtremeClearFlowData | 2 | CLEAR-FLOW match information |
| ExtremeAppTelemetry | 3 | Application telemetry data |
| ExtremeQueueStats | 4 | Queue statistics |
| ExtremePortStats | 5 | Extended port statistics |

## Troubleshooting

### No flows received

1. Verify connectivity: `ping <collector-ip>` from switch
2. Check VR: Ensure collector is reachable via configured VR
3. Verify ports: Check UDP port is open (default: 6343 sFlow, 2055 IPFIX)
4. Check status: `show sflow` or `show ip ipfix`

### Missing interface names

1. Enable SNMP on the switch
2. Configure community string to match collector
3. Enable SNMP enrichment: `--snmp-enabled --snmp-community <community>`
4. Wait for initial poll (up to 5 minutes)

### Sampling rate not detected

1. For sFlow: Rate is in datagram header (automatic)
2. For IPFIX: Check options template export is enabled
3. Use manual override if needed: `--sampling-rate 1024`

### Template decode errors (IPFIX)

1. Reduce template refresh interval on switch
2. Collector caches templates; wait for next template
3. Check logs for template ID mismatches

## References

- [ExtremeXOS User Guide - sFlow](https://documentation.extremenetworks.com/exos_33.1/GUID-B01E96DB-4365-42AA-8E3F-29DB1E1A38F4.shtml)
- [Fabric Engine User Guide - IPFIX](https://documentation.extremenetworks.com/FABRICENGINE/SW/810/FabricEngineUserGuide/GUID-844D127A-E959-4177-BD0B-BA73ED623F65.shtml)
- [5520 Hardware Installation Guide](https://documentation.extremenetworks.com/wired/5520/GUID-4E57A54C-1A9B-4876-94D7-65685F97E7E9.shtml)
