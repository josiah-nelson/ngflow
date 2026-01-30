// Package extreme - config_examples.go provides example configurations
// for Extreme Networks devices exporting flows to this collector.
//
// These configurations have been tested with:
//   - Switch Engine 33.5.2 (EXOS X435, 5120)
//   - Fabric Engine 9.3.1.0 (5520)

package extreme

import (
	"strconv"
)

func intToStr(n int) string {
	return strconv.Itoa(n)
}

// ExporterConfig holds example configuration for an Extreme device
type ExporterConfig struct {
	DeviceType  DeviceType
	Protocol    FlowProtocol
	Description string
	Config      string
	Notes       []string
}

// SwitchEngineSFlowBasic returns basic sFlow configuration for Switch Engine
func SwitchEngineSFlowBasic(collectorIP string, collectorPort int) ExporterConfig {
	return ExporterConfig{
		DeviceType:  DeviceTypeSwitchEngine,
		Protocol:    FlowProtocolSFlow,
		Description: "Basic sFlow configuration for Switch Engine / EXOS",
		Config: `# ==============================================================================
# Switch Engine / EXOS sFlow Configuration
# Tested on: EXOS 33.5.2 (Switch Engine)
# ==============================================================================

# 1. Enable sFlow globally
enable sflow

# 2. Configure the sFlow agent IP (typically a loopback or management IP)
# This is the source IP that appears in sFlow datagrams
configure sflow agent ipaddress 10.0.0.1

# 3. Configure the sFlow collector (this collector)
configure sflow collector ` + collectorIP + ` port ` + intToStr(collectorPort) + ` vr "VR-Default"

# 4. Configure sampling rate (1:1024 = sample 1 in every 1024 packets)
# Lower values = more samples = more accurate but more CPU/bandwidth
# Recommended: 512-2048 for typical deployments
configure sflow sample-rate 1024

# 5. Configure counter polling interval (seconds)
# This sends interface counters, useful for baseline traffic measurement
configure sflow poll-interval 30

# 6. Enable sFlow on all ports (or specify port list)
# "both" enables ingress AND egress sampling (EXOS 15.4+)
enable sflow ports all both

# 7. (Optional) Configure backoff threshold to prevent CPU overload
enable sflow backoff-threshold
configure sflow backoff-threshold 1000

# ==============================================================================
# Verification Commands
# ==============================================================================
# show sflow                    - Show sFlow configuration and statistics
# show sflow statistics         - Show sample/export counters
# show sflow configuration      - Show detailed configuration
`,
		Notes: []string{
			"Replace VR-Default with VR-Mgmt if collector is on management network",
			"Adjust sample-rate based on traffic volume (higher traffic = higher rate number)",
			"For stacked switches, sub-agent ID will automatically vary per stack member",
			"Ensure UDP port " + intToStr(collectorPort) + " is not blocked by ACLs",
		},
	}
}

// SwitchEngineSFlowWithClearFlow returns sFlow config with CLEAR-FLOW ACL sampling
func SwitchEngineSFlowWithClearFlow(collectorIP string, collectorPort int) ExporterConfig {
	return ExporterConfig{
		DeviceType:  DeviceTypeSwitchEngine,
		Protocol:    FlowProtocolSFlow,
		Description: "sFlow with CLEAR-FLOW ACL-based selective sampling",
		Config: `# ==============================================================================
# Switch Engine sFlow + CLEAR-FLOW Configuration
# Provides selective traffic sampling based on ACL rules
# ==============================================================================

# Basic sFlow configuration (same as basic)
enable sflow
configure sflow agent ipaddress 10.0.0.1
configure sflow collector ` + collectorIP + ` port ` + intToStr(collectorPort) + ` vr "VR-Default"
configure sflow sample-rate 2048
configure sflow poll-interval 30
enable sflow ports all both

# ==============================================================================
# CLEAR-FLOW Configuration for selective traffic monitoring
# ==============================================================================

# Create a policy file for CLEAR-FLOW rules
# Edit /config/clearflow_policy.pol with your rules

# Example policy file content (clearflow_policy.pol):
# ------------------------------------------------------------------------------
# # Monitor DNS traffic more aggressively
# entry dns_traffic {
#     if match all {
#         protocol udp;
#         destination-port 53;
#     } then {
#         count dns_counter;
#         mirror-destination 1;  # Mirror to sFlow
#     }
# }
#
# # Monitor HTTP/HTTPS traffic
# entry web_traffic {
#     if match all {
#         protocol tcp;
#         destination-port 80 443;
#     } then {
#         count web_counter;
#     }
# }
#
# # CLEAR-FLOW rule to alert on high DNS traffic
# clear-flow dns_alert {
#     if delta dns_counter 1 > 10000 then {
#         syslog "High DNS traffic detected" severity warning;
#     }
# }
# ------------------------------------------------------------------------------

# Apply the CLEAR-FLOW policy
configure access-list clearflow_policy ports all ingress

# Enable CLEAR-FLOW monitoring
enable clear-flow polling-interval 10

# ==============================================================================
# Verification Commands
# ==============================================================================
# show access-list counter          - Show ACL counters
# show clear-flow rules             - Show CLEAR-FLOW rules and status
# show clear-flow statistics        - Show CLEAR-FLOW triggered events
`,
		Notes: []string{
			"CLEAR-FLOW is ingress-only",
			"Policy file must be in /config/ directory",
			"CLEAR-FLOW adds CPU overhead; use sparingly on edge switches",
			"Mirror destination 1 sends samples to sFlow collector",
		},
	}
}

// FabricEngineIPFIXBasic returns basic IPFIX configuration for Fabric Engine
func FabricEngineIPFIXBasic(collectorIP string, collectorPort int) ExporterConfig {
	return ExporterConfig{
		DeviceType:  DeviceTypeFabricEngine,
		Protocol:    FlowProtocolIPFIX,
		Description: "Basic IPFIX configuration for Fabric Engine",
		Config: `# ==============================================================================
# Fabric Engine IPFIX Configuration
# Tested on: Fabric Engine 9.3.1.0 (5520)
# ==============================================================================

# Enter global configuration mode
enable
configure terminal

# 1. Enable IPFIX globally
ip ipfix enable

# 2. Configure IPFIX collector
# collector-id can be 1-4 (up to 4 collectors supported)
ip ipfix collector 1 ` + collectorIP + ` exporter-ip 10.0.0.1 dest-port ` + intToStr(collectorPort) + ` src-port 4739

# 3. (Optional) Configure observation domain
# Default is 0, set if using VRF-aware collection
ip ipfix observation-domain 1

# 4. Configure template refresh interval (seconds)
# Lower = faster template recovery after collector restart
ip ipfix template-refresh-time 300

# 5. Configure options template refresh (for sampling info)
ip ipfix options-template-refresh-time 300

# 6. Enable IPFIX on interfaces
# Replace 1/1-1/48 with your actual interface range
ip ipfix ports 1/1-1/48 ingress-and-egress

# 7. (Optional) Configure sampling if using sampled IPFIX
# Note: Fabric Engine IPFIX is typically unsampled
# ip ipfix sampling 1024

# ==============================================================================
# Verification Commands
# ==============================================================================
# show ip ipfix                     - Show IPFIX status
# show ip ipfix collector           - Show collector configuration
# show ip ipfix statistics          - Show export statistics
# show ip ipfix template            - Show active templates

exit
`,
		Notes: []string{
			"IPFIX on Fabric Engine is flow-based (not sampled by default)",
			"exporter-ip should be a reachable IP on the switch",
			"Use VRF context if collector is on a non-default VRF",
			"Template refresh should be <=300s for reliable operation",
			"Up to 4 collectors can be configured simultaneously",
		},
	}
}

// FabricEngineIPFIXWithVRF returns IPFIX config with VRF awareness
func FabricEngineIPFIXWithVRF(collectorIP string, collectorPort int, vrfName string) ExporterConfig {
	return ExporterConfig{
		DeviceType:  DeviceTypeFabricEngine,
		Protocol:    FlowProtocolIPFIX,
		Description: "IPFIX with VRF-aware configuration for Fabric Engine",
		Config: `# ==============================================================================
# Fabric Engine IPFIX Configuration with VRF
# Use this when collector is on a specific VRF
# ==============================================================================

enable
configure terminal

# Enable IPFIX globally
ip ipfix enable

# Configure within VRF context
router vrf ` + vrfName + `
ip ipfix collector 1 ` + collectorIP + ` exporter-ip 10.0.0.1 dest-port ` + intToStr(collectorPort) + `
exit

# Set observation domain to distinguish VRF traffic
# Use unique domain ID per VRF for multi-VRF environments
ip ipfix observation-domain 100

# Configure template intervals
ip ipfix template-refresh-time 300
ip ipfix options-template-refresh-time 300

# Enable on interfaces (within VRF)
ip ipfix ports 1/1-1/24 ingress-and-egress

# ==============================================================================
# VRF-specific considerations:
# ==============================================================================
# - Each VRF can have independent IPFIX collectors
# - Observation domain helps identify traffic source VRF
# - Ensure routing to collector exists within the VRF

exit
`,
		Notes: []string{
			"Replace VRF name with your actual VRF",
			"Observation domain helps correlate flows to VRF",
			"Ensure IP connectivity to collector within VRF",
		},
	}
}

// X435SFlowEdge returns optimized sFlow config for X435 edge switches
func X435SFlowEdge(collectorIP string, collectorPort int) ExporterConfig {
	return ExporterConfig{
		DeviceType:  DeviceTypeX435,
		Protocol:    FlowProtocolSFlow,
		Description: "Optimized sFlow for X435 edge/access switches",
		Config: `# ==============================================================================
# X435 Edge Switch sFlow Configuration
# Optimized for limited CPU/memory resources
# ==============================================================================

# Enable sFlow with conservative settings
enable sflow

# Configure agent (use management IP typically)
configure sflow agent ipaddress 10.0.0.100

# Configure collector
configure sflow collector ` + collectorIP + ` port ` + intToStr(collectorPort) + ` vr "VR-Mgmt"

# Use conservative sampling rate (higher number = fewer samples)
# X435 recommended: 1024-4096
configure sflow sample-rate 2048

# Longer poll interval to reduce CPU load
configure sflow poll-interval 60

# Enable backoff to prevent CPU exhaustion
enable sflow backoff-threshold
configure sflow backoff-threshold 200

# Enable only on necessary ports (not all)
# Example: uplink ports only
enable sflow ports 1:49,1:50 both

# Or for access ports with lower rate:
configure sflow ports 1:1-1:48 sample-rate 4096
enable sflow ports 1:1-1:48 ingress

# ==============================================================================
# X435 Resource Considerations:
# ==============================================================================
# - CPU: Limited, use sample-rate >= 1024
# - Memory: Limited, avoid complex CLEAR-FLOW rules
# - Uptime: Edge switches may reboot more frequently
# - Use ingress-only sampling if egress is not needed
`,
		Notes: []string{
			"X435 has limited resources - monitor CPU after enabling sFlow",
			"VR-Mgmt is typical for out-of-band management networks",
			"Consider sampling only uplinks for aggregate visibility",
			"Ingress-only sampling uses fewer resources",
		},
	}
}

// ApplicationTelemetryConfig returns config for Application Telemetry integration
func ApplicationTelemetryConfig(collectorIP string, sflowPort int, erspanDest string) ExporterConfig {
	return ExporterConfig{
		DeviceType:  DeviceTypeSwitchEngine,
		Protocol:    FlowProtocolSFlow,
		Description: "Application Telemetry configuration for deep packet inspection",
		Config: `# ==============================================================================
# Application Telemetry Configuration
# Combines sFlow + ERSPAN for detailed application visibility
# Requires Extreme Analytics Engine for full functionality
# ==============================================================================

# Standard sFlow configuration
enable sflow
configure sflow agent ipaddress 10.0.0.1
configure sflow collector ` + collectorIP + ` port ` + intToStr(sflowPort) + ` vr "VR-Default"
configure sflow sample-rate 1024
enable sflow ports all both

# ==============================================================================
# ERSPAN Configuration for DPI traffic
# Mirror specific traffic types for deep inspection
# ==============================================================================

# Create ERSPAN destination (to Analytics Engine)
configure mirror to remote-ip ` + erspanDest + ` vr "VR-Default" add mirror1

# Create mirror filter for specific traffic
# Example: Mirror TCP SYN packets for connection tracking
create access-list tcp_syn "protocol tcp ; tcp-flags syn" permit

# Apply mirror to uplink ports
configure mirror add mirror1 port 1:49 ingress filter tcp_syn

# ==============================================================================
# Application Telemetry Policy (telemetry.pol)
# This file is typically managed by ExtremeCloud IQ Site Engine
# ==============================================================================
# Manual policy example:
#
# entry http_telemetry {
#     if match all {
#         protocol tcp;
#         destination-port 80 443 8080;
#     } then {
#         mirror mirror1;
#         permit;
#     }
# }
#
# entry dns_telemetry {
#     if match all {
#         protocol udp;
#         destination-port 53;
#     } then {
#         mirror mirror1;
#         permit;
#     }
# }
# ==============================================================================

# Apply telemetry policy
configure access-list telemetry ports all ingress

`,
		Notes: []string{
			"Application Telemetry requires ExtremeCloud IQ for full features",
			"ERSPAN destination should be Analytics Engine or this collector",
			"DPI processing happens at the collector, not the switch",
			"TCP SYN mirroring enables response time calculation",
			"This collector supports limited L7 classification via nDPI",
		},
	}
}

// GetAllExporterConfigs returns all example configurations
func GetAllExporterConfigs(collectorIP string, collectorPort int) []ExporterConfig {
	return []ExporterConfig{
		SwitchEngineSFlowBasic(collectorIP, collectorPort),
		SwitchEngineSFlowWithClearFlow(collectorIP, collectorPort),
		FabricEngineIPFIXBasic(collectorIP, collectorPort),
		FabricEngineIPFIXWithVRF(collectorIP, collectorPort, "CustomerVRF"),
		X435SFlowEdge(collectorIP, collectorPort),
	}
}
