// Package extreme provides configuration examples for Extreme Networks devices.
//
// IMPORTANT: All configuration examples in this file are derived from official
// Extreme Networks documentation. Command syntax and default values are taken
// directly from vendor guides.
//
// Documentation Sources:
//   - Fabric Engine User Guide v9.3
//   - Switch Engine User Guide v33.5.1
//   - ExtremeXOS User Guide v32.7.1
//   - https://documentation.extremenetworks.com/

package extreme

import (
	"fmt"
)

// PlatformConfig describes flow export configuration for a specific platform.
type PlatformConfig struct {
	Platform    string
	OSVersion   string
	Protocol    string
	DocSource   string
	CLICommands []CLICommand
	Notes       []string
}

// CLICommand represents a CLI command with its description and parameters.
type CLICommand struct {
	Command     string
	Description string
	Parameters  string // Parameter syntax/range from docs
	Default     string // Default value from docs
}

// FabricEngineIPFIXConfig returns IPFIX configuration for Fabric Engine.
//
// Source: Fabric Engine User Guide, IPFIX Configuration section
// Tested with: Fabric Engine 9.3.x on 5520 series
func FabricEngineIPFIXConfig(collectorIP string, collectorPort int) PlatformConfig {
	return PlatformConfig{
		Platform:  "5520 Fabric Engine",
		OSVersion: "9.3.x",
		Protocol:  "IPFIX",
		DocSource: "https://documentation.extremenetworks.com/FABRICENGINE/SW/810/FabricEngineUserGuide/GUID-844D127A-E959-4177-BD0B-BA73ED623F65.shtml",
		CLICommands: []CLICommand{
			{
				Command:     "ip ipfix enable",
				Description: "Enable IPFIX globally",
				Parameters:  "none",
				Default:     "disabled",
			},
			{
				Command:     fmt.Sprintf("ip ipfix collector 1 %s exporter-ip <switch-ip> dest-port %d", collectorIP, collectorPort),
				Description: "Configure IPFIX collector",
				Parameters:  "collector-id: 1-2, dest-port: 1-65535, src-port: 1-65535 (optional)",
				Default:     "no collector configured",
			},
			{
				Command:     "ip ipfix slot 1 aging-interval 30",
				Description: "Set flow aging interval",
				Parameters:  "0-2147400 seconds",
				Default:     "30 seconds",
			},
			{
				Command:     "ip ipfix export-interval 60 template-refresh-interval 300",
				Description: "Set export and template refresh intervals",
				Parameters:  "export: 10-3600s, template-refresh: seconds",
				Default:     "template refresh: 1800 seconds (30 min)",
			},
			{
				Command:     "ip ipfix ports 1/1-1/48 enable",
				Description: "Enable IPFIX on interfaces",
				Parameters:  "port list",
				Default:     "disabled on all ports",
			},
		},
		Notes: []string{
			"IPFIX monitors IPv4 traffic flows only (IPv6 not supported)",
			"Only ingress sampling is supported; egress sampling is not available",
			"Maximum 2 collectors supported; data is not load balanced",
			"Template refresh also occurs every 10,000 packets",
			"Mac-in-Mac traversing flows (L2 only) are not captured",
		},
	}
}

// SwitchEngineSFlowConfig returns sFlow configuration for Switch Engine/EXOS.
//
// Source: ExtremeXOS User Guide, sFlow Configuration section
// https://documentation.extremenetworks.com/exos_32.7.1/GUID-C22DF001-16D7-4B6D-8044-DB4ECAAEDC85.shtml
func SwitchEngineSFlowConfig(collectorIP string, collectorPort int) PlatformConfig {
	return PlatformConfig{
		Platform:  "Switch Engine / EXOS",
		OSVersion: "33.5.x / 32.x",
		Protocol:  "sFlow v5",
		DocSource: "https://documentation.extremenetworks.com/exos_32.7.1/GUID-C22DF001-16D7-4B6D-8044-DB4ECAAEDC85.shtml",
		CLICommands: []CLICommand{
			{
				Command:     "enable sflow",
				Description: "Enable sFlow globally",
				Parameters:  "none",
				Default:     "disabled",
			},
			{
				Command:     "configure sflow agent ipaddress <switch-ip>",
				Description: "Set sFlow agent IP address",
				Parameters:  "IP address",
				Default:     "none (must be configured)",
			},
			{
				Command:     fmt.Sprintf("configure sflow collector %s port %d", collectorIP, collectorPort),
				Description: "Configure sFlow collector",
				Parameters:  "IP address, UDP port",
				Default:     "port 6343",
			},
			{
				Command:     "configure sflow sample-rate 4096",
				Description: "Set global sampling rate (1:N)",
				Parameters:  "sampling rate denominator",
				Default:     "4096",
			},
			{
				Command:     "configure sflow poll-interval 20",
				Description: "Set counter polling interval",
				Parameters:  "0-300 seconds (0 disables)",
				Default:     "20 seconds",
			},
			{
				Command:     "enable sflow ports all",
				Description: "Enable sFlow on ports",
				Parameters:  "port list or 'all'",
				Default:     "disabled on all ports",
			},
		},
		Notes: []string{
			"sFlow v5 implementation per RFC 3176",
			"Polling distributes load over interval (not all ports at once)",
			"Per-port sample rate can override global: configure sflow ports <port> sample-rate <rate>",
			"Disabling global sFlow puts all ports in disabled state",
		},
	}
}

// X435SFlowConfig returns sFlow configuration optimized for X435 edge switches.
//
// Source: X435 runs ExtremeXOS with Value Edge license
// https://www.extremenetworks.com/products/switches/extremexos-switches/x435
func X435SFlowConfig(collectorIP string, collectorPort int) PlatformConfig {
	config := SwitchEngineSFlowConfig(collectorIP, collectorPort)
	config.Platform = "X435 (Edge Switch)"
	config.Notes = append(config.Notes,
		"X435 runs ExtremeXOS with Value Edge license",
		"Verify sFlow feature availability for your license level",
		"Consider higher sample rates (e.g., 8192) on resource-constrained edge switches",
	)
	return config
}

// ValidationChecklist provides a checklist for validating flow export configuration.
type ValidationChecklist struct {
	Category string
	Checks   []ValidationCheck
}

// ValidationCheck is a single validation item.
type ValidationCheck struct {
	Check       string
	HowToVerify string
	RiskIfFails string
}

// GetValidationChecklist returns the flow export validation checklist.
func GetValidationChecklist() []ValidationChecklist {
	return []ValidationChecklist{
		{
			Category: "Connectivity",
			Checks: []ValidationCheck{
				{
					Check:       "Collector IP is reachable from switch",
					HowToVerify: "ping <collector-ip> from switch CLI",
					RiskIfFails: "No flows will be exported",
				},
				{
					Check:       "Correct VR/VRF specified (EXOS)",
					HowToVerify: "show vr; verify collector reachable via specified VR",
					RiskIfFails: "Flows sent to wrong routing context, may be black-holed",
				},
				{
					Check:       "UDP port not blocked",
					HowToVerify: "Check ACLs on path; test with tcpdump on collector",
					RiskIfFails: "Flows dropped before reaching collector",
				},
			},
		},
		{
			Category: "Template Reception (IPFIX)",
			Checks: []ValidationCheck{
				{
					Check:       "Templates received before data",
					HowToVerify: "Check collector logs; /templates endpoint",
					RiskIfFails: "Data flows cannot be decoded until template arrives",
				},
				{
					Check:       "Template contains expected fields",
					HowToVerify: "Inspect template via /templates endpoint",
					RiskIfFails: "Missing fields (e.g., no bytes/packets) limits analysis",
				},
				{
					Check:       "Template refresh interval reasonable",
					HowToVerify: "show ip ipfix on switch; check collector template age",
					RiskIfFails: "After collector restart, long wait for template",
				},
			},
		},
		{
			Category: "Sampling Rate",
			Checks: []ValidationCheck{
				{
					Check:       "Sampling rate visible to collector",
					HowToVerify: "/sampling endpoint shows rate per exporter",
					RiskIfFails: "Upscaling incorrect; traffic stats wrong by factor of N",
				},
				{
					Check:       "sFlow: rate in datagram header",
					HowToVerify: "sFlow datagrams contain sampling rate per sample",
					RiskIfFails: "Collector uses default rate (may be wrong)",
				},
				{
					Check:       "IPFIX: rate in options template",
					HowToVerify: "Check for options template with sampling fields",
					RiskIfFails: "Collector cannot determine sampling; stats may be raw",
				},
			},
		},
		{
			Category: "Observation Domain/Point",
			Checks: []ValidationCheck{
				{
					Check:       "Observation domain ID consistent",
					HowToVerify: "show ip ipfix; check flows have expected domain",
					RiskIfFails: "Flows from different VRFs may be mixed",
				},
				{
					Check:       "Stack members identified (EXOS)",
					HowToVerify: "Sub-agent ID varies per stack member",
					RiskIfFails: "Cannot distinguish which stack member sampled flow",
				},
			},
		},
		{
			Category: "Exporter Identification",
			Checks: []ValidationCheck{
				{
					Check:       "Exporter IP in flow records",
					HowToVerify: "samplerAddress field populated in exported flows",
					RiskIfFails: "Cannot correlate flows to specific device",
				},
				{
					Check:       "SNMP sysDescr available (if using enrichment)",
					HowToVerify: "SNMP poll returns sysDescr OID",
					RiskIfFails: "Device type detection falls back to heuristics",
				},
			},
		},
	}
}

// GenerateConfigScript generates a complete configuration script for a platform.
func GenerateConfigScript(platform string, collectorIP string, collectorPort int, switchIP string) string {
	switch platform {
	case "fabric-engine":
		return fmt.Sprintf(`# Fabric Engine IPFIX Configuration
# Generated for collector: %s:%d
# Documentation: https://documentation.extremenetworks.com/FABRICENGINE/

enable
configure terminal

# Enable IPFIX globally
ip ipfix enable

# Configure collector
ip ipfix collector 1 %s exporter-ip %s dest-port %d

# Set intervals (adjust as needed)
ip ipfix slot 1 aging-interval 30
ip ipfix export-interval 60 template-refresh-interval 300

# Enable on all front-panel ports (adjust port range as needed)
ip ipfix ports 1/1-1/48 enable

# Verify configuration
show ip ipfix
show ip ipfix collector

exit
`, collectorIP, collectorPort, collectorIP, switchIP, collectorPort)

	case "switch-engine", "exos":
		return fmt.Sprintf(`# Switch Engine / EXOS sFlow Configuration
# Generated for collector: %s:%d
# Documentation: https://documentation.extremenetworks.com/exos_32.7.1/

# Enable sFlow globally
enable sflow

# Configure agent IP (use management or loopback IP)
configure sflow agent ipaddress %s

# Configure collector
configure sflow collector %s port %d

# Set sampling rate (1:4096 is default; adjust based on traffic volume)
configure sflow sample-rate 4096

# Set polling interval
configure sflow poll-interval 20

# Enable on all ports (or specify port list)
enable sflow ports all

# Verify configuration
show sflow
show sflow collector
`, collectorIP, collectorPort, switchIP, collectorIP, collectorPort)

	default:
		return "# Unknown platform. See vendor documentation."
	}
}
