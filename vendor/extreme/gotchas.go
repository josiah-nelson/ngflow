// Package extreme - gotchas.go documents known issues, behavioral quirks,
// and important considerations when collecting flows from Extreme Networks devices.
//
// IMPORTANT: Read this file carefully before deploying in production.

package extreme

// Gotcha represents a known issue or behavioral quirk
type Gotcha struct {
	ID          string
	Category    GotchaCategory
	Severity    GotchaSeverity
	DeviceTypes []DeviceType
	Title       string
	Description string
	Workaround  string
	Reference   string
}

type GotchaCategory string

const (
	CategorySampling      GotchaCategory = "sampling"
	CategoryTemplates     GotchaCategory = "templates"
	CategoryTimestamps    GotchaCategory = "timestamps"
	CategoryInterfaces    GotchaCategory = "interfaces"
	CategoryVLAN          GotchaCategory = "vlan"
	CategoryIPFIX         GotchaCategory = "ipfix"
	CategorySFlow         GotchaCategory = "sflow"
	CategoryClearFlow     GotchaCategory = "clearflow"
	CategoryCompatibility GotchaCategory = "compatibility"
)

type GotchaSeverity string

const (
	SeverityCritical GotchaSeverity = "critical"
	SeverityHigh     GotchaSeverity = "high"
	SeverityMedium   GotchaSeverity = "medium"
	SeverityLow      GotchaSeverity = "low"
	SeverityInfo     GotchaSeverity = "info"
)

// KnownGotchas contains all documented issues for Extreme Networks devices
var KnownGotchas = []Gotcha{
	// ==========================================================================
	// SFLOW GOTCHAS (EXOS / Switch Engine)
	// ==========================================================================
	{
		ID:          "EXOS-SFLOW-001",
		Category:    CategorySFlow,
		Severity:    SeverityHigh,
		DeviceTypes: []DeviceType{DeviceTypeEXOS, DeviceTypeSwitchEngine, DeviceTypeX435, DeviceType5120},
		Title:       "EXOS versions before 15.4 only support egress sFlow",
		Description: `Prior to EXOS 15.4, sFlow sampling only works on egress traffic. This means
you will only see traffic leaving interfaces, not entering. This causes asymmetric flow data
and can lead to missing half of bidirectional flows.`,
		Workaround: `Upgrade to EXOS 15.4 or later. In Switch Engine 33.x, both ingress and
egress are fully supported. Use 'enable sflow ports <port-list> both' to enable bidirectional sampling.`,
		Reference: "https://documentation.extremenetworks.com/exos_32.7.1/GUID-C22DF001-16D7-4B6D-8044-DB4ECAAEDC85.shtml",
	},
	{
		ID:          "EXOS-SFLOW-002",
		Category:    CategorySampling,
		Severity:    SeverityMedium,
		DeviceTypes: []DeviceType{DeviceTypeEXOS, DeviceTypeSwitchEngine},
		Title:       "sFlow sampling rate is per-port, not per-interface",
		Description: `EXOS applies the sampling rate at the physical port level. If you have
multiple VLANs on a port, all VLANs share the same sampling rate. This can lead to
over-representation of high-traffic VLANs.`,
		Workaround: `Use per-port sample rate configuration with 'configure sflow ports <port>
sample-rate <rate>'. Consider different rates for different port classes (uplinks vs access).`,
		Reference: "https://documentation.extremenetworks.com/exos_33.1/GUID-B01E96DB-4365-42AA-8E3F-29DB1E1A38F4.shtml",
	},
	{
		ID:          "EXOS-SFLOW-003",
		Category:    CategorySampling,
		Severity:    SeverityMedium,
		DeviceTypes: []DeviceType{DeviceTypeEXOS, DeviceTypeSwitchEngine},
		Title:       "sFlow backoff-threshold can cause sample loss under load",
		Description: `EXOS has a backoff mechanism that throttles sFlow sampling when the
switch CPU is overloaded. The 'sflow backoff-threshold' setting controls when this kicks in.
Default is 500 samples/second. Under heavy traffic, you may lose samples without warning.`,
		Workaround: `Adjust the backoff threshold based on your switch's CPU capacity:
  configure sflow backoff-threshold <value>
  enable sflow backoff-threshold
Monitor 'show sflow' for drop counters.`,
		Reference: "",
	},
	{
		ID:          "EXOS-SFLOW-004",
		Category:    CategoryTimestamps,
		Severity:    SeverityLow,
		DeviceTypes: []DeviceType{DeviceTypeEXOS, DeviceTypeSwitchEngine},
		Title:       "sFlow timestamps are sysUptime-based, not wall clock",
		Description: `sFlow datagrams contain sysUptime in milliseconds since boot, not Unix
timestamps. After a reboot, the uptime resets to zero. This collector converts to wall clock
time at receipt, which may introduce slight timing skew.`,
		Workaround: `This is expected behavior. The collector normalizes timestamps at receive
time. For precise timing, ensure NTP is configured on both the switch and collector.`,
		Reference: "",
	},
	{
		ID:          "EXOS-SFLOW-005",
		Category:    CategoryInterfaces,
		Severity:    SeverityMedium,
		DeviceTypes: []DeviceType{DeviceTypeSwitchEngine},
		Title:       "Interface numbers in sFlow may not match SNMP ifIndex",
		Description: `In some configurations, the interface numbers reported in sFlow samples
(input/output interface) may differ from SNMP ifIndex values. This is particularly common with
LAG interfaces and virtual ports.`,
		Workaround: `Enable SNMP polling for interface metadata enrichment. The enrichment
module will attempt to map sFlow interface numbers to correct ifIndex values. Alternatively,
use 'show port ingress-port-map' to understand the mapping.`,
		Reference: "",
	},
	{
		ID:          "EXOS-SFLOW-006",
		Category:    CategoryVLAN,
		Severity:    SeverityLow,
		DeviceTypes: []DeviceType{DeviceTypeEXOS, DeviceTypeSwitchEngine},
		Title:       "VLAN information may be stripped from sampled packets",
		Description: `Depending on where in the switching pipeline the sample is taken, VLAN
tags may or may not be present in the sampled packet header. Extended switch data records
are more reliable for VLAN information.`,
		Workaround: `Prefer extended switch data (format 1001) over raw packet VLAN parsing
when available. The collector prioritizes extended switch data for VLAN fields.`,
		Reference: "",
	},

	// ==========================================================================
	// IPFIX GOTCHAS (Fabric Engine)
	// ==========================================================================
	{
		ID:          "FE-IPFIX-001",
		Category:    CategoryIPFIX,
		Severity:    SeverityHigh,
		DeviceTypes: []DeviceType{DeviceTypeFabricEngine, DeviceType5520},
		Title:       "IPFIX must be explicitly enabled globally",
		Description: `Unlike sFlow on EXOS, IPFIX on Fabric Engine is disabled by default and
must be explicitly enabled at both global and interface levels:
  ip ipfix enable
  ip ipfix collector <id> <ip> ...
  ip ipfix ports <ports> ingress-and-egress`,
		Workaround: `Run 'show ip ipfix' to verify configuration. Enable globally first,
then configure collector, then enable on interfaces.`,
		Reference: "https://documentation.extremenetworks.com/FABRICENGINE/SW/810/FabricEngineUserGuide/GUID-844D127A-E959-4177-BD0B-BA73ED623F65.shtml",
	},
	{
		ID:          "FE-IPFIX-002",
		Category:    CategoryTemplates,
		Severity:    SeverityMedium,
		DeviceTypes: []DeviceType{DeviceTypeFabricEngine, DeviceType5520},
		Title:       "Fabric Engine sends templates infrequently",
		Description: `Fabric Engine sends IPFIX templates at a configurable interval (default
is 30 minutes). If the collector restarts or loses templates, it cannot decode flows until
the next template is sent.`,
		Workaround: `Configure a shorter template refresh interval:
  ip ipfix template-refresh-time <seconds>
Recommended: 60-300 seconds for development, 300-600 for production.
The collector caches templates persistently where possible.`,
		Reference: "",
	},
	{
		ID:          "FE-IPFIX-003",
		Category:    CategorySampling,
		Severity:    SeverityMedium,
		DeviceTypes: []DeviceType{DeviceTypeFabricEngine, DeviceType5520},
		Title:       "IPFIX sampling rate not always in flow records",
		Description: `Fabric Engine may not include the sampling interval in every flow record.
Instead, it may be sent only in options templates. This requires tracking sampling info
from options templates separately.`,
		Workaround: `The collector tracks sampling rates from options templates per observation
domain. Ensure options template export is enabled:
  ip ipfix options-template-refresh-time <seconds>`,
		Reference: "",
	},
	{
		ID:          "FE-IPFIX-004",
		Category:    CategoryTimestamps,
		Severity:    SeverityLow,
		DeviceTypes: []DeviceType{DeviceTypeFabricEngine, DeviceType5520},
		Title:       "IPFIX timestamps are in milliseconds since epoch",
		Description: `Fabric Engine uses flowStartMilliseconds and flowEndMilliseconds fields
(IPFIX IDs 152, 153) which are milliseconds since Unix epoch. This differs from NetFlow v9
which uses system uptime offsets.`,
		Workaround: `The collector handles both formats automatically. Ensure NTP is properly
configured on the switch for accurate timestamps.`,
		Reference: "",
	},
	{
		ID:          "FE-IPFIX-005",
		Category:    CategoryInterfaces,
		Severity:    SeverityMedium,
		DeviceTypes: []DeviceType{DeviceTypeFabricEngine, DeviceType5520},
		Title:       "LAG interfaces report member port, not LAG ifIndex",
		Description: `When traffic traverses a LAG (SMLT/MLT), the interface ID in flow
records may be the physical member port rather than the LAG aggregate. This can make
traffic analysis confusing.`,
		Workaround: `Use SNMP enrichment to resolve physical ports to their LAG membership.
The enrichment module adds lag_ifindex and lag_name fields when available.`,
		Reference: "",
	},

	// ==========================================================================
	// CLEAR-FLOW GOTCHAS
	// ==========================================================================
	{
		ID:          "CF-001",
		Category:    CategoryClearFlow,
		Severity:    SeverityMedium,
		DeviceTypes: []DeviceType{DeviceTypeEXOS, DeviceTypeSwitchEngine},
		Title:       "CLEAR-FLOW is ingress-only",
		Description: `CLEAR-FLOW rules only apply to ingress traffic. Egress traffic cannot
be classified using CLEAR-FLOW ACLs. This limits visibility for certain traffic patterns.`,
		Workaround: `Design your topology to ensure interesting traffic enters ports where
CLEAR-FLOW rules are applied. Consider applying rules on uplink ports.`,
		Reference: "https://documentation.extremenetworks.com/exos_32.7.1/GUID-CB68E331-DEDB-418D-BE16-F540656FF1DC.shtml",
	},
	{
		ID:          "CF-002",
		Category:    CategoryClearFlow,
		Severity:    SeverityHigh,
		DeviceTypes: []DeviceType{DeviceTypeEXOS, DeviceTypeSwitchEngine},
		Title:       "CLEAR-FLOW counters may overflow without warning",
		Description: `CLEAR-FLOW ACL counters are 64-bit but the hardware counters may be
smaller on some platforms. Counters can overflow without explicit notification.`,
		Workaround: `Poll CLEAR-FLOW counters frequently (at least once per minute for high
traffic) and track deltas rather than absolute values.`,
		Reference: "",
	},

	// ==========================================================================
	// COMPATIBILITY GOTCHAS
	// ==========================================================================
	{
		ID:          "COMPAT-001",
		Category:    CategoryCompatibility,
		Severity:    SeverityInfo,
		DeviceTypes: []DeviceType{DeviceType5520},
		Title:       "5520 can run either Switch Engine or Fabric Engine",
		Description: `The 5520 series can run either EXOS-based Switch Engine or Fabric
Engine. The flow export capabilities differ significantly:
- Switch Engine: sFlow (primary), limited IPFIX
- Fabric Engine: IPFIX (primary), no sFlow
Check which OS is running before configuring flow export.`,
		Workaround: `Use 'show system' to determine the running OS. Configure the appropriate
flow export protocol for your OS.`,
		Reference: "https://documentation.extremenetworks.com/wired/5520/GUID-4E57A54C-1A9B-4876-94D7-65685F97E7E9.shtml",
	},
	{
		ID:          "COMPAT-002",
		Category:    CategoryCompatibility,
		Severity:    SeverityMedium,
		DeviceTypes: []DeviceType{DeviceTypeEXOS, DeviceTypeSwitchEngine, DeviceTypeFabricEngine},
		Title:       "Virtual Router (VR) affects flow export reachability",
		Description: `On EXOS/Switch Engine, flow export uses the specified VR for routing.
If the collector is not reachable via that VR, no flows will be exported. Common issue
when using VR-Mgmt for out-of-band management.`,
		Workaround: `Specify the correct VR in sFlow configuration:
  configure sflow collector <ip> port <port> vr <vr-name>
Common VRs: VR-Default (data plane), VR-Mgmt (management)`,
		Reference: "",
	},
	{
		ID:          "COMPAT-003",
		Category:    CategoryCompatibility,
		Severity:    SeverityLow,
		DeviceTypes: []DeviceType{DeviceTypeX435},
		Title:       "X435 has limited flow export resources",
		Description: `The X435 is an edge/access switch with limited CPU and memory.
Aggressive sampling rates can impact switch performance. Recommended minimum sampling
rate is 1:1024 for production use.`,
		Workaround: `Use conservative sampling rates on X435:
  configure sflow sample-rate 1024
  configure sflow poll-interval 30
Monitor CPU utilization when enabling sFlow.`,
		Reference: "",
	},
}

// GetGotchasForDevice returns gotchas relevant to a specific device type
func GetGotchasForDevice(deviceType DeviceType) []Gotcha {
	var result []Gotcha
	for _, g := range KnownGotchas {
		for _, dt := range g.DeviceTypes {
			if dt == deviceType {
				result = append(result, g)
				break
			}
		}
	}
	return result
}

// GetGotchasByCategory returns gotchas for a specific category
func GetGotchasByCategory(category GotchaCategory) []Gotcha {
	var result []Gotcha
	for _, g := range KnownGotchas {
		if g.Category == category {
			result = append(result, g)
		}
	}
	return result
}

// GetGotchasBySeverity returns gotchas at or above a severity level
func GetGotchasBySeverity(minSeverity GotchaSeverity) []Gotcha {
	severityOrder := map[GotchaSeverity]int{
		SeverityCritical: 5,
		SeverityHigh:     4,
		SeverityMedium:   3,
		SeverityLow:      2,
		SeverityInfo:     1,
	}

	minLevel := severityOrder[minSeverity]
	var result []Gotcha
	for _, g := range KnownGotchas {
		if severityOrder[g.Severity] >= minLevel {
			result = append(result, g)
		}
	}
	return result
}
