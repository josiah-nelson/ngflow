// Package extreme provides templates and field mappings for Extreme Networks flow export.
//
// This file contains template definitions for:
//   - EXOS/Switch Engine sFlow (enterprise ID 1916)
//   - Fabric Engine IPFIX templates
//   - CLEAR-FLOW extended fields
//   - Application Telemetry fields

package extreme

import (
	"encoding/binary"
	"fmt"
)

// IPFIX/NetFlow v9 field IDs used by Extreme Networks devices
// Many of these are standard IANA fields, but Extreme uses them in specific ways
const (
	// Standard IPFIX fields commonly exported by Extreme
	FieldOctetDeltaCount        = 1
	FieldPacketDeltaCount       = 2
	FieldProtocolIdentifier     = 4
	FieldIPClassOfService       = 5
	FieldTCPControlBits         = 6
	FieldSourceTransportPort    = 7
	FieldSourceIPv4Address      = 8
	FieldSourceIPv4PrefixLength = 9
	FieldIngressInterface       = 10
	FieldDestTransportPort      = 11
	FieldDestIPv4Address        = 12
	FieldDestIPv4PrefixLength   = 13
	FieldEgressInterface        = 14
	FieldIPNextHopIPv4Address   = 15
	FieldBGPSourceAsNumber      = 16
	FieldBGPDestAsNumber        = 17
	FieldFlowStartSysUpTime     = 22
	FieldFlowEndSysUpTime       = 21
	FieldSourceIPv6Address      = 27
	FieldDestIPv6Address        = 28
	FieldSourceIPv6PrefixLength = 29
	FieldDestIPv6PrefixLength   = 30
	FieldIPv6FlowLabel          = 31
	FieldIcmpTypeCodeIPv4       = 32
	FieldSourceMacAddress       = 56
	FieldDestMacAddress         = 80
	FieldVlanId                 = 58
	FieldIPVersion              = 60
	FieldFlowDirection          = 61
	FieldFlowSamplerID          = 48
	FieldSamplingInterval       = 34
	FieldSamplingAlgorithm      = 35
	FieldObservationDomainId    = 149
	FieldObservationPointId     = 138
	FieldFlowId                 = 148
	FieldFlowStartMilliseconds  = 152
	FieldFlowEndMilliseconds    = 153

	// Extreme Networks enterprise-specific IPFIX fields (Enterprise ID 1916)
	// These are used with enterprise bit set (field ID | 0x8000)
	ExtremeFieldClearFlowRuleID    = 1  // CLEAR-FLOW rule that matched this flow
	ExtremeFieldClearFlowRuleName  = 2  // CLEAR-FLOW rule name
	ExtremeFieldAppTelemetryClass  = 3  // Application telemetry classification
	ExtremeFieldQoSPriority        = 4  // QoS priority/DSCP marking
	ExtremeFieldDropReason         = 5  // Drop reason code
	ExtremeFieldInputQueueDepth    = 6  // Input queue depth at sample time
	ExtremeFieldOutputQueueDepth   = 7  // Output queue depth at sample time
	ExtremeFieldSwitchingPath      = 8  // Hardware/software switching indicator
	ExtremeFieldSlotNumber         = 9  // Slot number (stacked/chassis)
	ExtremeFieldPortSpeed          = 10 // Port speed in Mbps
)

// sFlow Enterprise-specific Data (Enterprise ID 1916)
// Extreme Networks sFlow extended data structures
const (
	// sFlow enterprise data format numbers for Extreme Networks
	SFlowExtremeSwitchData      = 1 // Extended switch statistics
	SFlowExtremeClearFlowData   = 2 // CLEAR-FLOW match information
	SFlowExtremeAppTelemetry    = 3 // Application telemetry data
	SFlowExtremeQueueStats      = 4 // Queue statistics
	SFlowExtremePortStats       = 5 // Extended port statistics
)

// ExtremeIPFIXTemplate represents an IPFIX template from Extreme devices
type ExtremeIPFIXTemplate struct {
	TemplateID      uint16
	FieldCount      uint16
	Fields          []TemplateField
	ObservationDom  uint32
	IsOptionsTpl    bool
	DeviceType      DeviceType
}

// TemplateField represents a single field in a template
type TemplateField struct {
	FieldID       uint16
	FieldLength   uint16
	EnterpriseNum uint32 // 0 for IANA fields, 1916 for Extreme
	IsEnterprise  bool
	Name          string
}

// StandardFabricEngineIPFIXTemplate returns the standard IPFIX template
// exported by Fabric Engine devices (5520 running FE 9.3.x)
func StandardFabricEngineIPFIXTemplate() *ExtremeIPFIXTemplate {
	return &ExtremeIPFIXTemplate{
		TemplateID:     256,
		FieldCount:     23,
		DeviceType:     DeviceTypeFabricEngine,
		IsOptionsTpl:   false,
		ObservationDom: 0, // Set per-device
		Fields: []TemplateField{
			{FieldID: FieldSourceIPv4Address, FieldLength: 4, Name: "sourceIPv4Address"},
			{FieldID: FieldDestIPv4Address, FieldLength: 4, Name: "destinationIPv4Address"},
			{FieldID: FieldIPNextHopIPv4Address, FieldLength: 4, Name: "ipNextHopIPv4Address"},
			{FieldID: FieldIngressInterface, FieldLength: 4, Name: "ingressInterface"},
			{FieldID: FieldEgressInterface, FieldLength: 4, Name: "egressInterface"},
			{FieldID: FieldPacketDeltaCount, FieldLength: 8, Name: "packetDeltaCount"},
			{FieldID: FieldOctetDeltaCount, FieldLength: 8, Name: "octetDeltaCount"},
			{FieldID: FieldFlowStartMilliseconds, FieldLength: 8, Name: "flowStartMilliseconds"},
			{FieldID: FieldFlowEndMilliseconds, FieldLength: 8, Name: "flowEndMilliseconds"},
			{FieldID: FieldSourceTransportPort, FieldLength: 2, Name: "sourceTransportPort"},
			{FieldID: FieldDestTransportPort, FieldLength: 2, Name: "destinationTransportPort"},
			{FieldID: FieldTCPControlBits, FieldLength: 1, Name: "tcpControlBits"},
			{FieldID: FieldProtocolIdentifier, FieldLength: 1, Name: "protocolIdentifier"},
			{FieldID: FieldIPClassOfService, FieldLength: 1, Name: "ipClassOfService"},
			{FieldID: FieldBGPSourceAsNumber, FieldLength: 4, Name: "bgpSourceAsNumber"},
			{FieldID: FieldBGPDestAsNumber, FieldLength: 4, Name: "bgpDestinationAsNumber"},
			{FieldID: FieldSourceIPv4PrefixLength, FieldLength: 1, Name: "sourceIPv4PrefixLength"},
			{FieldID: FieldDestIPv4PrefixLength, FieldLength: 1, Name: "destinationIPv4PrefixLength"},
			{FieldID: FieldFlowDirection, FieldLength: 1, Name: "flowDirection"},
			{FieldID: FieldSourceMacAddress, FieldLength: 6, Name: "sourceMacAddress"},
			{FieldID: FieldDestMacAddress, FieldLength: 6, Name: "destinationMacAddress"},
			{FieldID: FieldVlanId, FieldLength: 2, Name: "vlanId"},
			{FieldID: FieldSamplingInterval, FieldLength: 4, Name: "samplingInterval"},
		},
	}
}

// StandardFabricEngineIPv6Template returns the IPv6 IPFIX template
// exported by Fabric Engine devices
func StandardFabricEngineIPv6Template() *ExtremeIPFIXTemplate {
	return &ExtremeIPFIXTemplate{
		TemplateID:     257,
		FieldCount:     21,
		DeviceType:     DeviceTypeFabricEngine,
		IsOptionsTpl:   false,
		ObservationDom: 0,
		Fields: []TemplateField{
			{FieldID: FieldSourceIPv6Address, FieldLength: 16, Name: "sourceIPv6Address"},
			{FieldID: FieldDestIPv6Address, FieldLength: 16, Name: "destinationIPv6Address"},
			{FieldID: FieldIngressInterface, FieldLength: 4, Name: "ingressInterface"},
			{FieldID: FieldEgressInterface, FieldLength: 4, Name: "egressInterface"},
			{FieldID: FieldPacketDeltaCount, FieldLength: 8, Name: "packetDeltaCount"},
			{FieldID: FieldOctetDeltaCount, FieldLength: 8, Name: "octetDeltaCount"},
			{FieldID: FieldFlowStartMilliseconds, FieldLength: 8, Name: "flowStartMilliseconds"},
			{FieldID: FieldFlowEndMilliseconds, FieldLength: 8, Name: "flowEndMilliseconds"},
			{FieldID: FieldSourceTransportPort, FieldLength: 2, Name: "sourceTransportPort"},
			{FieldID: FieldDestTransportPort, FieldLength: 2, Name: "destinationTransportPort"},
			{FieldID: FieldTCPControlBits, FieldLength: 1, Name: "tcpControlBits"},
			{FieldID: FieldProtocolIdentifier, FieldLength: 1, Name: "protocolIdentifier"},
			{FieldID: FieldIPClassOfService, FieldLength: 1, Name: "ipClassOfService"},
			{FieldID: FieldIPv6FlowLabel, FieldLength: 4, Name: "ipv6FlowLabel"},
			{FieldID: FieldSourceIPv6PrefixLength, FieldLength: 1, Name: "sourceIPv6PrefixLength"},
			{FieldID: FieldDestIPv6PrefixLength, FieldLength: 1, Name: "destinationIPv6PrefixLength"},
			{FieldID: FieldFlowDirection, FieldLength: 1, Name: "flowDirection"},
			{FieldID: FieldSourceMacAddress, FieldLength: 6, Name: "sourceMacAddress"},
			{FieldID: FieldDestMacAddress, FieldLength: 6, Name: "destinationMacAddress"},
			{FieldID: FieldVlanId, FieldLength: 2, Name: "vlanId"},
			{FieldID: FieldSamplingInterval, FieldLength: 4, Name: "samplingInterval"},
		},
	}
}

// FabricEngineOptionsTemplate returns the options template for sampling info
func FabricEngineOptionsTemplate() *ExtremeIPFIXTemplate {
	return &ExtremeIPFIXTemplate{
		TemplateID:     258,
		FieldCount:     4,
		DeviceType:     DeviceTypeFabricEngine,
		IsOptionsTpl:   true,
		ObservationDom: 0,
		Fields: []TemplateField{
			{FieldID: FieldObservationDomainId, FieldLength: 4, Name: "observationDomainId"},
			{FieldID: FieldFlowSamplerID, FieldLength: 4, Name: "flowSamplerID"},
			{FieldID: FieldSamplingInterval, FieldLength: 4, Name: "samplingInterval"},
			{FieldID: FieldSamplingAlgorithm, FieldLength: 1, Name: "samplingAlgorithm"},
		},
	}
}

// ExtremeSFlowExtendedData represents enterprise-specific sFlow data
type ExtremeSFlowExtendedData struct {
	Enterprise uint32
	Format     uint32
	Length     uint32
	Data       interface{}
}

// ClearFlowExtendedData represents CLEAR-FLOW information in sFlow
type ClearFlowExtendedData struct {
	RuleID       uint32
	RuleName     string
	MatchCounter uint64
	Action       uint8 // 0=permit, 1=deny, 2=mirror, 3=redirect
}

// AppTelemetryExtendedData represents Application Telemetry info
type AppTelemetryExtendedData struct {
	AppClass     uint16
	AppSubClass  uint16
	ResponseTime uint32 // microseconds
	BytesSent    uint64
	BytesRecv    uint64
}

// ParseExtremeSFlowData parses Extreme-specific sFlow enterprise data
func ParseExtremeSFlowData(enterprise uint32, format uint32, data []byte) (*ExtremeSFlowExtendedData, error) {
	if enterprise != ExtremeEnterpriseID {
		return nil, fmt.Errorf("not an Extreme enterprise record: %d", enterprise)
	}

	ext := &ExtremeSFlowExtendedData{
		Enterprise: enterprise,
		Format:     format,
		Length:     uint32(len(data)),
	}

	switch format {
	case SFlowExtremeClearFlowData:
		if len(data) < 12 {
			return nil, fmt.Errorf("CLEAR-FLOW data too short: %d bytes", len(data))
		}
		cf := &ClearFlowExtendedData{
			RuleID:       binary.BigEndian.Uint32(data[0:4]),
			MatchCounter: binary.BigEndian.Uint64(data[4:12]),
		}
		if len(data) > 12 {
			cf.Action = data[12]
		}
		// Rule name is variable length after fixed fields
		if len(data) > 16 {
			nameLen := binary.BigEndian.Uint32(data[13:17])
			if len(data) >= int(17+nameLen) {
				cf.RuleName = string(data[17 : 17+nameLen])
			}
		}
		ext.Data = cf

	case SFlowExtremeAppTelemetry:
		if len(data) < 20 {
			return nil, fmt.Errorf("App Telemetry data too short: %d bytes", len(data))
		}
		at := &AppTelemetryExtendedData{
			AppClass:     binary.BigEndian.Uint16(data[0:2]),
			AppSubClass:  binary.BigEndian.Uint16(data[2:4]),
			ResponseTime: binary.BigEndian.Uint32(data[4:8]),
			BytesSent:    binary.BigEndian.Uint64(data[8:16]),
			BytesRecv:    binary.BigEndian.Uint64(data[12:20]),
		}
		ext.Data = at

	default:
		// Unknown format, store raw data
		ext.Data = data
	}

	return ext, nil
}

// ObservationDomainSemantics documents how Extreme uses observation domains
type ObservationDomainSemantics struct {
	// Fabric Engine: Observation domain typically maps to VRF ID or
	// a configured domain ID via 'ip ipfix observation-domain <id>'
	// Default is 0

	// Switch Engine/EXOS: In sFlow, the sub-agent ID serves a similar
	// purpose, typically set to 0 unless stacking is used, where it
	// represents the stack member number

	// CLEAR-FLOW: Rules can be configured with specific observation
	// points for granular traffic classification

	DeviceType DeviceType
	DomainID   uint32
	DomainType DomainType
	VRFName    string
	StackSlot  uint8
}

// DomainType indicates what the observation domain represents
type DomainType uint8

const (
	DomainTypeDefault DomainType = iota
	DomainTypeVRF
	DomainTypeStackMember
	DomainTypeClearFlowRule
	DomainTypeVLAN
)

// InterpretObservationDomain interprets the observation domain based on device type
func InterpretObservationDomain(deviceType DeviceType, domainID uint32) *ObservationDomainSemantics {
	sem := &ObservationDomainSemantics{
		DeviceType: deviceType,
		DomainID:   domainID,
	}

	switch deviceType {
	case DeviceTypeFabricEngine, DeviceType5520:
		// Fabric Engine uses observation domain for VRF mapping
		if domainID == 0 {
			sem.DomainType = DomainTypeDefault
			sem.VRFName = "GlobalRouter"
		} else {
			sem.DomainType = DomainTypeVRF
			// VRF name would need SNMP lookup
		}

	case DeviceTypeSwitchEngine, DeviceTypeEXOS, DeviceTypeX435, DeviceType5120:
		// EXOS/Switch Engine uses sub-agent ID for stacking
		if domainID == 0 {
			sem.DomainType = DomainTypeDefault
		} else {
			sem.DomainType = DomainTypeStackMember
			sem.StackSlot = uint8(domainID)
		}
	}

	return sem
}
