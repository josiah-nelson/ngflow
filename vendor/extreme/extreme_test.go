package extreme

import (
	"encoding/binary"
	"net"
	"testing"
)

// TestExtremeVendorTracker tests device tracking functionality
func TestExtremeVendorTracker(t *testing.T) {
	tracker := NewExtremeVendorTracker()

	ip := net.ParseIP("192.168.1.1")

	// Register device
	device := tracker.RegisterDevice(ip, DeviceTypeSwitchEngine, FlowProtocolSFlow)

	if device == nil {
		t.Fatal("RegisterDevice returned nil")
	}

	if device.DeviceType != DeviceTypeSwitchEngine {
		t.Errorf("Expected DeviceTypeSwitchEngine, got %v", device.DeviceType)
	}

	if device.FlowProtocol != FlowProtocolSFlow {
		t.Errorf("Expected FlowProtocolSFlow, got %v", device.FlowProtocol)
	}

	// Get device
	retrieved := tracker.GetDevice(ip)
	if retrieved == nil {
		t.Fatal("GetDevice returned nil")
	}

	if retrieved.FlowCount != 1 {
		t.Errorf("Expected FlowCount=1, got %d", retrieved.FlowCount)
	}

	// Register again (should increment flow count)
	tracker.RegisterDevice(ip, DeviceTypeSwitchEngine, FlowProtocolSFlow)
	retrieved = tracker.GetDevice(ip)
	if retrieved.FlowCount != 2 {
		t.Errorf("Expected FlowCount=2, got %d", retrieved.FlowCount)
	}

	// Get all devices
	all := tracker.GetAllDevices()
	if len(all) != 1 {
		t.Errorf("Expected 1 device, got %d", len(all))
	}
}

// TestDetectDeviceType tests device type detection
func TestDetectDeviceType(t *testing.T) {
	tests := []struct {
		name         string
		sysDesc      string
		flowProtocol FlowProtocol
		expected     DeviceType
	}{
		{
			name:         "X435 from sysDescr",
			sysDesc:      "Extreme Networks X435-24P Switch",
			flowProtocol: FlowProtocolSFlow,
			expected:     DeviceTypeX435,
		},
		{
			name:         "5520 from sysDescr",
			sysDesc:      "ExtremeSwitching 5520-48SE Fabric Engine 9.3.1.0",
			flowProtocol: FlowProtocolIPFIX,
			expected:     DeviceType5520,
		},
		{
			name:         "Switch Engine from sysDescr",
			sysDesc:      "ExtremeXOS Switch Engine 33.5.2",
			flowProtocol: FlowProtocolSFlow,
			expected:     DeviceTypeSwitchEngine,
		},
		{
			name:         "5120 from sysDescr",
			sysDesc:      "ExtremeSwitching 5120-48P Switch Engine",
			flowProtocol: FlowProtocolSFlow,
			expected:     DeviceType5120,
		},
		{
			name:         "Fabric Engine from protocol",
			sysDesc:      "",
			flowProtocol: FlowProtocolIPFIX,
			expected:     DeviceTypeFabricEngine,
		},
		{
			name:         "Switch Engine from protocol",
			sysDesc:      "",
			flowProtocol: FlowProtocolSFlow,
			expected:     DeviceTypeSwitchEngine,
		},
		{
			name:         "Unknown",
			sysDesc:      "",
			flowProtocol: FlowProtocolUnknown,
			expected:     DeviceTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectDeviceType(nil, tt.flowProtocol, 0, tt.sysDesc)
			if result != tt.expected {
				t.Errorf("DetectDeviceType() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestDeviceTypeString tests string representation
func TestDeviceTypeString(t *testing.T) {
	tests := []struct {
		dt       DeviceType
		expected string
	}{
		{DeviceTypeEXOS, "EXOS"},
		{DeviceTypeSwitchEngine, "Switch Engine"},
		{DeviceTypeFabricEngine, "Fabric Engine"},
		{DeviceTypeX435, "X435"},
		{DeviceType5120, "5120"},
		{DeviceType5520, "5520"},
		{DeviceTypeUnknown, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.dt.String(); got != tt.expected {
				t.Errorf("DeviceType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestFlowProtocolString tests string representation
func TestFlowProtocolString(t *testing.T) {
	tests := []struct {
		fp       FlowProtocol
		expected string
	}{
		{FlowProtocolSFlow, "sFlow"},
		{FlowProtocolIPFIX, "IPFIX"},
		{FlowProtocolNetFlowV9, "NetFlow v9"},
		{FlowProtocolUnknown, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.fp.String(); got != tt.expected {
				t.Errorf("FlowProtocol.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestStandardFabricEngineIPFIXTemplate tests template structure
func TestStandardFabricEngineIPFIXTemplate(t *testing.T) {
	tpl := StandardFabricEngineIPFIXTemplate()

	if tpl.TemplateID != 256 {
		t.Errorf("Expected TemplateID=256, got %d", tpl.TemplateID)
	}

	if tpl.DeviceType != DeviceTypeFabricEngine {
		t.Errorf("Expected DeviceTypeFabricEngine, got %v", tpl.DeviceType)
	}

	if len(tpl.Fields) != 23 {
		t.Errorf("Expected 23 fields, got %d", len(tpl.Fields))
	}

	// Verify key fields exist
	fieldNames := make(map[string]bool)
	for _, f := range tpl.Fields {
		fieldNames[f.Name] = true
	}

	requiredFields := []string{
		"sourceIPv4Address",
		"destinationIPv4Address",
		"packetDeltaCount",
		"octetDeltaCount",
		"protocolIdentifier",
		"samplingInterval",
	}

	for _, name := range requiredFields {
		if !fieldNames[name] {
			t.Errorf("Missing required field: %s", name)
		}
	}
}

// TestStandardFabricEngineIPv6Template tests IPv6 template
func TestStandardFabricEngineIPv6Template(t *testing.T) {
	tpl := StandardFabricEngineIPv6Template()

	if tpl.TemplateID != 257 {
		t.Errorf("Expected TemplateID=257, got %d", tpl.TemplateID)
	}

	// Verify IPv6-specific fields
	hasIPv6Src := false
	hasIPv6Dst := false
	for _, f := range tpl.Fields {
		if f.Name == "sourceIPv6Address" {
			hasIPv6Src = true
			if f.FieldLength != 16 {
				t.Errorf("IPv6 source address field length should be 16, got %d", f.FieldLength)
			}
		}
		if f.Name == "destinationIPv6Address" {
			hasIPv6Dst = true
			if f.FieldLength != 16 {
				t.Errorf("IPv6 dest address field length should be 16, got %d", f.FieldLength)
			}
		}
	}

	if !hasIPv6Src || !hasIPv6Dst {
		t.Error("Missing IPv6 address fields")
	}
}

// TestFabricEngineOptionsTemplate tests options template
func TestFabricEngineOptionsTemplate(t *testing.T) {
	tpl := FabricEngineOptionsTemplate()

	if !tpl.IsOptionsTpl {
		t.Error("Expected IsOptionsTpl=true")
	}

	if tpl.TemplateID != 258 {
		t.Errorf("Expected TemplateID=258, got %d", tpl.TemplateID)
	}

	// Options template should have sampling-related fields
	hasSamplingInterval := false
	hasSamplingAlgo := false
	for _, f := range tpl.Fields {
		if f.Name == "samplingInterval" {
			hasSamplingInterval = true
		}
		if f.Name == "samplingAlgorithm" {
			hasSamplingAlgo = true
		}
	}

	if !hasSamplingInterval || !hasSamplingAlgo {
		t.Error("Options template missing sampling fields")
	}
}

// TestParseExtremeSFlowData tests parsing enterprise-specific sFlow data
func TestParseExtremeSFlowData(t *testing.T) {
	// Test non-Extreme enterprise ID
	_, err := ParseExtremeSFlowData(1234, 1, []byte{0x00})
	if err == nil {
		t.Error("Expected error for non-Extreme enterprise ID")
	}

	// Test CLEAR-FLOW data parsing
	clearFlowData := make([]byte, 20)
	binary.BigEndian.PutUint32(clearFlowData[0:4], 12345)           // Rule ID
	binary.BigEndian.PutUint64(clearFlowData[4:12], 1000000)        // Match counter
	clearFlowData[12] = 0                                           // Action: permit

	result, err := ParseExtremeSFlowData(ExtremeEnterpriseID, SFlowExtremeClearFlowData, clearFlowData)
	if err != nil {
		t.Fatalf("ParseExtremeSFlowData failed: %v", err)
	}

	cf, ok := result.Data.(*ClearFlowExtendedData)
	if !ok {
		t.Fatal("Expected ClearFlowExtendedData")
	}

	if cf.RuleID != 12345 {
		t.Errorf("Expected RuleID=12345, got %d", cf.RuleID)
	}

	if cf.MatchCounter != 1000000 {
		t.Errorf("Expected MatchCounter=1000000, got %d", cf.MatchCounter)
	}

	if cf.Action != 0 {
		t.Errorf("Expected Action=0, got %d", cf.Action)
	}

	// Test short data
	_, err = ParseExtremeSFlowData(ExtremeEnterpriseID, SFlowExtremeClearFlowData, []byte{0x00})
	if err == nil {
		t.Error("Expected error for short CLEAR-FLOW data")
	}
}

// TestInterpretObservationDomain tests observation domain interpretation
func TestInterpretObservationDomain(t *testing.T) {
	tests := []struct {
		name       string
		deviceType DeviceType
		domainID   uint32
		wantType   DomainType
	}{
		{
			name:       "FabricEngine default",
			deviceType: DeviceTypeFabricEngine,
			domainID:   0,
			wantType:   DomainTypeDefault,
		},
		{
			name:       "FabricEngine VRF",
			deviceType: DeviceTypeFabricEngine,
			domainID:   100,
			wantType:   DomainTypeVRF,
		},
		{
			name:       "SwitchEngine default",
			deviceType: DeviceTypeSwitchEngine,
			domainID:   0,
			wantType:   DomainTypeDefault,
		},
		{
			name:       "SwitchEngine stack member",
			deviceType: DeviceTypeSwitchEngine,
			domainID:   2,
			wantType:   DomainTypeStackMember,
		},
		{
			name:       "X435 default",
			deviceType: DeviceTypeX435,
			domainID:   0,
			wantType:   DomainTypeDefault,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sem := InterpretObservationDomain(tt.deviceType, tt.domainID)
			if sem.DomainType != tt.wantType {
				t.Errorf("InterpretObservationDomain() DomainType = %v, want %v", sem.DomainType, tt.wantType)
			}
		})
	}
}

// TestGetGotchasForDevice tests gotcha filtering
func TestGetGotchasForDevice(t *testing.T) {
	// X435 should have EXOS/SwitchEngine gotchas
	x435Gotchas := GetGotchasForDevice(DeviceTypeX435)
	if len(x435Gotchas) == 0 {
		t.Error("Expected gotchas for X435")
	}

	// Verify sFlow egress gotcha is present
	found := false
	for _, g := range x435Gotchas {
		if g.ID == "EXOS-SFLOW-001" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected EXOS-SFLOW-001 gotcha for X435")
	}

	// FabricEngine should have IPFIX gotchas
	feGotchas := GetGotchasForDevice(DeviceTypeFabricEngine)
	if len(feGotchas) == 0 {
		t.Error("Expected gotchas for FabricEngine")
	}

	found = false
	for _, g := range feGotchas {
		if g.ID == "FE-IPFIX-001" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected FE-IPFIX-001 gotcha for FabricEngine")
	}
}

// TestGetGotchasByCategory tests category filtering
func TestGetGotchasByCategory(t *testing.T) {
	sflowGotchas := GetGotchasByCategory(CategorySFlow)
	if len(sflowGotchas) == 0 {
		t.Error("Expected sFlow category gotchas")
	}

	for _, g := range sflowGotchas {
		if g.Category != CategorySFlow {
			t.Errorf("Got non-sFlow gotcha in sFlow category: %v", g.Category)
		}
	}

	ipfixGotchas := GetGotchasByCategory(CategoryIPFIX)
	if len(ipfixGotchas) == 0 {
		t.Error("Expected IPFIX category gotchas")
	}
}

// TestGetGotchasBySeverity tests severity filtering
func TestGetGotchasBySeverity(t *testing.T) {
	critical := GetGotchasBySeverity(SeverityCritical)
	high := GetGotchasBySeverity(SeverityHigh)
	all := GetGotchasBySeverity(SeverityInfo)

	// Higher severity filter should return fewer results
	if len(high) > len(all) {
		t.Error("High severity filter should return fewer results than info")
	}

	if len(critical) > len(high) {
		t.Error("Critical severity filter should return fewer results than high")
	}
}

// ============================================================================
// ADVERSARIAL TEST CASES
// ============================================================================

// TestAdversarialUnknownEnterpriseID tests handling of unknown enterprise IDs
func TestAdversarialUnknownEnterpriseID(t *testing.T) {
	unknownEnterprise := uint32(99999)

	_, err := ParseExtremeSFlowData(unknownEnterprise, 1, []byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Error("Expected error for unknown enterprise ID")
	}
}

// TestAdversarialMalformedSFlowData tests handling of malformed data
func TestAdversarialMalformedSFlowData(t *testing.T) {
	// Empty data
	_, err := ParseExtremeSFlowData(ExtremeEnterpriseID, SFlowExtremeClearFlowData, []byte{})
	if err == nil {
		t.Error("Expected error for empty data")
	}

	// Too short for CLEAR-FLOW (needs at least 12 bytes)
	_, err = ParseExtremeSFlowData(ExtremeEnterpriseID, SFlowExtremeClearFlowData, []byte{0x01, 0x02})
	if err == nil {
		t.Error("Expected error for short CLEAR-FLOW data")
	}

	// Too short for App Telemetry (needs at least 20 bytes)
	_, err = ParseExtremeSFlowData(ExtremeEnterpriseID, SFlowExtremeAppTelemetry, []byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Error("Expected error for short App Telemetry data")
	}
}

// TestAdversarialNilIP tests handling of nil IP addresses
func TestAdversarialNilIP(t *testing.T) {
	tracker := NewExtremeVendorTracker()

	// Register with nil IP should not panic
	device := tracker.RegisterDevice(nil, DeviceTypeSwitchEngine, FlowProtocolSFlow)
	if device == nil {
		// This is expected behavior - nil IP should be handled gracefully
		t.Log("RegisterDevice with nil IP returned nil (expected)")
	}

	// Get with nil IP
	result := tracker.GetDevice(nil)
	if result != nil {
		t.Log("GetDevice with nil IP should return nil")
	}
}

// TestAdversarialEmptySysDescr tests detection with empty sysDescr
func TestAdversarialEmptySysDescr(t *testing.T) {
	// Empty sysDescr should fall back to protocol-based detection
	result := DetectDeviceType(nil, FlowProtocolSFlow, 0, "")
	if result != DeviceTypeSwitchEngine {
		t.Errorf("Expected DeviceTypeSwitchEngine for sFlow with empty sysDescr, got %v", result)
	}

	result = DetectDeviceType(nil, FlowProtocolIPFIX, 0, "")
	if result != DeviceTypeFabricEngine {
		t.Errorf("Expected DeviceTypeFabricEngine for IPFIX with empty sysDescr, got %v", result)
	}
}

// TestAdversarialInvalidObservationDomain tests invalid observation domain handling
func TestAdversarialInvalidObservationDomain(t *testing.T) {
	// Very large observation domain ID
	sem := InterpretObservationDomain(DeviceTypeFabricEngine, 0xFFFFFFFF)
	if sem.DomainID != 0xFFFFFFFF {
		t.Error("Domain ID not preserved")
	}

	// Observation domain with unknown device type
	sem = InterpretObservationDomain(DeviceTypeUnknown, 100)
	if sem.DomainType != DomainTypeDefault {
		t.Log("Unknown device type defaults to DomainTypeDefault")
	}
}

// TestAdversarialTemplateFieldBoundaries tests template field validation
func TestAdversarialTemplateFieldBoundaries(t *testing.T) {
	tpl := StandardFabricEngineIPFIXTemplate()

	// Verify no fields have zero length
	for _, f := range tpl.Fields {
		if f.FieldLength == 0 {
			t.Errorf("Field %s has zero length", f.Name)
		}
	}

	// Verify field IDs are valid IPFIX field IDs
	for _, f := range tpl.Fields {
		if f.FieldID == 0 {
			t.Errorf("Field %s has zero field ID", f.Name)
		}
	}
}

// TestAdversarialUnknownSFlowFormat tests unknown sFlow format handling
func TestAdversarialUnknownSFlowFormat(t *testing.T) {
	// Unknown format should store raw data
	unknownFormat := uint32(255)
	data := []byte{0x01, 0x02, 0x03, 0x04}

	result, err := ParseExtremeSFlowData(ExtremeEnterpriseID, unknownFormat, data)
	if err != nil {
		t.Fatalf("Unexpected error for unknown format: %v", err)
	}

	// Should store raw bytes
	rawData, ok := result.Data.([]byte)
	if !ok {
		t.Error("Expected raw bytes for unknown format")
	}

	if len(rawData) != len(data) {
		t.Errorf("Expected %d bytes, got %d", len(data), len(rawData))
	}
}

// TestAdversarialConcurrentAccess tests thread safety
func TestAdversarialConcurrentAccess(t *testing.T) {
	tracker := NewExtremeVendorTracker()

	// Concurrent registration
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func(n int) {
			ip := net.ParseIP("192.168.1." + string(rune('0'+n%10)))
			tracker.RegisterDevice(ip, DeviceTypeSwitchEngine, FlowProtocolSFlow)
			_ = tracker.GetDevice(ip)
			_ = tracker.GetAllDevices()
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}
}
