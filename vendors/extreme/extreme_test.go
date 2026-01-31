package extreme

import (
	"net"
	"strings"
	"testing"
)

func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}

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

// TestDefaultFabricEngineIPFIX tests documented defaults
func TestDefaultFabricEngineIPFIX(t *testing.T) {
	defaults := DefaultFabricEngineIPFIX()

	// Verify documented default values
	if defaults.AgingInterval != 30 {
		t.Errorf("Expected AgingInterval=30, got %d", defaults.AgingInterval)
	}

	if defaults.TemplateRefreshInterval != 1800 {
		t.Errorf("Expected TemplateRefreshInterval=1800, got %d", defaults.TemplateRefreshInterval)
	}

	if defaults.MaxCollectors != 2 {
		t.Errorf("Expected MaxCollectors=2, got %d", defaults.MaxCollectors)
	}
}

// TestDefaultSwitchEngineSFlow tests documented defaults
func TestDefaultSwitchEngineSFlow(t *testing.T) {
	defaults := DefaultSwitchEngineSFlow()

	// Verify documented default values
	if defaults.PollInterval != 20 {
		t.Errorf("Expected PollInterval=20, got %d", defaults.PollInterval)
	}

	if defaults.SamplingRate != 4096 {
		t.Errorf("Expected SamplingRate=4096, got %d", defaults.SamplingRate)
	}

	if defaults.DefaultUDPPort != 6343 {
		t.Errorf("Expected DefaultUDPPort=6343, got %d", defaults.DefaultUDPPort)
	}

	if defaults.SFlowVersion != 5 {
		t.Errorf("Expected SFlowVersion=5, got %d", defaults.SFlowVersion)
	}
}

// TestValidateIPFIXTemplate tests template validation
func TestValidateIPFIXTemplate(t *testing.T) {
	// Complete template
	completeFields := []uint16{
		IESourceIPv4Address,
		IEDestIPv4Address,
		IEProtocolIdentifier,
		IEOctetDeltaCount,
	}
	issues := ValidateIPFIXTemplate(256, completeFields)
	if len(issues) != 0 {
		t.Errorf("Expected no issues for complete template, got: %v", issues)
	}

	// Missing source address
	missingSource := []uint16{
		IEDestIPv4Address,
		IEProtocolIdentifier,
		IEOctetDeltaCount,
	}
	issues = ValidateIPFIXTemplate(256, missingSource)
	if len(issues) != 1 {
		t.Errorf("Expected 1 issue for missing source, got %d", len(issues))
	}

	// Empty template
	issues = ValidateIPFIXTemplate(256, []uint16{})
	if len(issues) != 4 {
		t.Errorf("Expected 4 issues for empty template, got %d", len(issues))
	}
}

// TestFabricEngineLimitations tests limitation documentation
func TestFabricEngineLimitations(t *testing.T) {
	limits := GetFabricEngineLimitations()

	if !limits.IPv4Only {
		t.Error("Expected IPv4Only=true")
	}

	if !limits.IngressOnly {
		t.Error("Expected IngressOnly=true")
	}
}

// TestInterpretObservationDomain tests observation domain interpretation
func TestInterpretObservationDomain(t *testing.T) {
	tests := []struct {
		name         string
		deviceType   DeviceType
		domainID     uint32
		wantContains string
	}{
		{
			name:         "FabricEngine default",
			deviceType:   DeviceTypeFabricEngine,
			domainID:     0,
			wantContains: "GlobalRouter",
		},
		{
			name:         "FabricEngine VRF",
			deviceType:   DeviceTypeFabricEngine,
			domainID:     100,
			wantContains: "VRF",
		},
		{
			name:         "SwitchEngine default",
			deviceType:   DeviceTypeSwitchEngine,
			domainID:     0,
			wantContains: "primary",
		},
		{
			name:         "SwitchEngine stack member",
			deviceType:   DeviceTypeSwitchEngine,
			domainID:     2,
			wantContains: "stack member",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := InterpretObservationDomain(tt.deviceType, tt.domainID)
			if !contains(info.Interpretation, tt.wantContains) {
				t.Errorf("Interpretation %q does not contain %q", info.Interpretation, tt.wantContains)
			}
		})
	}
}

// TestParseEnterpriseRecord tests enterprise record parsing
func TestParseEnterpriseRecord(t *testing.T) {
	// Non-Extreme enterprise
	record, err := ParseEnterpriseRecord(1234, 1, []byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if record.Enterprise != 1234 {
		t.Errorf("Expected enterprise=1234, got %d", record.Enterprise)
	}

	// Extreme enterprise
	record, err = ParseEnterpriseRecord(ExtremeEnterpriseID, 1, []byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if record.Enterprise != ExtremeEnterpriseID {
		t.Errorf("Expected enterprise=%d, got %d", ExtremeEnterpriseID, record.Enterprise)
	}
}

// TestGenerateConfigScript tests config script generation
func TestGenerateConfigScript(t *testing.T) {
	script := GenerateConfigScript("fabric-engine", "192.168.1.100", 2055, "10.0.0.1")
	if !contains(script, "ip ipfix enable") {
		t.Error("Fabric Engine script missing 'ip ipfix enable'")
	}
	if !contains(script, "192.168.1.100") {
		t.Error("Fabric Engine script missing collector IP")
	}

	script = GenerateConfigScript("switch-engine", "192.168.1.100", 6343, "10.0.0.1")
	if !contains(script, "enable sflow") {
		t.Error("Switch Engine script missing 'enable sflow'")
	}

	script = GenerateConfigScript("unknown", "192.168.1.100", 6343, "10.0.0.1")
	if !contains(script, "Unknown platform") {
		t.Error("Unknown platform should return error message")
	}
}

// TestGetValidationChecklist tests checklist retrieval
func TestGetValidationChecklist(t *testing.T) {
	checklist := GetValidationChecklist()

	if len(checklist) == 0 {
		t.Error("Expected non-empty checklist")
	}

	// Verify expected categories exist
	categories := make(map[string]bool)
	for _, cat := range checklist {
		categories[cat.Category] = true
	}

	expectedCategories := []string{"Connectivity", "Template Reception (IPFIX)", "Sampling Rate"}
	for _, expected := range expectedCategories {
		if !categories[expected] {
			t.Errorf("Missing expected category: %s", expected)
		}
	}
}

// TestFabricEngineIPFIXConfig tests config generation
func TestFabricEngineIPFIXConfig(t *testing.T) {
	config := FabricEngineIPFIXConfig("192.168.1.100", 2055)

	if config.Platform != "5520 Fabric Engine" {
		t.Errorf("Unexpected platform: %s", config.Platform)
	}

	if config.Protocol != "IPFIX" {
		t.Errorf("Unexpected protocol: %s", config.Protocol)
	}

	if len(config.CLICommands) == 0 {
		t.Error("Expected CLI commands")
	}

	// Verify first command is enable
	if config.CLICommands[0].Command != "ip ipfix enable" {
		t.Errorf("First command should be 'ip ipfix enable', got %s", config.CLICommands[0].Command)
	}
}

// TestSwitchEngineSFlowConfig tests sFlow config generation
func TestSwitchEngineSFlowConfig(t *testing.T) {
	config := SwitchEngineSFlowConfig("192.168.1.100", 6343)

	if config.Protocol != "sFlow v5" {
		t.Errorf("Unexpected protocol: %s", config.Protocol)
	}

	if len(config.CLICommands) == 0 {
		t.Error("Expected CLI commands")
	}

	// Check for documented default in commands
	foundSampleRate := false
	for _, cmd := range config.CLICommands {
		if contains(cmd.Command, "sample-rate") && cmd.Default == "4096" {
			foundSampleRate = true
			break
		}
	}
	if !foundSampleRate {
		t.Error("Expected sample-rate command with default 4096")
	}
}

// TestConcurrentAccess tests thread safety
func TestConcurrentAccess(t *testing.T) {
	tracker := NewExtremeVendorTracker()

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

	for i := 0; i < 100; i++ {
		<-done
	}
}
