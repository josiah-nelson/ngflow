// Package extreme provides vendor-specific support for Extreme Networks devices
// including EXOS X435, 5120 Switch Engine (EXOS 33.5), and 5520 Fabric Engine (9.3.1.0).
//
// Supported protocols:
//   - sFlow v5 (primary on EXOS/Switch Engine)
//   - IPFIX (primary on Fabric Engine)
//   - NetFlow v9 (legacy support)
//
// Proprietary features:
//   - CLEAR-FLOW ACL-based sampling
//   - Application Telemetry integration
//   - Observation point/domain semantics
package extreme

import (
	"net"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

var log *logrus.Logger

func SetLogger(l *logrus.Logger) {
	log = l
}

// ExtremeEnterpriseID is Extreme Networks' IANA Private Enterprise Number
// Used in sFlow enterprise-specific records and IPFIX enterprise fields
const ExtremeEnterpriseID = 1916

// ExtremeVendor represents a detected Extreme Networks device
type ExtremeVendor struct {
	// Device identification
	IPAddress    net.IP
	DeviceType   DeviceType
	OSVersion    string
	Model        string
	SerialNumber string

	// Flow export configuration
	FlowProtocol     FlowProtocol
	SamplingRate     uint32
	SamplingAlgo     SamplingAlgorithm
	ObservationPoint uint32

	// CLEAR-FLOW configuration (if enabled)
	ClearFlowEnabled bool
	ClearFlowRules   []ClearFlowRule

	// Application Telemetry (if enabled)
	AppTelemetryEnabled bool
	TelemetryPolicy     string

	// Tracking
	LastSeen    time.Time
	FirstSeen   time.Time
	FlowCount   uint64
	ErrorCount  uint64
}

// DeviceType represents the type of Extreme Networks device
type DeviceType uint8

const (
	DeviceTypeUnknown DeviceType = iota
	DeviceTypeEXOS               // Legacy EXOS
	DeviceTypeSwitchEngine       // EXOS 33.x (Switch Engine)
	DeviceTypeFabricEngine       // Fabric Engine 9.x
	DeviceTypeX435               // Edge switch
	DeviceType5120               // 5120 series
	DeviceType5520               // 5520 series
)

func (d DeviceType) String() string {
	switch d {
	case DeviceTypeEXOS:
		return "EXOS"
	case DeviceTypeSwitchEngine:
		return "Switch Engine"
	case DeviceTypeFabricEngine:
		return "Fabric Engine"
	case DeviceTypeX435:
		return "X435"
	case DeviceType5120:
		return "5120"
	case DeviceType5520:
		return "5520"
	default:
		return "Unknown"
	}
}

// FlowProtocol represents the flow export protocol
type FlowProtocol uint8

const (
	FlowProtocolUnknown FlowProtocol = iota
	FlowProtocolSFlow
	FlowProtocolIPFIX
	FlowProtocolNetFlowV9
)

func (p FlowProtocol) String() string {
	switch p {
	case FlowProtocolSFlow:
		return "sFlow"
	case FlowProtocolIPFIX:
		return "IPFIX"
	case FlowProtocolNetFlowV9:
		return "NetFlow v9"
	default:
		return "Unknown"
	}
}

// SamplingAlgorithm represents the sampling method
type SamplingAlgorithm uint8

const (
	SamplingUnknown SamplingAlgorithm = iota
	SamplingSystematic                // Count-based 1:N (sFlow default)
	SamplingRandom                    // Random sampling
	SamplingClearFlow                 // ACL-based CLEAR-FLOW
	SamplingAppTelemetry              // Application Telemetry selective
)

// ClearFlowRule represents a CLEAR-FLOW ACL rule
type ClearFlowRule struct {
	Name        string
	RuleID      uint32
	Priority    uint16
	MatchBytes  uint64
	MatchPkts   uint64
	HitCount    uint64
	Enabled     bool
	Description string
}

// ExtremeVendorTracker tracks detected Extreme Networks devices
type ExtremeVendorTracker struct {
	devices map[string]*ExtremeVendor
	mu      sync.RWMutex
}

// NewExtremeVendorTracker creates a new vendor tracker
func NewExtremeVendorTracker() *ExtremeVendorTracker {
	return &ExtremeVendorTracker{
		devices: make(map[string]*ExtremeVendor),
	}
}

// RegisterDevice registers or updates an Extreme Networks device
func (t *ExtremeVendorTracker) RegisterDevice(ip net.IP, deviceType DeviceType, protocol FlowProtocol) *ExtremeVendor {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := ip.String()
	device, exists := t.devices[key]
	if !exists {
		device = &ExtremeVendor{
			IPAddress:    ip,
			DeviceType:   deviceType,
			FlowProtocol: protocol,
			FirstSeen:    time.Now(),
		}
		t.devices[key] = device
	}

	device.LastSeen = time.Now()
	device.FlowCount++

	return device
}

// GetDevice returns a device by IP address
func (t *ExtremeVendorTracker) GetDevice(ip net.IP) *ExtremeVendor {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if device, ok := t.devices[ip.String()]; ok {
		// Return a copy
		copy := *device
		return &copy
	}
	return nil
}

// GetAllDevices returns all tracked devices
func (t *ExtremeVendorTracker) GetAllDevices() map[string]ExtremeVendor {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make(map[string]ExtremeVendor, len(t.devices))
	for k, v := range t.devices {
		result[k] = *v
	}
	return result
}

// DetectDeviceType attempts to determine device type from flow characteristics
func DetectDeviceType(samplerIP net.IP, flowProtocol FlowProtocol, observationDomain uint32, sysDesc string) DeviceType {
	// Check sysDescr for device identification if available
	if sysDesc != "" {
		switch {
		case contains(sysDesc, "X435"):
			return DeviceTypeX435
		case contains(sysDesc, "5520") || contains(sysDesc, "Fabric Engine"):
			return DeviceType5520
		case contains(sysDesc, "5120"):
			return DeviceType5120
		case contains(sysDesc, "Switch Engine") || contains(sysDesc, "EXOS 3"):
			return DeviceTypeSwitchEngine
		case contains(sysDesc, "EXOS"):
			return DeviceTypeEXOS
		case contains(sysDesc, "Fabric"):
			return DeviceTypeFabricEngine
		}
	}

	// Infer from protocol preference
	switch flowProtocol {
	case FlowProtocolIPFIX:
		// Fabric Engine prefers IPFIX
		return DeviceTypeFabricEngine
	case FlowProtocolSFlow:
		// EXOS/Switch Engine prefers sFlow
		return DeviceTypeSwitchEngine
	}

	return DeviceTypeUnknown
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
