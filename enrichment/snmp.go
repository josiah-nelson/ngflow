// Package enrichment provides flow enrichment capabilities including
// SNMP-based interface metadata and optional L7 classification.
package enrichment

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/sirupsen/logrus"
)

var log *logrus.Logger

func SetLogger(l *logrus.Logger) {
	log = l
}

// SNMP OIDs for interface information
const (
	// IF-MIB standard OIDs
	OIDIfDescr       = "1.3.6.1.2.1.2.2.1.2"  // Interface description
	OIDIfType        = "1.3.6.1.2.1.2.2.1.3"  // Interface type
	OIDIfSpeed       = "1.3.6.1.2.1.2.2.1.5"  // Interface speed (bps, 32-bit)
	OIDIfPhysAddress = "1.3.6.1.2.1.2.2.1.6"  // MAC address
	OIDIfAdminStatus = "1.3.6.1.2.1.2.2.1.7"  // Admin status
	OIDIfOperStatus  = "1.3.6.1.2.1.2.2.1.8"  // Oper status
	OIDIfName        = "1.3.6.1.2.1.31.1.1.1.1"  // Interface name (IF-MIB ifXTable)
	OIDIfAlias       = "1.3.6.1.2.1.31.1.1.1.18" // Interface alias/description
	OIDIfHighSpeed   = "1.3.6.1.2.1.31.1.1.1.15" // High-speed counter (Mbps)

	// LAG/Port-Channel OIDs
	OIDLagPortListIndex = "1.2.840.10006.300.43.1.2.1.1.12" // IEEE8023-LAG-MIB

	// System info
	OIDSysDescr    = "1.3.6.1.2.1.1.1.0"
	OIDSysName     = "1.3.6.1.2.1.1.5.0"
	OIDSysUptime   = "1.3.6.1.2.1.1.3.0"
	OIDSysObjectID = "1.3.6.1.2.1.1.2.0"
)

// InterfaceInfo holds metadata for a single interface
type InterfaceInfo struct {
	IfIndex     uint32
	IfName      string // Short name (e.g., "1:1", "1/1")
	IfDescr     string // Description from ifDescr
	IfAlias     string // User-configured alias
	IfType      uint32 // IANA ifType
	IfSpeed     uint64 // Speed in bps
	IfHighSpeed uint64 // Speed in Mbps (for 10G+ interfaces)
	AdminStatus uint8  // 1=up, 2=down, 3=testing
	OperStatus  uint8  // 1=up, 2=down, etc.
	PhysAddress string // MAC address
	IsLagMember bool   // Is this a LAG member port?
	LagIfIndex  uint32 // Parent LAG ifIndex if member
	LastUpdated time.Time
}

// DeviceInfo holds system-level information for a device
type DeviceInfo struct {
	IPAddress   net.IP
	SysDescr    string
	SysName     string
	SysObjectID string
	SysUptime   uint64 // Hundredths of seconds
	Interfaces  map[uint32]*InterfaceInfo
	LastPolled  time.Time
	PollErrors  uint64
}

// SNMPEnricherConfig holds configuration for SNMP enrichment
type SNMPEnricherConfig struct {
	// SNMP connection settings
	Community    string        // SNMPv2c community string
	Version      gosnmp.SnmpVersion
	Timeout      time.Duration
	Retries      int

	// Polling settings
	PollInterval     time.Duration // How often to poll devices
	MaxParallelPolls int           // Max concurrent device polls

	// Device discovery
	AutoDiscover bool          // Auto-discover exporters as devices
	StaticDevices []string     // Static list of device IPs to poll

	// Feature toggles
	Enabled      bool
	PollOnDemand bool          // Poll when first flow is seen from device

	// Metrics
	Metrics *SNMPMetrics
}

// SNMPMetrics holds prometheus metrics for SNMP polling
type SNMPMetrics struct {
	PollsTotal     *prometheus.CounterVec
	PollErrors     *prometheus.CounterVec
	PollDuration   *prometheus.HistogramVec
	DevicesTracked prometheus.Gauge
	InterfaceCount *prometheus.GaugeVec
}

// NewSNMPMetrics creates prometheus metrics for SNMP enrichment
func NewSNMPMetrics(namespace string) *SNMPMetrics {
	return &SNMPMetrics{
		PollsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "snmp",
			Name:      "polls_total",
			Help:      "Total SNMP polls performed",
		}, []string{"device", "status"}),
		PollErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "snmp",
			Name:      "poll_errors_total",
			Help:      "Total SNMP poll errors",
		}, []string{"device", "error_type"}),
		PollDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: "snmp",
			Name:      "poll_duration_seconds",
			Help:      "SNMP poll duration in seconds",
			Buckets:   prometheus.ExponentialBuckets(0.1, 2, 8),
		}, []string{"device"}),
		DevicesTracked: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "snmp",
			Name:      "devices_tracked",
			Help:      "Number of devices being tracked via SNMP",
		}),
		InterfaceCount: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: "snmp",
			Name:      "interface_count",
			Help:      "Number of interfaces per device",
		}, []string{"device"}),
	}
}

// SNMPEnricher handles SNMP-based flow enrichment
type SNMPEnricher struct {
	config  *SNMPEnricherConfig
	devices map[string]*DeviceInfo
	mu      sync.RWMutex
	stopCh  chan struct{}
	wg      sync.WaitGroup
}

// NewSNMPEnricher creates a new SNMP enricher
func NewSNMPEnricher(cfg *SNMPEnricherConfig) *SNMPEnricher {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Retries == 0 {
		cfg.Retries = 2
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 5 * time.Minute
	}
	if cfg.MaxParallelPolls == 0 {
		cfg.MaxParallelPolls = 4
	}
	if cfg.Version == 0 {
		cfg.Version = gosnmp.Version2c
	}
	if cfg.Community == "" {
		cfg.Community = "public"
	}

	return &SNMPEnricher{
		config:  cfg,
		devices: make(map[string]*DeviceInfo),
		stopCh:  make(chan struct{}),
	}
}

// Start begins the SNMP polling routine
func (e *SNMPEnricher) Start() error {
	if !e.config.Enabled {
		if log != nil {
			log.Info("SNMP enrichment is disabled")
		}
		return nil
	}

	// Poll static devices immediately
	for _, ip := range e.config.StaticDevices {
		e.wg.Add(1)
		go func(deviceIP string) {
			defer e.wg.Done()
			if err := e.PollDevice(net.ParseIP(deviceIP)); err != nil {
				if log != nil {
					log.WithError(err).WithField("device", deviceIP).Warn("Initial SNMP poll failed")
				}
			}
		}(ip)
	}

	// Start periodic polling
	e.wg.Add(1)
	go e.pollLoop()

	if log != nil {
		log.WithFields(logrus.Fields{
			"interval":      e.config.PollInterval,
			"static_devices": len(e.config.StaticDevices),
			"auto_discover": e.config.AutoDiscover,
		}).Info("SNMP enrichment started")
	}

	return nil
}

// Stop stops the SNMP polling routine
func (e *SNMPEnricher) Stop() {
	close(e.stopCh)
	e.wg.Wait()
	if log != nil {
		log.Info("SNMP enrichment stopped")
	}
}

func (e *SNMPEnricher) pollLoop() {
	defer e.wg.Done()

	ticker := time.NewTicker(e.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			e.pollAllDevices()
		}
	}
}

func (e *SNMPEnricher) pollAllDevices() {
	e.mu.RLock()
	deviceIPs := make([]string, 0, len(e.devices))
	for ip := range e.devices {
		deviceIPs = append(deviceIPs, ip)
	}
	e.mu.RUnlock()

	// Rate-limit concurrent polls
	sem := make(chan struct{}, e.config.MaxParallelPolls)
	var wg sync.WaitGroup

	for _, ipStr := range deviceIPs {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer func() {
				<-sem
				wg.Done()
			}()
			if err := e.PollDevice(net.ParseIP(ip)); err != nil {
				if log != nil {
					log.WithError(err).WithField("device", ip).Debug("SNMP poll failed")
				}
			}
		}(ipStr)
	}

	wg.Wait()
}

// PollDevice polls a device for interface information
func (e *SNMPEnricher) PollDevice(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("nil IP address")
	}

	start := time.Now()
	ipStr := ip.String()

	snmp := &gosnmp.GoSNMP{
		Target:    ipStr,
		Port:      161,
		Community: e.config.Community,
		Version:   e.config.Version,
		Timeout:   e.config.Timeout,
		Retries:   e.config.Retries,
	}

	if err := snmp.Connect(); err != nil {
		if e.config.Metrics != nil {
			e.config.Metrics.PollErrors.WithLabelValues(ipStr, "connect").Inc()
		}
		return fmt.Errorf("SNMP connect failed: %w", err)
	}
	defer snmp.Conn.Close()

	device := &DeviceInfo{
		IPAddress:  ip,
		Interfaces: make(map[uint32]*InterfaceInfo),
		LastPolled: time.Now(),
	}

	// Get system info
	if err := e.pollSystemInfo(snmp, device); err != nil {
		if log != nil {
			log.WithError(err).WithField("device", ipStr).Debug("Failed to get system info")
		}
		// Continue anyway - interface info is more important
	}

	// Get interface info
	if err := e.pollInterfaceInfo(snmp, device); err != nil {
		if e.config.Metrics != nil {
			e.config.Metrics.PollErrors.WithLabelValues(ipStr, "interface").Inc()
		}
		return fmt.Errorf("failed to poll interfaces: %w", err)
	}

	// Store device info
	e.mu.Lock()
	e.devices[ipStr] = device
	deviceCount := len(e.devices)
	e.mu.Unlock()

	duration := time.Since(start)

	if e.config.Metrics != nil {
		e.config.Metrics.PollsTotal.WithLabelValues(ipStr, "success").Inc()
		e.config.Metrics.PollDuration.WithLabelValues(ipStr).Observe(duration.Seconds())
		e.config.Metrics.DevicesTracked.Set(float64(deviceCount))
		e.config.Metrics.InterfaceCount.WithLabelValues(ipStr).Set(float64(len(device.Interfaces)))
	}

	if log != nil {
		log.WithFields(logrus.Fields{
			"device":     ipStr,
			"sys_name":   device.SysName,
			"interfaces": len(device.Interfaces),
			"duration":   duration,
		}).Debug("SNMP poll completed")
	}

	return nil
}

func (e *SNMPEnricher) pollSystemInfo(snmp *gosnmp.GoSNMP, device *DeviceInfo) error {
	oids := []string{OIDSysDescr, OIDSysName, OIDSysObjectID, OIDSysUptime}

	result, err := snmp.Get(oids)
	if err != nil {
		return err
	}

	for _, variable := range result.Variables {
		switch variable.Name {
		case OIDSysDescr:
			device.SysDescr = string(variable.Value.([]byte))
		case OIDSysName:
			device.SysName = string(variable.Value.([]byte))
		case OIDSysObjectID:
			device.SysObjectID = variable.Value.(string)
		case OIDSysUptime:
			device.SysUptime = gosnmp.ToBigInt(variable.Value).Uint64()
		}
	}

	return nil
}

func (e *SNMPEnricher) pollInterfaceInfo(snmp *gosnmp.GoSNMP, device *DeviceInfo) error {
	// Walk ifName first as it's most useful
	if err := e.walkOID(snmp, OIDIfName, func(oid string, value interface{}) {
		ifIndex := extractIfIndex(oid)
		if ifIndex == 0 {
			return
		}
		iface := e.getOrCreateInterface(device, ifIndex)
		if v, ok := value.([]byte); ok {
			iface.IfName = string(v)
		}
	}); err != nil {
		// ifName might not be supported, try ifDescr
		if log != nil {
			log.WithError(err).Debug("ifName walk failed, trying ifDescr")
		}
	}

	// Walk ifDescr
	if err := e.walkOID(snmp, OIDIfDescr, func(oid string, value interface{}) {
		ifIndex := extractIfIndex(oid)
		if ifIndex == 0 {
			return
		}
		iface := e.getOrCreateInterface(device, ifIndex)
		if v, ok := value.([]byte); ok {
			iface.IfDescr = string(v)
			// Use ifDescr as name if ifName not set
			if iface.IfName == "" {
				iface.IfName = iface.IfDescr
			}
		}
	}); err != nil {
		return fmt.Errorf("ifDescr walk failed: %w", err)
	}

	// Walk ifAlias
	_ = e.walkOID(snmp, OIDIfAlias, func(oid string, value interface{}) {
		ifIndex := extractIfIndex(oid)
		if ifIndex == 0 {
			return
		}
		iface := e.getOrCreateInterface(device, ifIndex)
		if v, ok := value.([]byte); ok {
			iface.IfAlias = string(v)
		}
	})

	// Walk ifHighSpeed (Mbps - for 10G+ interfaces)
	_ = e.walkOID(snmp, OIDIfHighSpeed, func(oid string, value interface{}) {
		ifIndex := extractIfIndex(oid)
		if ifIndex == 0 {
			return
		}
		iface := e.getOrCreateInterface(device, ifIndex)
		if v, ok := value.(uint); ok {
			iface.IfHighSpeed = uint64(v)
			iface.IfSpeed = uint64(v) * 1000000 // Convert to bps
		}
	})

	// Walk ifSpeed (bps - fallback for slower interfaces)
	_ = e.walkOID(snmp, OIDIfSpeed, func(oid string, value interface{}) {
		ifIndex := extractIfIndex(oid)
		if ifIndex == 0 {
			return
		}
		iface := e.getOrCreateInterface(device, ifIndex)
		// Only use ifSpeed if ifHighSpeed wasn't set
		if iface.IfSpeed == 0 {
			if v, ok := value.(uint); ok {
				iface.IfSpeed = uint64(v)
			}
		}
	})

	// Walk ifType
	_ = e.walkOID(snmp, OIDIfType, func(oid string, value interface{}) {
		ifIndex := extractIfIndex(oid)
		if ifIndex == 0 {
			return
		}
		iface := e.getOrCreateInterface(device, ifIndex)
		if v, ok := value.(int); ok {
			iface.IfType = uint32(v)
		}
	})

	// Walk ifOperStatus
	_ = e.walkOID(snmp, OIDIfOperStatus, func(oid string, value interface{}) {
		ifIndex := extractIfIndex(oid)
		if ifIndex == 0 {
			return
		}
		iface := e.getOrCreateInterface(device, ifIndex)
		if v, ok := value.(int); ok {
			iface.OperStatus = uint8(v)
		}
	})

	// Set last updated time for all interfaces
	now := time.Now()
	for _, iface := range device.Interfaces {
		iface.LastUpdated = now
	}

	return nil
}

func (e *SNMPEnricher) walkOID(snmp *gosnmp.GoSNMP, oid string, handler func(string, interface{})) error {
	return snmp.BulkWalk(oid, func(pdu gosnmp.SnmpPDU) error {
		handler(pdu.Name, pdu.Value)
		return nil
	})
}

func (e *SNMPEnricher) getOrCreateInterface(device *DeviceInfo, ifIndex uint32) *InterfaceInfo {
	if iface, ok := device.Interfaces[ifIndex]; ok {
		return iface
	}
	iface := &InterfaceInfo{IfIndex: ifIndex}
	device.Interfaces[ifIndex] = iface
	return iface
}

// extractIfIndex extracts the ifIndex from an OID like "1.3.6.1.2.1.31.1.1.1.1.12345"
func extractIfIndex(oid string) uint32 {
	// Find last dot
	lastDot := -1
	for i := len(oid) - 1; i >= 0; i-- {
		if oid[i] == '.' {
			lastDot = i
			break
		}
	}
	if lastDot == -1 || lastDot == len(oid)-1 {
		return 0
	}

	indexStr := oid[lastDot+1:]
	index, err := strconv.ParseUint(indexStr, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(index)
}

// RegisterExporter registers an exporter for SNMP polling
// Called when first flow is received from a new exporter
func (e *SNMPEnricher) RegisterExporter(ip net.IP) {
	if !e.config.Enabled || !e.config.AutoDiscover {
		return
	}

	ipStr := ip.String()
	e.mu.RLock()
	_, exists := e.devices[ipStr]
	e.mu.RUnlock()

	if !exists {
		// Create placeholder entry
		e.mu.Lock()
		e.devices[ipStr] = &DeviceInfo{
			IPAddress:  ip,
			Interfaces: make(map[uint32]*InterfaceInfo),
		}
		e.mu.Unlock()

		// Poll on-demand if configured
		if e.config.PollOnDemand {
			go func() {
				if err := e.PollDevice(ip); err != nil {
					if log != nil {
						log.WithError(err).WithField("device", ipStr).Debug("On-demand SNMP poll failed")
					}
				}
			}()
		}
	}
}

// GetInterfaceInfo returns interface info for a device/ifIndex
func (e *SNMPEnricher) GetInterfaceInfo(deviceIP net.IP, ifIndex uint32) *InterfaceInfo {
	if deviceIP == nil {
		return nil
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	device, ok := e.devices[deviceIP.String()]
	if !ok {
		return nil
	}

	if iface, ok := device.Interfaces[ifIndex]; ok {
		// Return a copy
		copy := *iface
		return &copy
	}

	return nil
}

// GetDeviceInfo returns device info
func (e *SNMPEnricher) GetDeviceInfo(deviceIP net.IP) *DeviceInfo {
	if deviceIP == nil {
		return nil
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	if device, ok := e.devices[deviceIP.String()]; ok {
		// Return a copy (shallow for interfaces map)
		copy := *device
		return &copy
	}

	return nil
}

// GetAllDevices returns all tracked devices
func (e *SNMPEnricher) GetAllDevices() map[string]*DeviceInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()

	result := make(map[string]*DeviceInfo, len(e.devices))
	for k, v := range e.devices {
		copy := *v
		result[k] = &copy
	}
	return result
}

// IsEnabled returns whether SNMP enrichment is enabled
func (e *SNMPEnricher) IsEnabled() bool {
	return e.config.Enabled
}
