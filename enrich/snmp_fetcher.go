package enrich

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

const (
	oidIfName      = "1.3.6.1.2.1.31.1.1.1.1"
	oidIfDescr     = "1.3.6.1.2.1.2.2.1.2"
	oidIfAlias     = "1.3.6.1.2.1.31.1.1.1.18"
	oidIfSpeed     = "1.3.6.1.2.1.2.2.1.5"
	oidIfHighSpeed = "1.3.6.1.2.1.31.1.1.1.15"
)

type SNMPFetcherConfig struct {
	Community string
	Port      uint16
	Version   string
	Timeout   time.Duration
	Retries   int
}

type SNMPFetcher struct {
	config SNMPFetcherConfig
}

func NewSNMPFetcher(config SNMPFetcherConfig) *SNMPFetcher {
	return &SNMPFetcher{config: config}
}

func (f *SNMPFetcher) Fetch(target string) (map[uint32]InterfaceMetadata, error) {
	if net.ParseIP(target) == nil {
		return nil, fmt.Errorf("invalid SNMP target: %s", target)
	}

	client, err := f.newClient(target)
	if err != nil {
		return nil, err
	}
	if err := client.Connect(); err != nil {
		return nil, fmt.Errorf("snmp connect failed: %w", err)
	}
	defer client.Conn.Close()

	entries := make(map[uint32]InterfaceMetadata)
	if err := f.walkString(client, oidIfName, func(ifIndex uint32, value string) {
		meta := entries[ifIndex]
		meta.Name = value
		entries[ifIndex] = meta
	}); err != nil {
		log.WithError(err).WithField("target", target).Debug("snmp ifName walk failed")
	}

	if err := f.walkString(client, oidIfDescr, func(ifIndex uint32, value string) {
		meta := entries[ifIndex]
		if meta.Name == "" {
			meta.Name = value
		}
		entries[ifIndex] = meta
	}); err != nil {
		log.WithError(err).WithField("target", target).Debug("snmp ifDescr walk failed")
	}

	if err := f.walkString(client, oidIfAlias, func(ifIndex uint32, value string) {
		meta := entries[ifIndex]
		meta.Alias = value
		entries[ifIndex] = meta
	}); err != nil {
		log.WithError(err).WithField("target", target).Debug("snmp ifAlias walk failed")
	}

	if err := f.walkUint(client, oidIfSpeed, func(ifIndex uint32, value uint64) {
		meta := entries[ifIndex]
		if meta.SpeedBps == 0 {
			meta.SpeedBps = value
			entries[ifIndex] = meta
		}
	}); err != nil {
		log.WithError(err).WithField("target", target).Debug("snmp ifSpeed walk failed")
	}

	if err := f.walkUint(client, oidIfHighSpeed, func(ifIndex uint32, value uint64) {
		if value == 0 {
			return
		}
		meta := entries[ifIndex]
		meta.SpeedBps = value * 1_000_000
		entries[ifIndex] = meta
	}); err != nil {
		log.WithError(err).WithField("target", target).Debug("snmp ifHighSpeed walk failed")
	}

	return entries, nil
}

func (f *SNMPFetcher) newClient(target string) (*gosnmp.GoSNMP, error) {
	version := gosnmp.Version2c
	if f.config.Version != "" && f.config.Version != "2c" {
		return nil, fmt.Errorf("unsupported SNMP version: %s", f.config.Version)
	}

	community := f.config.Community
	if community == "" {
		community = "public"
	}

	timeout := f.config.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	port := f.config.Port
	if port == 0 {
		port = 161
	}

	return &gosnmp.GoSNMP{
		Target:    target,
		Port:      port,
		Version:   version,
		Community: community,
		Timeout:   timeout,
		Retries:   f.config.Retries,
	}, nil
}

func (f *SNMPFetcher) walkString(client *gosnmp.GoSNMP, oid string, apply func(uint32, string)) error {
	pdus, err := client.BulkWalkAll(oid)
	if err != nil {
		return fmt.Errorf("snmp walk %s failed: %w", oid, err)
	}
	for _, pdu := range pdus {
		ifIndex, err := parseIfIndex(pdu.Name)
		if err != nil {
			continue
		}
		value := strings.TrimSpace(toString(pdu.Value))
		if value == "" {
			continue
		}
		apply(ifIndex, value)
	}
	return nil
}

func (f *SNMPFetcher) walkUint(client *gosnmp.GoSNMP, oid string, apply func(uint32, uint64)) error {
	pdus, err := client.BulkWalkAll(oid)
	if err != nil {
		return fmt.Errorf("snmp walk %s failed: %w", oid, err)
	}
	for _, pdu := range pdus {
		ifIndex, err := parseIfIndex(pdu.Name)
		if err != nil {
			continue
		}
		value, ok := toUint64(pdu.Value)
		if !ok {
			continue
		}
		apply(ifIndex, value)
	}
	return nil
}

func parseIfIndex(oid string) (uint32, error) {
	parts := strings.Split(oid, ".")
	if len(parts) == 0 {
		return 0, fmt.Errorf("invalid oid")
	}
	indexStr := parts[len(parts)-1]
	idx, err := strconv.ParseUint(indexStr, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(idx), nil
}

func toString(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	default:
		return ""
	}
}

func toUint64(value interface{}) (uint64, bool) {
	switch v := value.(type) {
	case uint8:
		return uint64(v), true
	case uint16:
		return uint64(v), true
	case uint:
		return uint64(v), true
	case uint32:
		return uint64(v), true
	case uint64:
		return v, true
	case int8:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case int16:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case int:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case int32:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case int64:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	default:
		return 0, false
	}
}
