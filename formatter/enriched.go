// Package formatter - enriched.go provides formatting support for enriched flows
// with vendor-specific fields, SNMP metadata, and L7 classification.
//
// This extends the existing TLV and JSON formatters to include:
//   - SNMP interface metadata (ifName, ifAlias, ifSpeed)
//   - L7 application classification
//   - Vendor-specific fields (Extreme Networks, etc.)
//
// Compatibility: ntopng 5.x and 6.x

package formatter

import (
	"encoding/json"
	"strconv"

	"github.com/netsampler/goflow2/v2/decoders/netflow"
	"github.com/synfinatic/netflow2ng/enrichment"
)

// Extended field IDs for enriched data
// These are custom field IDs that ntopng will recognize
const (
	// SNMP enrichment fields (using IPFIX enterprise-specific range)
	FieldInIfName      = 82  // Standard IPFIX interfaceName (ingress)
	FieldOutIfName     = 83  // interfaceName (egress) - custom
	FieldInIfAlias     = 18  // interfaceDescription (ingress)
	FieldOutIfAlias    = 19  // interfaceDescription (egress) - custom
	FieldInIfSpeed     = 84  // Custom: input interface speed (Mbps)
	FieldOutIfSpeed    = 85  // Custom: output interface speed (Mbps)
	FieldDeviceName    = 86  // Custom: device sysName

	// L7 classification fields
	FieldL7Protocol    = 87  // Custom: L7 protocol ID
	FieldL7Category    = 88  // Custom: L7 category ID
	FieldL7ProtoName   = 89  // Custom: L7 protocol name (string)
	FieldL7CategoryName = 90 // Custom: L7 category name (string)
	FieldL7Confidence  = 91  // Custom: classification confidence

	// Vendor-specific fields (Extreme Networks)
	FieldVendorType    = 92  // Custom: vendor identifier
	FieldExtremeDevice = 93  // Custom: Extreme device type
)

// EnrichedTLVItems returns additional TLV items for enriched flow data
func EnrichedTLVItems(enriched *enrichment.EnrichedFlow) []ndpiItem {
	var items []ndpiItem

	// SNMP enrichment
	if enriched.SNMPEnriched {
		if enriched.InIfName != "" {
			items = append(items, ndpiItem{Key: FieldInIfName, Value: enriched.InIfName})
		}
		if enriched.OutIfName != "" {
			items = append(items, ndpiItem{Key: FieldOutIfName, Value: enriched.OutIfName})
		}
		if enriched.InIfAlias != "" {
			items = append(items, ndpiItem{Key: FieldInIfAlias, Value: enriched.InIfAlias})
		}
		if enriched.OutIfAlias != "" {
			items = append(items, ndpiItem{Key: FieldOutIfAlias, Value: enriched.OutIfAlias})
		}
		if enriched.InIfSpeed > 0 {
			// Convert to Mbps for reasonable size
			items = append(items, ndpiItem{Key: FieldInIfSpeed, Value: enriched.InIfSpeed / 1000000})
		}
		if enriched.OutIfSpeed > 0 {
			items = append(items, ndpiItem{Key: FieldOutIfSpeed, Value: enriched.OutIfSpeed / 1000000})
		}
		if enriched.DeviceSysName != "" {
			items = append(items, ndpiItem{Key: FieldDeviceName, Value: enriched.DeviceSysName})
		}
	}

	// L7 classification
	if enriched.L7Enriched {
		items = append(items,
			ndpiItem{Key: FieldL7Protocol, Value: uint16(enriched.L7Protocol)},
			ndpiItem{Key: FieldL7Category, Value: uint8(enriched.L7Category)},
			ndpiItem{Key: FieldL7ProtoName, Value: enriched.L7Protocol.String()},
			ndpiItem{Key: FieldL7CategoryName, Value: enriched.L7Category.String()},
			ndpiItem{Key: FieldL7Confidence, Value: enriched.L7Confidence},
		)
	}

	// Vendor-specific fields
	if enriched.VendorType != "" {
		items = append(items, ndpiItem{Key: FieldVendorType, Value: enriched.VendorType})
	}

	// Add any custom vendor fields
	for key, value := range enriched.VendorFields {
		// Map string keys to numeric field IDs
		// This is a simplified approach; production would use a proper mapping
		switch key {
		case "extreme_device_type":
			if v, ok := value.(string); ok {
				items = append(items, ndpiItem{Key: FieldExtremeDevice, Value: v})
			}
		}
	}

	return items
}

// EnrichedJSONFields returns additional JSON fields for enriched flow data
func EnrichedJSONFields(enriched *enrichment.EnrichedFlow, retmap map[string]interface{}) {
	// SNMP enrichment
	if enriched.SNMPEnriched {
		if enriched.InIfName != "" {
			retmap[strconv.Itoa(FieldInIfName)] = enriched.InIfName
		}
		if enriched.OutIfName != "" {
			retmap[strconv.Itoa(FieldOutIfName)] = enriched.OutIfName
		}
		if enriched.InIfAlias != "" {
			retmap[strconv.Itoa(FieldInIfAlias)] = enriched.InIfAlias
		}
		if enriched.OutIfAlias != "" {
			retmap[strconv.Itoa(FieldOutIfAlias)] = enriched.OutIfAlias
		}
		if enriched.InIfSpeed > 0 {
			retmap[strconv.Itoa(FieldInIfSpeed)] = enriched.InIfSpeed / 1000000
		}
		if enriched.OutIfSpeed > 0 {
			retmap[strconv.Itoa(FieldOutIfSpeed)] = enriched.OutIfSpeed / 1000000
		}
		if enriched.DeviceSysName != "" {
			retmap[strconv.Itoa(FieldDeviceName)] = enriched.DeviceSysName
		}

		// Also add human-readable keys for JSON consumers
		retmap["in_if_name"] = enriched.InIfName
		retmap["out_if_name"] = enriched.OutIfName
		retmap["in_if_alias"] = enriched.InIfAlias
		retmap["out_if_alias"] = enriched.OutIfAlias
		retmap["device_name"] = enriched.DeviceSysName
	}

	// L7 classification
	if enriched.L7Enriched {
		retmap[strconv.Itoa(FieldL7Protocol)] = uint16(enriched.L7Protocol)
		retmap[strconv.Itoa(FieldL7Category)] = uint8(enriched.L7Category)
		retmap[strconv.Itoa(FieldL7ProtoName)] = enriched.L7Protocol.String()
		retmap[strconv.Itoa(FieldL7CategoryName)] = enriched.L7Category.String()
		retmap[strconv.Itoa(FieldL7Confidence)] = enriched.L7Confidence

		// Human-readable keys
		retmap["l7_protocol"] = enriched.L7Protocol.String()
		retmap["l7_category"] = enriched.L7Category.String()
		retmap["l7_confidence"] = enriched.L7Confidence
	}

	// Vendor-specific
	if enriched.VendorType != "" {
		retmap["vendor"] = enriched.VendorType
	}
	for key, value := range enriched.VendorFields {
		retmap[key] = value
	}
}

// FormatEnrichedFlowTLV formats an enriched flow to TLV
func FormatEnrichedFlowTLV(enriched *enrichment.EnrichedFlow) ([]byte, error) {
	if enriched == nil || enriched.BaseFlow == nil {
		return nil, nil
	}

	// Get base TLV items from the standard formatter
	// Note: This requires integration with the existing toTLV logic
	// For now, we'll just create the enriched items

	items := EnrichedTLVItems(enriched)

	// Add standard flow fields from base flow
	baseItems := baseFlowToTLVItems(enriched.BaseFlow)
	items = append(baseItems, items...)

	return serializeTlvRecord(items)
}

// baseFlowToTLVItems converts base flow to TLV items
// This is a subset of the full toTLV function for enriched flows
func baseFlowToTLVItems(flow interface{}) []ndpiItem {
	// This would need access to the flow message
	// Implementation depends on how enriched flows are integrated
	// For now, return empty - the main formatter handles base fields
	return nil
}

// FormatEnrichedFlowJSON formats an enriched flow to JSON
func FormatEnrichedFlowJSON(enriched *enrichment.EnrichedFlow) ([]byte, error) {
	if enriched == nil || enriched.BaseFlow == nil {
		return nil, nil
	}

	retmap := make(map[string]interface{})

	// Add base flow fields
	baseFlow := enriched.BaseFlow

	// Direction and stats
	retmap[strconv.Itoa(netflow.NFV9_FIELD_DIRECTION)] = 0
	retmap[strconv.Itoa(netflow.NFV9_FIELD_IN_BYTES)] = baseFlow.Bytes
	retmap[strconv.Itoa(netflow.NFV9_FIELD_IN_PKTS)] = baseFlow.Packets
	retmap[strconv.Itoa(netflow.NFV9_FIELD_FIRST_SWITCHED)] = uint32(baseFlow.TimeFlowStartNs / 1_000_000_000)
	retmap[strconv.Itoa(netflow.NFV9_FIELD_LAST_SWITCHED)] = uint32(baseFlow.TimeFlowEndNs / 1_000_000_000)

	// L4
	retmap[strconv.Itoa(netflow.NFV9_FIELD_PROTOCOL)] = baseFlow.Proto
	retmap[strconv.Itoa(netflow.NFV9_FIELD_L4_SRC_PORT)] = baseFlow.SrcPort
	retmap[strconv.Itoa(netflow.NFV9_FIELD_L4_DST_PORT)] = baseFlow.DstPort

	// Interfaces
	retmap[strconv.Itoa(netflow.NFV9_FIELD_INPUT_SNMP)] = baseFlow.InIf
	retmap[strconv.Itoa(netflow.NFV9_FIELD_OUTPUT_SNMP)] = baseFlow.OutIf

	// Add enriched fields
	EnrichedJSONFields(enriched, retmap)

	return json.Marshal(retmap)
}

// NtopngFieldMapping documents the field mapping for ntopng compatibility
// These mappings work with ntopng 5.4+ and 6.x
var NtopngFieldMapping = map[uint16]string{
	// Standard fields
	netflow.NFV9_FIELD_IN_BYTES:      "IN_BYTES",
	netflow.NFV9_FIELD_IN_PKTS:       "IN_PKTS",
	netflow.NFV9_FIELD_PROTOCOL:      "PROTOCOL",
	netflow.NFV9_FIELD_L4_SRC_PORT:   "L4_SRC_PORT",
	netflow.NFV9_FIELD_L4_DST_PORT:   "L4_DST_PORT",
	netflow.NFV9_FIELD_INPUT_SNMP:    "INPUT_SNMP",
	netflow.NFV9_FIELD_OUTPUT_SNMP:   "OUTPUT_SNMP",

	// Enriched fields
	FieldInIfName:       "INPUT_INTERFACE_NAME",
	FieldOutIfName:      "OUTPUT_INTERFACE_NAME",
	FieldInIfAlias:      "INPUT_INTERFACE_DESCRIPTION",
	FieldOutIfAlias:     "OUTPUT_INTERFACE_DESCRIPTION",
	FieldL7Protocol:     "L7_PROTO",
	FieldL7Category:     "L7_CATEGORY",
	FieldL7ProtoName:    "L7_PROTO_NAME",
	FieldL7CategoryName: "L7_CATEGORY_NAME",
}
