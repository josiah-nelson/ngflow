package syslogflow

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	flowpb "github.com/netsampler/goflow2/v2/pb"
)

// ParseMessage parses a syslog payload into a flow record.
// Supported formats: fortinet (key=value), json (structured).
func ParseMessage(format string, payload []byte) (*FlowRecord, error) {
	raw := strings.TrimSpace(string(payload))
	if raw == "" {
		return nil, fmt.Errorf("empty syslog message")
	}

	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "fortinet"
	}

	switch format {
	case "json":
		return parseJSONMessage(raw)
	case "fortinet":
		return parseFortinetMessage(raw)
	default:
		return nil, fmt.Errorf("unsupported syslog flow format: %s", format)
	}
}

func parseJSONMessage(raw string) (*FlowRecord, error) {
	payload := raw
	if idx := strings.Index(raw, "{"); idx >= 0 {
		payload = raw[idx:]
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		return nil, err
	}

	flow, extras := buildFlowFromJSON(data)
	if extras == nil {
		extras = map[string]interface{}{}
	}
	extras["syslog.format"] = "json"
	return &FlowRecord{Flow: flow, Extras: extras}, nil
}

func parseFortinetMessage(raw string) (*FlowRecord, error) {
	payload := extractPayload(raw, []string{"date=", "time=", "srcip=", "dstip=", "devname=", "devid=", "type="})
	fields := parseKeyValuePairs(payload)
	if len(fields) == 0 {
		return nil, fmt.Errorf("no key/value pairs found")
	}

	flow, extras := buildFlowFromFortinet(fields)
	if extras == nil {
		extras = map[string]interface{}{}
	}
	extras["syslog.format"] = "fortinet"
	return &FlowRecord{Flow: flow, Extras: extras}, nil
}

func buildFlowFromJSON(data map[string]interface{}) (*flowpb.FlowMessage, map[string]interface{}) {
	used := make(map[string]bool)
	getString := func(keys ...string) (string, bool) {
		for _, key := range keys {
			if v, ok := data[key]; ok {
				used[key] = true
				switch t := v.(type) {
				case string:
					return t, true
				case float64:
					return strconv.FormatInt(int64(t), 10), true
				case json.Number:
					return t.String(), true
				}
			}
		}
		return "", false
	}
	getInt := func(keys ...string) (int64, bool) {
		for _, key := range keys {
			if v, ok := data[key]; ok {
				used[key] = true
				switch t := v.(type) {
				case float64:
					return int64(t), true
				case int64:
					return t, true
				case int:
					return int64(t), true
				case json.Number:
					if n, err := t.Int64(); err == nil {
						return n, true
					}
				case string:
					if n, err := strconv.ParseInt(t, 10, 64); err == nil {
						return n, true
					}
				}
			}
		}
		return 0, false
	}

	flow := &flowpb.FlowMessage{
		Type: flowpb.FlowMessage_FLOWUNKNOWN,
	}

	if srcIP, ok := getString("srcip", "src_ip", "source.ip", "source_ip", "srcaddr", "src"); ok {
		flow.SrcAddr = parseIPBytes(srcIP)
	}
	if dstIP, ok := getString("dstip", "dst_ip", "destination.ip", "dest_ip", "dstaddr", "dst"); ok {
		flow.DstAddr = parseIPBytes(dstIP)
	}
	if srcPort, ok := getInt("srcport", "src_port", "source.port"); ok {
		flow.SrcPort = uint32(srcPort)
	}
	if dstPort, ok := getInt("dstport", "dst_port", "destination.port"); ok {
		flow.DstPort = uint32(dstPort)
	}

	if protoVal, ok := getString("proto", "protocol", "ip_proto", "l4_proto"); ok {
		flow.Proto = uint32(parseProto(protoVal))
	} else if protoNum, ok := getInt("proto", "protocol", "ip_proto", "l4_proto"); ok {
		flow.Proto = uint32(protoNum)
	}

	bytes := int64(0)
	if v, ok := getInt("bytes", "byte", "in_bytes", "out_bytes"); ok {
		bytes = v
	} else {
		sent, _ := getInt("sentbyte", "bytes_sent", "out_bytes")
		recv, _ := getInt("rcvdbyte", "bytes_received", "in_bytes")
		bytes = sent + recv
	}
	if bytes > 0 {
		flow.Bytes = uint64(bytes)
	}

	packets := int64(0)
	if v, ok := getInt("packets", "pkts", "in_pkts", "out_pkts"); ok {
		packets = v
	} else {
		sent, _ := getInt("sentpkt", "pkts_sent", "out_pkts")
		recv, _ := getInt("rcvdpkt", "pkts_received", "in_pkts")
		packets = sent + recv
	}
	if packets > 0 {
		flow.Packets = uint64(packets)
	}

	var startTime time.Time
	var endTime time.Time

	if ts, ok := getString("@timestamp", "timestamp", "time", "event_time", "end_time", "end"); ok {
		if parsed, ok := parseTimeString(ts); ok {
			endTime = parsed
		}
	}
	if tsNum, ok := getInt("eventtime", "end_time", "end", "timestamp"); ok && endTime.IsZero() {
		if parsed, ok := parseUnixTimestamp(tsNum); ok {
			endTime = parsed
		}
	}
	if ts, ok := getString("start", "start_time", "time_start"); ok {
		if parsed, ok := parseTimeString(ts); ok {
			startTime = parsed
		}
	}
	if tsNum, ok := getInt("start", "start_time", "time_start"); ok && startTime.IsZero() {
		if parsed, ok := parseUnixTimestamp(tsNum); ok {
			startTime = parsed
		}
	}

	durationSec := int64(0)
	if dur, ok := getInt("duration", "duration_sec"); ok {
		durationSec = dur
	} else if durMs, ok := getInt("duration_ms"); ok {
		durationSec = durMs / 1000
	}

	if endTime.IsZero() && !startTime.IsZero() && durationSec > 0 {
		endTime = startTime.Add(time.Duration(durationSec) * time.Second)
	}
	if startTime.IsZero() && !endTime.IsZero() && durationSec > 0 {
		startTime = endTime.Add(-time.Duration(durationSec) * time.Second)
	}
	if startTime.IsZero() && !endTime.IsZero() {
		startTime = endTime
	}
	if endTime.IsZero() {
		endTime = time.Now()
		if startTime.IsZero() {
			startTime = endTime
		}
	}

	flow.TimeFlowStartNs = uint64(startTime.UnixNano())
	flow.TimeFlowEndNs = uint64(endTime.UnixNano())

	if samplerIP, ok := getString("device_ip", "observer.ip", "observer_ip", "host"); ok {
		flow.SamplerAddress = parseIPBytes(samplerIP)
	}

	extras := make(map[string]interface{})
	for k, v := range data {
		if used[k] {
			continue
		}
		switch t := v.(type) {
		case string, float64, bool, json.Number:
			extras["syslog."+sanitizeKey(k)] = t
		}
	}
	return flow, extras
}

func buildFlowFromFortinet(fields map[string]string) (*flowpb.FlowMessage, map[string]interface{}) {
	flow := &flowpb.FlowMessage{
		Type: flowpb.FlowMessage_FLOWUNKNOWN,
	}

	srcIP := fields["srcip"]
	if srcIP == "" {
		srcIP = fields["src_ip"]
	}
	dstIP := fields["dstip"]
	if dstIP == "" {
		dstIP = fields["dst_ip"]
	}

	if srcIP != "" {
		flow.SrcAddr = parseIPBytes(srcIP)
	}
	if dstIP != "" {
		flow.DstAddr = parseIPBytes(dstIP)
	}

	if srcPort := parseInt(fields["srcport"]); srcPort > 0 {
		flow.SrcPort = uint32(srcPort)
	}
	if dstPort := parseInt(fields["dstport"]); dstPort > 0 {
		flow.DstPort = uint32(dstPort)
	}

	if proto := fields["proto"]; proto != "" {
		flow.Proto = uint32(parseProto(proto))
	} else if proto := fields["protocol"]; proto != "" {
		flow.Proto = uint32(parseProto(proto))
	}

	bytes := int64(0)
	if b := parseInt64(fields["bytes"]); b > 0 {
		bytes = b
	} else {
		sent := parseInt64(fields["sentbyte"])
		recv := parseInt64(fields["rcvdbyte"])
		bytes = sent + recv
	}
	if bytes > 0 {
		flow.Bytes = uint64(bytes)
	}

	packets := int64(0)
	if p := parseInt64(fields["packets"]); p > 0 {
		packets = p
	} else {
		sent := parseInt64(fields["sentpkt"])
		recv := parseInt64(fields["rcvdpkt"])
		packets = sent + recv
	}
	if packets > 0 {
		flow.Packets = uint64(packets)
	}

	var endTime time.Time
	var startTime time.Time

	if eventTime := parseInt64(fields["eventtime"]); eventTime > 0 {
		if parsed, ok := parseUnixTimestamp(eventTime); ok {
			endTime = parsed
		}
	}

	if endTime.IsZero() {
		date := fields["date"]
		tm := fields["time"]
		if date != "" && tm != "" {
			if parsed, err := time.ParseInLocation("2006-01-02 15:04:05", date+" "+tm, time.UTC); err == nil {
				endTime = parsed
			}
		}
	}

	duration := parseInt64(fields["duration"])
	if duration > 0 && !endTime.IsZero() {
		startTime = endTime.Add(-time.Duration(duration) * time.Second)
	}

	if startTime.IsZero() && !endTime.IsZero() {
		startTime = endTime
	}
	if endTime.IsZero() {
		endTime = time.Now()
		if startTime.IsZero() {
			startTime = endTime
		}
	}

	flow.TimeFlowStartNs = uint64(startTime.UnixNano())
	flow.TimeFlowEndNs = uint64(endTime.UnixNano())

	if devIP := fields["deviceip"]; devIP != "" {
		flow.SamplerAddress = parseIPBytes(devIP)
	}

	extras := make(map[string]interface{})
	if action := fields["action"]; action != "" {
		extras["syslog.action"] = action
	}
	if policy := fields["policyid"]; policy != "" {
		if val, err := strconv.ParseInt(policy, 10, 64); err == nil {
			extras["syslog.policy_id"] = val
		} else {
			extras["syslog.policy_id"] = policy
		}
	}
	if app := fields["app"]; app != "" {
		extras["syslog.app"] = app
	} else if service := fields["service"]; service != "" {
		extras["syslog.app"] = service
	}
	if appcat := fields["appcat"]; appcat != "" {
		extras["syslog.app_category"] = appcat
	}
	if subtype := fields["subtype"]; subtype != "" {
		extras["syslog.subtype"] = subtype
	}
	if eventType := fields["type"]; eventType != "" {
		extras["syslog.type"] = eventType
	}
	if devName := fields["devname"]; devName != "" {
		extras["syslog.device_name"] = devName
	}
	if devID := fields["devid"]; devID != "" {
		extras["syslog.device_id"] = devID
	}
	if vdom := fields["vd"]; vdom != "" {
		extras["syslog.vdom"] = vdom
	}
	if srcIntf := fields["srcintf"]; srcIntf != "" {
		extras["in_ifName"] = srcIntf
	}
	if dstIntf := fields["dstintf"]; dstIntf != "" {
		extras["out_ifName"] = dstIntf
	}
	if direction := fields["direction"]; direction != "" {
		extras["syslog.direction"] = direction
	}
	if duration > 0 {
		extras["syslog.duration_sec"] = duration
	}

	return flow, extras
}

func extractPayload(raw string, keys []string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	index := -1
	for _, key := range keys {
		if pos := strings.Index(raw, key); pos >= 0 {
			if index == -1 || pos < index {
				index = pos
			}
		}
	}
	if index > 0 {
		return strings.TrimSpace(raw[index:])
	}
	return raw
}

func parseKeyValuePairs(input string) map[string]string {
	out := make(map[string]string)
	i := 0
	for i < len(input) {
		for i < len(input) && input[i] == ' ' {
			i++
		}
		if i >= len(input) {
			break
		}
		startKey := i
		for i < len(input) && input[i] != '=' && input[i] != ' ' {
			i++
		}
		if i >= len(input) || input[i] != '=' {
			for i < len(input) && input[i] != ' ' {
				i++
			}
			continue
		}
		key := input[startKey:i]
		i++
		if i >= len(input) {
			out[key] = ""
			break
		}
		var value string
		if input[i] == '"' {
			i++
			startVal := i
			for i < len(input) && input[i] != '"' {
				if input[i] == '\\' && i+1 < len(input) {
					i += 2
					continue
				}
				i++
			}
			value = input[startVal:i]
			if i < len(input) && input[i] == '"' {
				i++
			}
		} else {
			startVal := i
			for i < len(input) && input[i] != ' ' {
				i++
			}
			value = input[startVal:i]
		}
		if key != "" {
			out[key] = value
		}
	}
	return out
}

func parseProto(value string) uint8 {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "tcp":
		return 6
	case "udp":
		return 17
	case "icmp":
		return 1
	case "icmpv6":
		return 58
	default:
		if n, err := strconv.ParseUint(value, 10, 8); err == nil {
			return uint8(n)
		}
	}
	return 0
}

func parseIPBytes(value string) []byte {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip.To16()
}

func parseInt(value string) int {
	if value == "" {
		return 0
	}
	i, _ := strconv.Atoi(value)
	return i
}

func parseInt64(value string) int64 {
	if value == "" {
		return 0
	}
	i, _ := strconv.ParseInt(value, 10, 64)
	return i
}

func parseUnixTimestamp(value int64) (time.Time, bool) {
	if value <= 0 {
		return time.Time{}, false
	}
	if value > 1_000_000_000_000 {
		return time.Unix(0, value*int64(time.Millisecond)), true
	}
	return time.Unix(value, 0), true
}

func parseTimeString(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, true
		}
	}
	return time.Time{}, false
}

func sanitizeKey(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	replacer := strings.NewReplacer(" ", "_", "\t", "_")
	return replacer.Replace(value)
}
