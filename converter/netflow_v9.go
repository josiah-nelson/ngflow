package converter

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	flowpb "github.com/netsampler/goflow2/v2/pb"
)

type NetFlowV9Config struct {
	Targets         []string
	SourceID        uint32
	TemplateID      uint16
	TemplateRefresh time.Duration
}

type NetFlowV9Exporter struct {
	conns           []*net.UDPConn
	sourceID        uint32
	templateID      uint16
	templateRefresh time.Duration
	seq             uint32
	started         time.Time
	lastTemplate    time.Time
	mu              sync.Mutex
}

func NewNetFlowV9Exporter(cfg NetFlowV9Config) (*NetFlowV9Exporter, error) {
	if len(cfg.Targets) == 0 {
		return nil, nil
	}
	if cfg.TemplateID == 0 {
		cfg.TemplateID = 256
	}
	if cfg.TemplateRefresh <= 0 {
		cfg.TemplateRefresh = 30 * time.Second
	}

	exp := &NetFlowV9Exporter{
		sourceID:        cfg.SourceID,
		templateID:      cfg.TemplateID,
		templateRefresh: cfg.TemplateRefresh,
		started:         time.Now(),
	}

	for _, target := range cfg.Targets {
		addr := strings.TrimSpace(target)
		addr = strings.TrimPrefix(addr, "udp://")
		if addr == "" {
			continue
		}
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, fmt.Errorf("invalid netflow target %s: %w", addr, err)
		}
		conn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to dial netflow target %s: %w", addr, err)
		}
		exp.conns = append(exp.conns, conn)
	}
	if len(exp.conns) == 0 {
		return nil, nil
	}
	return exp, nil
}

func (e *NetFlowV9Exporter) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, conn := range e.conns {
		if conn != nil {
			_ = conn.Close()
		}
	}
	e.conns = nil
}

func (e *NetFlowV9Exporter) SendFlow(flow *flowpb.FlowMessage) error {
	if e == nil || flow == nil || len(e.conns) == 0 {
		return nil
	}
	if len(flow.SrcAddr) != 4 || len(flow.DstAddr) != 4 {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	uptime := uint32(now.Sub(e.started).Milliseconds())
	first, last := computeSwitchedTimes(flow, uptime, now)

	record := encodeNetFlowV9Record(flow, first, last)
	includeTemplate := e.lastTemplate.IsZero() || now.Sub(e.lastTemplate) >= e.templateRefresh
	packet := buildNetFlowV9Packet(e.sourceID, e.templateID, e.seq, uptime, now, record, includeTemplate)

	for _, conn := range e.conns {
		if conn != nil {
			_, _ = conn.Write(packet)
		}
	}

	e.seq++
	if includeTemplate {
		e.lastTemplate = now
	}
	return nil
}

func computeSwitchedTimes(flow *flowpb.FlowMessage, uptime uint32, now time.Time) (first uint32, last uint32) {
	last = uptime
	first = uptime

	if flow.TimeFlowEndNs > 0 {
		endTime := time.Unix(0, int64(flow.TimeFlowEndNs))
		delta := now.Sub(endTime).Milliseconds()
		if delta >= 0 && delta <= int64(uptime) {
			last = uptime - uint32(delta)
		}
	}

	if flow.TimeFlowStartNs > 0 {
		startTime := time.Unix(0, int64(flow.TimeFlowStartNs))
		delta := now.Sub(startTime).Milliseconds()
		if delta >= 0 && delta <= int64(uptime) {
			first = uptime - uint32(delta)
		}
	}
	if first > last {
		first = last
	}
	return first, last
}

func buildNetFlowV9Packet(sourceID uint32, templateID uint16, seq uint32, uptime uint32, now time.Time, record []byte, includeTemplate bool) []byte {
	var buf bytes.Buffer
	count := uint16(1)
	if includeTemplate {
		count++
	}

	binary.Write(&buf, binary.BigEndian, uint16(9))
	binary.Write(&buf, binary.BigEndian, count)
	binary.Write(&buf, binary.BigEndian, uptime)
	binary.Write(&buf, binary.BigEndian, uint32(now.Unix()))
	binary.Write(&buf, binary.BigEndian, seq)
	binary.Write(&buf, binary.BigEndian, sourceID)

	if includeTemplate {
		templateFlowset := buildTemplateFlowset(templateID)
		buf.Write(templateFlowset)
	}

	dataFlowset := buildDataFlowset(templateID, record)
	buf.Write(dataFlowset)

	return buf.Bytes()
}

func buildTemplateFlowset(templateID uint16) []byte {
	// Template fields and lengths (bytes)
	fields := [][2]uint16{
		{1, 8},  // IN_BYTES
		{2, 8},  // IN_PKTS
		{4, 1},  // PROTOCOL
		{5, 1},  // TOS
		{6, 1},  // TCP_FLAGS
		{7, 2},  // L4_SRC_PORT
		{8, 4},  // IPV4_SRC_ADDR
		{10, 4}, // INPUT_SNMP
		{11, 2}, // L4_DST_PORT
		{12, 4}, // IPV4_DST_ADDR
		{14, 4}, // OUTPUT_SNMP
		{21, 4}, // LAST_SWITCHED
		{22, 4}, // FIRST_SWITCHED
	}

	length := 4 + 4 + len(fields)*4
	paddedLen := pad4(length)
	buf := bytes.NewBuffer(make([]byte, 0, paddedLen))
	binary.Write(buf, binary.BigEndian, uint16(0))
	binary.Write(buf, binary.BigEndian, uint16(paddedLen))
	binary.Write(buf, binary.BigEndian, templateID)
	binary.Write(buf, binary.BigEndian, uint16(len(fields)))
	for _, f := range fields {
		binary.Write(buf, binary.BigEndian, f[0])
		binary.Write(buf, binary.BigEndian, f[1])
	}
	if pad := paddedLen - length; pad > 0 {
		buf.Write(make([]byte, pad))
	}
	return buf.Bytes()
}

func buildDataFlowset(templateID uint16, record []byte) []byte {
	length := 4 + len(record)
	paddedLen := pad4(length)
	buf := bytes.NewBuffer(make([]byte, 0, paddedLen))
	binary.Write(buf, binary.BigEndian, templateID)
	binary.Write(buf, binary.BigEndian, uint16(paddedLen))
	buf.Write(record)
	if pad := paddedLen - length; pad > 0 {
		buf.Write(make([]byte, pad))
	}
	return buf.Bytes()
}

func pad4(length int) int {
	if rem := length % 4; rem != 0 {
		return length + (4 - rem)
	}
	return length
}

func encodeNetFlowV9Record(flow *flowpb.FlowMessage, first, last uint32) []byte {
	buf := bytes.NewBuffer(nil)
	binary.Write(buf, binary.BigEndian, uint64(flow.Bytes))
	binary.Write(buf, binary.BigEndian, uint64(flow.Packets))
	buf.WriteByte(byte(flow.Proto))
	buf.WriteByte(byte(flow.IpTos))
	buf.WriteByte(byte(flow.TcpFlags))
	binary.Write(buf, binary.BigEndian, uint16(flow.SrcPort))
	buf.Write(flow.SrcAddr)
	binary.Write(buf, binary.BigEndian, flow.InIf)
	binary.Write(buf, binary.BigEndian, uint16(flow.DstPort))
	buf.Write(flow.DstAddr)
	binary.Write(buf, binary.BigEndian, flow.OutIf)
	binary.Write(buf, binary.BigEndian, last)
	binary.Write(buf, binary.BigEndian, first)
	return buf.Bytes()
}
