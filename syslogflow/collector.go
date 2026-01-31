package syslogflow

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/josiah-nelson/ngflow/collector"
	flowpb "github.com/netsampler/goflow2/v2/pb"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type FlowRecord struct {
	Flow   *flowpb.FlowMessage
	Extras map[string]interface{}
}

type FlowHandler func(*FlowRecord) error

type Metrics struct {
	MessagesReceived prometheus.Counter
	FlowsDecoded     prometheus.Counter
	DecodeErrors     prometheus.Counter
	BytesReceived    prometheus.Counter
}

func NewMetrics(namespace string) *Metrics {
	return &Metrics{
		MessagesReceived: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "syslogflow",
			Name:      "messages_received_total",
			Help:      "Total syslog flow messages received",
		}),
		FlowsDecoded: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "syslogflow",
			Name:      "flows_decoded_total",
			Help:      "Total syslog flow records decoded",
		}),
		DecodeErrors: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "syslogflow",
			Name:      "decode_errors_total",
			Help:      "Total syslog flow decode errors",
		}),
		BytesReceived: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: "syslogflow",
			Name:      "bytes_received_total",
			Help:      "Total bytes received via syslog flow collection",
		}),
	}
}

type CollectorConfig struct {
	ListenAddr       string
	Network          string
	Format           string
	Handler          FlowHandler
	Metrics          *Metrics
	ExporterRegistry *collector.ExporterRegistry
}

type Collector struct {
	listenAddr string
	network    string
	format     string
	handler    FlowHandler
	metrics    *Metrics
	exporters  *collector.ExporterRegistry

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	conn   net.PacketConn
	listen net.Listener
}

func NewCollector(cfg *CollectorConfig) *Collector {
	ctx, cancel := context.WithCancel(context.Background())
	network := strings.ToLower(strings.TrimSpace(cfg.Network))
	if network == "" {
		network = "udp"
	}
	format := strings.ToLower(strings.TrimSpace(cfg.Format))
	if format == "" {
		format = "fortinet"
	}
	return &Collector{
		listenAddr: cfg.ListenAddr,
		network:    network,
		format:     format,
		handler:    cfg.Handler,
		metrics:    cfg.Metrics,
		exporters:  cfg.ExporterRegistry,
		ctx:        ctx,
		cancel:     cancel,
	}
}

func (c *Collector) Start() error {
	if c.listenAddr == "" {
		return fmt.Errorf("syslog flow listen address is required")
	}

	switch c.network {
	case "udp":
		conn, err := net.ListenPacket("udp", c.listenAddr)
		if err != nil {
			return err
		}
		c.conn = conn
		c.wg.Add(1)
		go c.udpLoop()
	case "tcp":
		ln, err := net.Listen("tcp", c.listenAddr)
		if err != nil {
			return err
		}
		c.listen = ln
		c.wg.Add(1)
		go c.tcpLoop()
	default:
		return fmt.Errorf("unsupported syslog flow network: %s", c.network)
	}
	return nil
}

func (c *Collector) Stop() {
	c.cancel()
	if c.conn != nil {
		_ = c.conn.Close()
	}
	if c.listen != nil {
		_ = c.listen.Close()
	}
	c.wg.Wait()
}

func (c *Collector) udpLoop() {
	defer c.wg.Done()

	buf := make([]byte, 65535)
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		n, addr, err := c.conn.ReadFrom(buf)
		if err != nil {
			if c.ctx.Err() != nil {
				return
			}
			continue
		}
		if c.metrics != nil {
			c.metrics.MessagesReceived.Inc()
			c.metrics.BytesReceived.Add(float64(n))
		}
		if addr != nil {
			if udpAddr, ok := addr.(*net.UDPAddr); ok && c.exporters != nil {
				c.exporters.RecordPacket(udpAddr.IP, 0, n)
			}
		}
		c.handleMessage(buf[:n], addr)
	}
}

func (c *Collector) tcpLoop() {
	defer c.wg.Done()
	for {
		conn, err := c.listen.Accept()
		if err != nil {
			if c.ctx.Err() != nil {
				return
			}
			continue
		}
		c.wg.Add(1)
		go c.handleConn(conn)
	}
}

func (c *Collector) handleConn(conn net.Conn) {
	defer c.wg.Done()
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if c.metrics != nil {
			c.metrics.MessagesReceived.Inc()
			c.metrics.BytesReceived.Add(float64(len(line)))
		}
		if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok && c.exporters != nil {
			c.exporters.RecordPacket(tcpAddr.IP, 0, len(line))
		}
		c.handleMessage(line, conn.RemoteAddr())
	}
}

func (c *Collector) handleMessage(payload []byte, remote net.Addr) {
	record, err := ParseMessage(c.format, payload)
	if err != nil {
		if c.metrics != nil {
			c.metrics.DecodeErrors.Inc()
		}
		return
	}
	if record.Flow == nil {
		return
	}
	if record.Flow.SamplerAddress == nil && remote != nil {
		if udpAddr, ok := remote.(*net.UDPAddr); ok {
			record.Flow.SamplerAddress = udpAddr.IP
		} else if tcpAddr, ok := remote.(*net.TCPAddr); ok {
			record.Flow.SamplerAddress = tcpAddr.IP
		}
	}
	if c.handler != nil {
		if err := c.handler(record); err == nil {
			if c.metrics != nil {
				c.metrics.FlowsDecoded.Inc()
			}
		}
	}
}
