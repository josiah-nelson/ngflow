package transport

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type SyslogConfig struct {
	Network  string
	Address  string
	Facility int
	Severity int
	Hostname string
	AppName  string
	ProcID   string
	MsgID    string
}

type SyslogDriver struct {
	cfg  *SyslogConfig
	conn net.Conn
	mu   sync.Mutex
}

func RegisterSyslogWithConfig(cfg *SyslogConfig) {
	s := &SyslogDriver{cfg: cfg}
	transport.RegisterTransportDriver("syslog", s)
}

func (s *SyslogDriver) Prepare() error {
	return nil
}

func (s *SyslogDriver) Init() error {
	if s.cfg == nil {
		return fmt.Errorf("syslog config is required")
	}
	if strings.TrimSpace(s.cfg.Address) == "" {
		return fmt.Errorf("syslog address is required")
	}
	if s.cfg.Network == "" {
		s.cfg.Network = "udp"
	}
	if s.cfg.Hostname == "" {
		host, _ := os.Hostname()
		s.cfg.Hostname = host
	}
	if s.cfg.AppName == "" {
		s.cfg.AppName = "netflow2ng"
	}
	if s.cfg.ProcID == "" {
		s.cfg.ProcID = "-"
	}
	if s.cfg.MsgID == "" {
		s.cfg.MsgID = "flow"
	}

	conn, err := net.Dial(s.cfg.Network, s.cfg.Address)
	if err != nil {
		return err
	}
	s.conn = conn
	return nil
}

func (s *SyslogDriver) Send(_key, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn == nil {
		return fmt.Errorf("syslog connection not initialized")
	}

	pri := s.cfg.Facility*8 + s.cfg.Severity
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	msg := fmt.Sprintf("<%d>1 %s %s %s %s %s - %s", pri, ts, s.cfg.Hostname, s.cfg.AppName, s.cfg.ProcID, s.cfg.MsgID, string(data))
	if s.cfg.Network == "tcp" || strings.HasPrefix(s.cfg.Network, "tcp") {
		msg += "\n"
	}
	_, err := s.conn.Write([]byte(msg))
	if err != nil && (s.cfg.Network == "tcp" || strings.HasPrefix(s.cfg.Network, "tcp")) {
		if conn, dialErr := net.Dial(s.cfg.Network, s.cfg.Address); dialErr == nil {
			s.conn = conn
			_, err = s.conn.Write([]byte(msg))
		}
	}
	return err
}

func (s *SyslogDriver) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}
