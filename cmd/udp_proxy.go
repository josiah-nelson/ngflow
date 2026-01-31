package main

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

type udpProxy struct {
	conns []*net.UDPConn
	mu    sync.Mutex
}

func newUDPProxy(targets string) (*udpProxy, error) {
	parts := parseCSV(targets)
	if len(parts) == 0 {
		return nil, nil
	}

	proxy := &udpProxy{}
	for _, raw := range parts {
		addr := strings.TrimSpace(raw)
		addr = strings.TrimPrefix(addr, "udp://")
		if addr == "" {
			continue
		}
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, fmt.Errorf("invalid udp proxy target %s: %w", addr, err)
		}
		conn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to dial udp proxy target %s: %w", addr, err)
		}
		proxy.conns = append(proxy.conns, conn)
	}
	if len(proxy.conns) == 0 {
		return nil, nil
	}
	return proxy, nil
}

func (p *udpProxy) Send(payload []byte) {
	if p == nil || len(p.conns) == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, conn := range p.conns {
		if conn != nil {
			_, _ = conn.Write(payload)
		}
	}
}

func (p *udpProxy) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, conn := range p.conns {
		if conn != nil {
			_ = conn.Close()
		}
	}
	p.conns = nil
}
