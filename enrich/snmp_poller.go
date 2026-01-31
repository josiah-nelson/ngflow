package enrich

import (
	"context"
	"net"
	"sync"
	"time"
)

type SNMPPoller struct {
	cache        *InterfaceCache
	fetcher      InterfaceFetcher
	pollInterval time.Duration
	mu           sync.Mutex
	exporters    map[string]time.Time
	started      bool
}

func NewSNMPPoller(cache *InterfaceCache, fetcher InterfaceFetcher, pollInterval time.Duration) *SNMPPoller {
	if pollInterval <= 0 {
		pollInterval = 5 * time.Minute
	}
	return &SNMPPoller{
		cache:        cache,
		fetcher:      fetcher,
		pollInterval: pollInterval,
		exporters:    make(map[string]time.Time),
	}
}

func (p *SNMPPoller) ObserveExporter(exporterIP net.IP) {
	if p == nil || p.fetcher == nil {
		return
	}
	if exporterIP == nil {
		return
	}
	target := exporterIP.String()
	if target == "" {
		return
	}

	p.mu.Lock()
	if _, exists := p.exporters[target]; !exists {
		p.exporters[target] = time.Time{}
	}
	p.mu.Unlock()
}

func (p *SNMPPoller) Start(ctx context.Context) {
	if p == nil || p.fetcher == nil {
		return
	}
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return
	}
	p.started = true
	p.mu.Unlock()

	go func() {
		ticker := time.NewTicker(p.pollInterval / 2)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				p.pollDue()
			}
		}
	}()
}

func (p *SNMPPoller) pollDue() {
	now := time.Now()

	p.mu.Lock()
	targets := make(map[string]time.Time, len(p.exporters))
	for target, nextPoll := range p.exporters {
		targets[target] = nextPoll
	}
	p.mu.Unlock()

	for target, nextPoll := range targets {
		if !nextPoll.IsZero() && now.Before(nextPoll) {
			continue
		}

		entries, err := p.fetcher.Fetch(target)
		next := now.Add(p.pollInterval)
		if err != nil {
			log.WithError(err).WithField("target", target).Warn("snmp poll failed")
			p.setNextPoll(target, next)
			continue
		}
		if p.cache != nil {
			p.cache.Update(target, entries)
		}
		p.setNextPoll(target, next)
		log.WithField("target", target).Debug("snmp interface metadata refreshed")
	}
}

func (p *SNMPPoller) setNextPoll(target string, next time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.exporters[target]; ok {
		p.exporters[target] = next
	}
}
