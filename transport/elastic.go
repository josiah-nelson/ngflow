package transport

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type ElasticConfig struct {
	URL          string
	Index        string
	BulkSize     int
	BulkInterval time.Duration
	QueueSize    int
	Username     string
	Password     string
	APIKey       string
	Insecure     bool
}

type ElasticDriver struct {
	cfg    *ElasticConfig
	client *http.Client
	queue  chan []byte
	stopCh chan struct{}
	wg     sync.WaitGroup
}

func RegisterElasticWithConfig(cfg *ElasticConfig) {
	e := &ElasticDriver{cfg: cfg}
	transport.RegisterTransportDriver("elastic", e)
}

func (e *ElasticDriver) Prepare() error {
	return nil
}

func (e *ElasticDriver) Init() error {
	if e.cfg == nil {
		return fmt.Errorf("elastic config is required")
	}
	if strings.TrimSpace(e.cfg.URL) == "" {
		return fmt.Errorf("elastic url is required")
	}
	if e.cfg.BulkSize <= 0 {
		e.cfg.BulkSize = 1000
	}
	if e.cfg.BulkInterval <= 0 {
		e.cfg.BulkInterval = time.Second
	}
	if e.cfg.QueueSize <= 0 {
		e.cfg.QueueSize = 10000
	}

	tr := &http.Transport{}
	if e.cfg.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	e.client = &http.Client{Transport: tr, Timeout: 30 * time.Second}
	e.queue = make(chan []byte, e.cfg.QueueSize)
	e.stopCh = make(chan struct{})

	e.wg.Add(1)
	go e.loop()
	return nil
}

func (e *ElasticDriver) Send(_key, data []byte) error {
	if e.queue == nil {
		return fmt.Errorf("elastic queue not initialized")
	}
	select {
	case e.queue <- append([]byte(nil), data...):
		return nil
	default:
		return fmt.Errorf("elastic queue full")
	}
}

func (e *ElasticDriver) Close() error {
	if e.stopCh != nil {
		close(e.stopCh)
	}
	e.wg.Wait()
	return nil
}

func (e *ElasticDriver) loop() {
	defer e.wg.Done()

	ticker := time.NewTicker(e.cfg.BulkInterval)
	defer ticker.Stop()

	var buf bytes.Buffer
	docCount := 0

	flush := func() {
		if docCount == 0 {
			return
		}
		if err := e.flushBulk(buf.Bytes()); err != nil && log != nil {
			log.WithError(err).Warn("elastic bulk flush failed")
		}
		buf.Reset()
		docCount = 0
	}

	for {
		select {
		case <-e.stopCh:
			flush()
			return
		case <-ticker.C:
			flush()
		case doc := <-e.queue:
			writeBulkRecord(&buf, e.cfg.Index, doc)
			docCount++
			if docCount >= e.cfg.BulkSize {
				flush()
			}
		}
	}
}

func (e *ElasticDriver) flushBulk(payload []byte) error {
	endpoint := strings.TrimRight(e.cfg.URL, "/") + "/_bulk"
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")

	if e.cfg.APIKey != "" {
		req.Header.Set("Authorization", "ApiKey "+e.cfg.APIKey)
	} else if e.cfg.Username != "" {
		req.SetBasicAuth(e.cfg.Username, e.cfg.Password)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("elastic bulk status %s", resp.Status)
	}
	return nil
}

func writeBulkRecord(buf *bytes.Buffer, index string, doc []byte) {
	if strings.TrimSpace(index) != "" {
		fmt.Fprintf(buf, "{ \"index\": { \"_index\": %q } }\n", index)
	} else {
		buf.WriteString("{ \"index\": {} }\n")
	}
	buf.Write(doc)
	buf.WriteByte('\n')
}
