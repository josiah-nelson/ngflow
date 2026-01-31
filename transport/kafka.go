package transport

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
)

type KafkaConfig struct {
	Brokers      []string
	Topic        string
	BatchBytes   int
	BatchTimeout time.Duration
	RequiredAcks int
	Compression  string
}

type KafkaDriver struct {
	cfg    *KafkaConfig
	writer *kafka.Writer
}

func RegisterKafkaWithConfig(cfg *KafkaConfig) {
	k := &KafkaDriver{cfg: cfg}
	transport.RegisterTransportDriver("kafka", k)
}

func (k *KafkaDriver) Prepare() error {
	return nil
}

func (k *KafkaDriver) Init() error {
	if k.cfg == nil {
		return fmt.Errorf("kafka config is required")
	}
	if len(k.cfg.Brokers) == 0 {
		return fmt.Errorf("kafka brokers are required")
	}
	if strings.TrimSpace(k.cfg.Topic) == "" {
		return fmt.Errorf("kafka topic is required")
	}

	writer := &kafka.Writer{
		Addr:         kafka.TCP(k.cfg.Brokers...),
		Topic:        k.cfg.Topic,
		BatchBytes:   k.cfg.BatchBytes,
		BatchTimeout: k.cfg.BatchTimeout,
		RequiredAcks: kafka.RequiredAcks(k.cfg.RequiredAcks),
	}

	switch strings.ToLower(strings.TrimSpace(k.cfg.Compression)) {
	case "", "none":
		// no compression
	case "gzip":
		writer.Compression = kafka.Gzip
	case "snappy":
		writer.Compression = kafka.Snappy
	case "lz4":
		writer.Compression = kafka.Lz4
	case "zstd":
		writer.Compression = kafka.Zstd
	default:
		return fmt.Errorf("unsupported kafka compression: %s", k.cfg.Compression)
	}

	k.writer = writer
	return nil
}

func (k *KafkaDriver) Send(key, data []byte) error {
	if k.writer == nil {
		return fmt.Errorf("kafka writer not initialized")
	}
	msg := kafka.Message{
		Key:   key,
		Value: data,
		Time:  time.Now(),
	}
	return k.writer.WriteMessages(context.Background(), msg)
}

func (k *KafkaDriver) Close() error {
	if k.writer != nil {
		return k.writer.Close()
	}
	return nil
}
