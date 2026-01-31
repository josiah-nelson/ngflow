# netflow2ng

High-throughput NetFlow v9/IPFIX/sFlow collector for [ntopng](https://www.ntop.org/products/traffic-analysis/ntop/)

[![Tests](https://github.com/josiah-nelson/ngflow/actions/workflows/tests.yml/badge.svg)](https://github.com/josiah-nelson/ngflow/actions/workflows/tests.yml)
[![codeql-analysis.yml](https://github.com/josiah-nelson/ngflow/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/josiah-nelson/ngflow/actions/workflows/codeql-analysis.yml)
[![golangci-lint](https://github.com/josiah-nelson/ngflow/actions/workflows/golangci-lint.yaml/badge.svg)](https://github.com/josiah-nelson/ngflow/actions/workflows/golangci-lint.yaml)

## Overview

ntopng is a free/commercial network traffic analysis console suitable for a variety of use cases. However, if you want to collect NetFlow, IPFIX, or sFlow data and load it into ntopng, you typically need [nProbe](https://www.ntop.org/products/netflow/nprobe/) which may be cost-prohibitive for home/SOHO use.

**netflow2ng** provides a high-performance, open-source alternative optimized for:
- Predictable but high-bandwidth environments (cameras, NVRs, intercoms, switches)
- Collector mode with ZMQ publisher interoperability with ntopng
- Per-exporter sampling rate tracking and upscaling
- Multi-endpoint ZMQ fan-out for scaling

## Features

### Protocol Support
- **NetFlow v9** - Full template-based support
- **IPFIX (NetFlow v10)** - Full support including options templates
- **sFlow v5** - Native packet sampling support

### Performance Features
- **Fixed worker pool** with bounded queue (no goroutine per packet)
- **sync.Pool** for byte buffers to reduce GC pressure
- **Ring buffer** for efficient packet queuing
- **Metrics** for queue depth, drops, and per-exporter throughput

### Sampling & Accuracy
- **Automatic sampling rate detection** from:
  - IPFIX options templates
  - sFlow datagram headers
- **Configurable upscaling** of bytes/packets before sending to ntopng
- **Manual rate override** for exporters that pre-scale

### Flow Relay / Fan-out
- **Multi-endpoint ZMQ** publishing to multiple ntopng instances
- **Hash-based distribution** (exporter + 5-tuple) for flow affinity
- **Round-robin distribution** for load balancing

### Output Backends
- **Kafka** producer for flow JSON/TLV
- **ElasticSearch** bulk indexing (NDJSON)
- **Syslog** RFC5424 forwarding

> **Note:** ElasticSearch and Syslog outputs require `--format=json` or `--format=jcompress`.

### Protocol Proxy & Conversion
- **Raw NetFlow/IPFIX proxy** for packet mirroring
- **Raw sFlow proxy** for external collectors
- **sFlow → NetFlow v9** conversion for legacy tooling

> **sFlow → NetFlow v9 limitation:** only IPv4 records are exported; IPv6 sFlow samples are skipped.

### Deduplication
- **Per-exporter dedup cache** with configurable TTL and size bounds
- **Heuristics** to avoid false positives on long-lived flows

### Vendor Exporters
- **Extreme Networks** templates, configuration examples, and exporter gotchas in [docs/extreme-networks.md](docs/extreme-networks.md)

### Flow Enrichment
- **SNMP interface metadata** - ifName, ifAlias, ifSpeed mapping from ifIndex
- **Application telemetry classification** - nDPI-style categories from IPFIX app telemetry
- **L7 port heuristics** - SIP, RTP/RTCP, DNS, DHCP, SSH, SNMP, NTP (no payload inspection)
- **VoIP/QoS metrics** - bitrate, PPS, avg packet size, codec guess for voice/audio flows

## Installation

### Build From Source

```bash
# Ensure you have Go 1.23+ and libzmq development files
apt-get install libzmq3-dev  # Debian/Ubuntu
brew install zeromq          # macOS

git clone https://github.com/josiah-nelson/ngflow.git
cd ngflow
make
# Binary will be in dist/
```

### Docker

```bash
git clone https://github.com/josiah-nelson/ngflow.git
cd ngflow
docker compose up
```

**Important**: When using Docker, you must use host networking due to NAT causing the source port to change for inbound flow packets.

## Configuration

### Command Line Options

```
Usage: netflow2ng [flags]

High-throughput NetFlow v9/IPFIX/sFlow collector for ntopng

Flags:
  -h, --help                      Show context-sensitive help.

NetFlow/IPFIX Configuration:
  -a, --listen=0.0.0.0:2055       NetFlow/IPFIX listen address:port
      --reuse                     Enable SO_REUSEPORT for NetFlow/IPFIX listen port
  -w, --workers=2                 Number of NetFlow workers

sFlow Configuration:
      --sflow-listen=ADDRESS      sFlow listen address:port (empty to disable)
      --sflow-workers=2           Number of sFlow workers

Metrics/Health:
  -m, --metrics=0.0.0.0:8080      Metrics listen address

ZMQ Configuration:
  -z, --listen-zmq="tcp://*:5556" ZMQ bind address(es), comma-separated for fan-out
      --fanout-strategy="hash"    ZMQ fan-out strategy [hash|round-robin]
      --topic="flow"              ZMQ Topic
      --source-id=0               NetFlow SourceId (0-255)
  -f, --format="tlv"              Output format [tlv|json|jcompress]
      --outputs="zmq"             Comma-separated outputs: zmq,kafka,elastic,syslog

Kafka Output Configuration:
      --kafka-brokers=STRING      Kafka brokers (comma-separated)
      --kafka-topic=STRING        Kafka topic for flow messages
      --kafka-batch-bytes=INT     Kafka batch size in bytes
      --kafka-batch-timeout=DUR   Kafka batch timeout
      --kafka-required-acks=INT   Kafka required acks (-1 all, 0 none, 1 leader)
      --kafka-compression=STRING  Kafka compression [none|gzip|snappy|lz4|zstd]

Elastic Output Configuration:
      --elastic-url=STRING        ElasticSearch base URL
      --elastic-index=STRING      ElasticSearch index name
      --elastic-bulk-size=INT     ElasticSearch bulk size (documents per flush)
      --elastic-bulk-interval=DUR ElasticSearch bulk flush interval
      --elastic-queue-size=INT    ElasticSearch queue size
      --elastic-username=STRING   ElasticSearch username
      --elastic-password=STRING   ElasticSearch password
      --elastic-api-key=STRING    ElasticSearch API key (base64)
      --elastic-insecure          Skip TLS verification for ElasticSearch

Syslog Output Configuration:
      --syslog-addr=STRING        Syslog destination address (host:port)
      --syslog-network="udp"      Syslog network [udp|tcp]
      --syslog-facility=INT       Syslog facility (0-23)
      --syslog-severity=INT       Syslog severity (0-7)
      --syslog-hostname=STRING    Syslog hostname override
      --syslog-app-name=STRING    Syslog app name
      --syslog-procid=STRING      Syslog procid
      --syslog-msgid=STRING       Syslog msgid

Sampling Configuration:
      --disable-upscaling         Disable sampling rate upscaling (use when exporters pre-scale)
      --default-sample-rate=1     Default sampling rate when not reported by exporter

Enrichment Configuration:
      --snmp-enabled              Enable SNMP interface enrichment
      --snmp-community="public"   SNMP community string
      --snmp-port=161             SNMP port
      --snmp-version="2c"         SNMP version (2c only)
      --snmp-timeout=2s           SNMP timeout per request
      --snmp-retries=1            SNMP retry count
      --snmp-poll-interval=5m     SNMP interface poll interval
      --snmp-auto-discover        Auto-discover exporters for SNMP polling

nDPI Configuration:
      --ndpi-enabled              Enable nDPI classification from application telemetry
      --ndpi-categories="sip,video,audio,control,services"
                                  Comma-separated list of allowed nDPI categories

L7 Configuration:
      --l7-enabled                Enable L7 application classification (port heuristics)
      --l7-categories="voice,video,audio,control,services,other"
                                  Comma-separated list of allowed L7 categories

Deduplication Configuration:
      --dedup-enabled             Enable flow deduplication
      --dedup-max-size=100000     Maximum dedup cache size
      --dedup-ttl=60s             Dedup cache entry TTL

Queue Configuration:
      --queue-size=1000000        Packet queue size

Proxy / Conversion:
      --proxy-netflow=STRING      Forward raw NetFlow/IPFIX datagrams to host:port list
      --proxy-sflow=STRING        Forward raw sFlow datagrams to host:port list
      --sflow-to-netflow=STRING   Export sFlow as NetFlow v9 to host:port list
      --sflow-template-id=INT     NetFlow v9 template ID for sFlow conversion
      --sflow-template-refresh=DUR
                                  NetFlow v9 template refresh interval

Syslog Flow Collection:
      --syslog-flow-listen=ADDR   Syslog flow listen address:port (empty to disable)
      --syslog-flow-network="udp" Syslog flow network [udp|tcp]
      --syslog-flow-format="fortinet"
                                  Syslog flow format [fortinet|json]

Logging:
  -l, --log-level="info"          Log level [error|warn|info|debug|trace]
      --log-format="default"      Log format [default|json]

  -v, --version                   Print version and copyright info
```

### Examples

#### Basic Usage (NetFlow/IPFIX only)

```bash
netflow2ng -a 0.0.0.0:2055 -z tcp://*:5556
```

#### With sFlow Support

```bash
netflow2ng -a 0.0.0.0:2055 --sflow-listen 0.0.0.0:6343 -z tcp://*:5556
```

#### Kafka + Elastic Fan-out

```bash
netflow2ng -a 0.0.0.0:2055 \
  --format json \
  --outputs zmq,kafka,elastic \
  --kafka-brokers localhost:9092 --kafka-topic flows \
  --elastic-url http://localhost:9200 --elastic-index netflow2ng-flows
```

#### Syslog Flow Collection (Fortinet)

```bash
netflow2ng --syslog-flow-listen 0.0.0.0:5514 --syslog-flow-format fortinet
```

#### Syslog Flow Collection (JSON)

```bash
netflow2ng --syslog-flow-listen 0.0.0.0:5514 --syslog-flow-format json
```

### Syslog Flow Parsing Notes

Fortinet format expects `key=value` fields (e.g., `srcip`, `dstip`, `srcport`, `dstport`, `proto`, `sentbyte`, `rcvdbyte`, `sentpkt`, `rcvdpkt`, `duration`, `eventtime`).
JSON format extracts common fields (e.g., `srcip`, `dstip`, `srcport`, `dstport`, `protocol`, `bytes`, `packets`, `start`, `end`, `duration`, `@timestamp`) and stores remaining fields under `syslog.*`.

#### Multi-Endpoint Fan-out (Hash-based)

Distribute flows across multiple ntopng instances with flow affinity:

```bash
netflow2ng -a 0.0.0.0:2055 \
  -z "tcp://*:5556,tcp://*:5557,tcp://*:5558" \
  --fanout-strategy hash
```

#### Multi-Endpoint Fan-out (Round-Robin)

Load balance across ntopng instances:

```bash
netflow2ng -a 0.0.0.0:2055 \
  -z "tcp://*:5556,tcp://*:5557" \
  --fanout-strategy round-robin
```

#### With Sampling Upscaling Disabled

Use when your exporters already account for sampling in reported values:

```bash
netflow2ng -a 0.0.0.0:2055 --disable-upscaling
```

#### With Deduplication Enabled

Enable flow deduplication to suppress duplicate flow records:

```bash
netflow2ng -a 0.0.0.0:2055 \
  --dedup-enabled \
  --dedup-max-size 200000 \
  --dedup-ttl 120s
```

#### With SNMP Enrichment and L7 Classification

Enable SNMP interface metadata plus app telemetry and L7 port heuristics:

```bash
netflow2ng -a 0.0.0.0:2055 \
  --snmp-enabled \
  --snmp-community "public" \
  --snmp-poll-interval 5m \
  --snmp-auto-discover \
  --ndpi-categories "sip,video,audio,control,services" \
  --l7-enabled
```

See [docs/extreme-networks.md](docs/extreme-networks.md) for Extreme Networks templates and exporter notes.

#### High-Throughput Configuration

For high-volume environments:

```bash
netflow2ng -a 0.0.0.0:2055 \
  --sflow-listen 0.0.0.0:6343 \
  -w 8 \
  --sflow-workers 4 \
  --queue-size 2000000 \
  -z "tcp://*:5556,tcp://*:5557" \
  --fanout-strategy hash \
  --dedup-enabled \
  --dedup-max-size 500000
```

### ntopng Configuration

Configure ntopng to subscribe to netflow2ng:

```bash
ntopng -i tcp://192.168.1.1:5556
```

For multi-endpoint setups, run multiple ntopng instances or use ntopng's multi-interface support:

```bash
ntopng -i tcp://192.168.1.1:5556 -i tcp://192.168.1.1:5557
```

## HTTP Endpoints

netflow2ng exposes several HTTP endpoints on the metrics port (default 8080):

| Endpoint | Description |
|----------|-------------|
| `/__health` | Health check (503 until collecting, 200 when ready) |
| `/metrics` | Prometheus metrics |
| `/templates` | NetFlow/IPFIX template cache (JSON) |
| `/sampling` | Per-exporter sampling rate information (JSON) |
| `/dedup` | Deduplication cache statistics (JSON, if enabled) |
| `/exporters` | Exporter statistics snapshot (JSON) |

Notes:
- `/exporters` reports UDP packet/byte counts from raw datagrams, while flow counts are post-dedup decoded flows.

## Prometheus Metrics

netflow2ng exports comprehensive Prometheus metrics:

### Queue Metrics
- `netflow2ng_packets_received_total` - Total packets received
- `netflow2ng_packets_processed_total` - Total packets processed
- `netflow2ng_packets_dropped_total` - Packets dropped due to queue overflow
- `netflow2ng_queue_depth` - Current queue depth
- `netflow2ng_workers_busy` - Number of workers currently processing

### Exporter Metrics
- `netflow2ng_exporter_packets_received_total{exporter_ip,source_id}` - Per-exporter packets
- `netflow2ng_exporter_bytes_received_total{exporter_ip,source_id}` - Per-exporter bytes
- `netflow2ng_exporter_flows_processed_total{exporter_ip,source_id}` - Per-exporter flows

### Sampling Metrics
- `netflow2ng_sampling_rate{exporter_ip,observation_domain,source}` - Current sampling rate
- `netflow2ng_sampling_scaled_bytes_total{exporter_ip}` - Bytes added by upscaling
- `netflow2ng_sampling_scaled_packets_total{exporter_ip}` - Packets added by upscaling

### ZMQ Metrics
- `netflow2ng_zmq_messages_sent_total{endpoint}` - Messages sent per endpoint
- `netflow2ng_zmq_bytes_sent_total{endpoint}` - Bytes sent per endpoint
- `netflow2ng_zmq_errors_total{endpoint,error_type}` - Errors per endpoint
- `netflow2ng_zmq_endpoints_active` - Number of active endpoints

### Deduplication Metrics (when enabled)
- `netflow2ng_dedup_cache_hits_total` - Cache hits (potential duplicates)
- `netflow2ng_dedup_cache_misses_total` - Cache misses (new flows)
- `netflow2ng_dedup_duplicates_total` - Actual duplicates suppressed
- `netflow2ng_dedup_cache_size` - Current cache size
- `netflow2ng_dedup_evictions_total` - Evictions due to size limit
- `netflow2ng_dedup_expired_evictions_total` - Evictions due to TTL

### sFlow Metrics (when enabled)
- `netflow2ng_sflow_datagrams_received_total` - sFlow datagrams received
- `netflow2ng_sflow_samples_decoded_total` - sFlow samples decoded
- `netflow2ng_sflow_flows_produced_total` - Flow messages produced
- `netflow2ng_sflow_decode_errors_total` - Decode errors

## Architecture

```
┌─────────────────┐     ┌─────────────────┐
│ NetFlow/IPFIX   │     │     sFlow       │
│   Exporters     │     │   Exporters     │
└────────┬────────┘     └────────┬────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐     ┌─────────────────┐
│  UDP Receiver   │     │  UDP Receiver   │
│  (port 2055)    │     │  (port 6343)    │
└────────┬────────┘     └────────┬────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐     ┌─────────────────┐
│   Ring Buffer   │     │   Ring Buffer   │
└────────┬────────┘     └────────┬────────┘
         │                       │
         ▼                       ▼
┌─────────────────┐     ┌─────────────────┐
│  Worker Pool    │     │  Worker Pool    │
│  (decode/prod)  │     │  (decode/prod)  │
└────────┬────────┘     └────────┬────────┘
         │                       │
         └───────────┬───────────┘
                     │
                     ▼
         ┌─────────────────────┐
         │  Sampling Tracker   │
         │  (upscale if enabled)│
         └──────────┬──────────┘
                    │
                    ▼
         ┌─────────────────────┐
         │  Dedup Cache        │
         │  (if enabled)       │
         └──────────┬──────────┘
                    │
                    ▼
         ┌─────────────────────┐
         │  Formatter          │
         │  (TLV/JSON)         │
         └──────────┬──────────┘
                    │
                    ▼
         ┌─────────────────────┐
         │  ZMQ Publisher      │
         │  (fan-out)          │
         └──────────┬──────────┘
                    │
         ┌──────────┼──────────┐
         ▼          ▼          ▼
    ┌────────┐ ┌────────┐ ┌────────┐
    │ntopng 1│ │ntopng 2│ │ntopng 3│
    └────────┘ └────────┘ └────────┘
```

## Deduplication Heuristics

The deduplication cache uses several heuristics to avoid false positives:

1. **Flow identification**: Flows are keyed by exporter IP + 5-tuple (src/dst IP, ports, protocol)
2. **Update detection**: Flows with increased bytes/packets are not considered duplicates
3. **Sequence tracking**: Flows with advancing sequence numbers pass through
4. **Long-lived flow handling**: Periodic updates for flows active longer than TTL are allowed

This ensures that legitimate flow updates are not suppressed while true duplicates (same packet reported multiple times) are filtered.

## Ports

Default listening ports (configurable via flags):

| Port | Protocol | Description |
|------|----------|-------------|
| 2055 | UDP | NetFlow v9/IPFIX |
| 6343 | UDP | sFlow (when enabled) |
| 5556 | TCP | ZMQ Publisher |
| 8080 | TCP | Metrics/Health/Templates |

## Differences from nProbe

| Feature | netflow2ng | nProbe |
|---------|-----------|--------|
| Price | Free | 199 Euro |
| Probe mode | No | Yes |
| Collector mode | Yes | Yes |
| NetFlow v5 | No | Yes |
| NetFlow v9 | Yes | Yes |
| IPFIX | Yes | Yes |
| sFlow | Yes | Yes |
| Multi-endpoint fan-out | Yes | Via configuration |
| Sampling upscaling | Yes | Yes |
| Deduplication | Yes | Yes |
| MySQL/disk export | No | Yes |
| Commercial support | No | Yes |

## Contributing

Contributions are welcome! Please ensure:
1. Code passes `go vet` and `golangci-lint`
2. New features include tests
3. Documentation is updated

## License

See [LICENSE](LICENSE) file.
