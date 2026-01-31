package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/josiah-nelson/ngflow/collector"
	"github.com/josiah-nelson/ngflow/converter"
	"github.com/josiah-nelson/ngflow/dedup"
	"github.com/josiah-nelson/ngflow/enrich"
	localformatters "github.com/josiah-nelson/ngflow/formatter"
	"github.com/josiah-nelson/ngflow/sampling"
	"github.com/josiah-nelson/ngflow/sflow"
	"github.com/josiah-nelson/ngflow/syslogflow"
	localtransport "github.com/josiah-nelson/ngflow/transport"
	"gopkg.in/yaml.v3"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	"github.com/netsampler/goflow2/v2/decoders/netflow"
	"github.com/netsampler/goflow2/v2/format"
	_ "github.com/netsampler/goflow2/v2/format/json"
	"github.com/netsampler/goflow2/v2/metrics"
	"github.com/netsampler/goflow2/v2/producer"
	protoproducer "github.com/netsampler/goflow2/v2/producer/proto"
	"github.com/netsampler/goflow2/v2/transport"
	_ "github.com/netsampler/goflow2/v2/transport/file"
	"github.com/netsampler/goflow2/v2/utils"
	"github.com/netsampler/goflow2/v2/utils/debug"
)

var (
	COPYRIGHT_YEAR string = "2020-2026"
	Version        string = "unknown"
	Buildinfos     string = "unknown"
	Delta          string = ""
	CommitID       string = "unknown"
	Tag            string = "NO-TAG"
	log            *logrus.Logger
	rctx           RunContext
)

const (
	METRICS_NAMESPACE = "netflow2ng"
)

type RunContext struct {
	Kctx *kong.Context
	cli  CLI
}

type SourceId int

func (s *SourceId) Validate() error {
	if *s < 0 || *s > 255 {
		return fmt.Errorf("must be between 0 and 255")
	}
	return nil
}

type Address string

func (a *Address) Value() (string, int) {
	var port int64
	var err error

	listen := strings.SplitN(string(*a), ":", 2)
	if port, err = strconv.ParseInt(listen[1], 10, 16); err != nil {
		log.Fatalf("Unable to parse: --listen %s", string(*a))
	}
	return listen[0], int(port)
}

type CLI struct {
	// NetFlow/IPFIX Configuration
	Listen  Address `short:"a" help:"NetFlow/IPFIX listen address:port" default:"0.0.0.0:2055"`
	Reuse   bool    `help:"Enable SO_REUSEPORT for NetFlow/IPFIX listen port"`
	Workers int     `short:"w" help:"Number of NetFlow workers" default:"2"`

	// sFlow Configuration
	SFlowListen  Address `help:"sFlow listen address:port (empty to disable)" default:""`
	SFlowWorkers int     `help:"Number of sFlow workers" default:"2"`

	// Metrics/Health
	Metrics Address `short:"m" help:"Metrics listen address" default:"0.0.0.0:8080"`

	// ZMQ Configuration
	ListenZmq      string   `short:"z" help:"ZMQ bind address(es), comma-separated for fan-out" default:"tcp://*:5556"`
	FanoutStrategy string   `help:"ZMQ fan-out strategy [hash|round-robin]" enum:"hash,round-robin" default:"hash"`
	Topic          string   `help:"ZMQ Topic" default:"flow"`
	SourceId       SourceId `help:"NetFlow SourceId (0-255)" default:"0"`
	Format         string   `short:"f" help:"Output format [tlv|json|jcompress]." enum:"tlv,json,jcompress" default:"tlv"`
	Outputs        string   `help:"Comma-separated outputs: zmq,kafka,elastic,syslog" default:"zmq"`

	// Kafka Output Configuration
	KafkaBrokers      string        `help:"Kafka brokers (comma-separated)"`
	KafkaTopic        string        `help:"Kafka topic for flow messages"`
	KafkaBatchBytes   int           `help:"Kafka batch size in bytes" default:"1048576"`
	KafkaBatchTimeout time.Duration `help:"Kafka batch timeout" default:"1s"`
	KafkaRequiredAcks int           `help:"Kafka required acks (-1 all, 0 none, 1 leader)" default:"-1"`
	KafkaCompression  string        `help:"Kafka compression [none|gzip|snappy|lz4|zstd]" default:"none"`

	// Elastic Output Configuration
	ElasticURL          string        `help:"ElasticSearch base URL (e.g. http://localhost:9200)"`
	ElasticIndex        string        `help:"ElasticSearch index name" default:"netflow2ng-flows"`
	ElasticBulkSize     int           `help:"ElasticSearch bulk size (documents per flush)" default:"1000"`
	ElasticBulkInterval time.Duration `help:"ElasticSearch bulk flush interval" default:"1s"`
	ElasticQueueSize    int           `help:"ElasticSearch queue size" default:"10000"`
	ElasticUsername     string        `help:"ElasticSearch username"`
	ElasticPassword     string        `help:"ElasticSearch password"`
	ElasticAPIKey       string        `help:"ElasticSearch API key (base64)"`
	ElasticInsecure     bool          `help:"Skip TLS verification for ElasticSearch"`

	// Syslog Output Configuration
	SyslogAddr     string `help:"Syslog destination address (host:port)"`
	SyslogNetwork  string `help:"Syslog network [udp|tcp]" default:"udp"`
	SyslogFacility int    `help:"Syslog facility (0-23)" default:"16"`
	SyslogSeverity int    `help:"Syslog severity (0-7)" default:"6"`
	SyslogHostname string `help:"Syslog hostname override (default: system hostname)"`
	SyslogAppName  string `help:"Syslog app name" default:"netflow2ng"`
	SyslogProcID   string `help:"Syslog procid" default:"-"`
	SyslogMsgID    string `help:"Syslog msgid" default:"flow"`

	// Sampling Configuration
	DisableUpscaling  bool `help:"Disable sampling rate upscaling (use when exporters pre-scale)"`
	DefaultSampleRate int  `help:"Default sampling rate when not reported by exporter" default:"1"`

	// Enrichment Configuration
	SNMPEnabled      bool          `help:"Enable SNMP interface enrichment" default:"false"`
	SNMPCommunity    string        `help:"SNMP community string" default:"public"`
	SNMPPort         uint16        `help:"SNMP port" default:"161"`
	SNMPVersion      string        `help:"SNMP version (2c only)" default:"2c"`
	SNMPTimeout      time.Duration `help:"SNMP timeout per request" default:"2s"`
	SNMPRetries      int           `help:"SNMP retry count" default:"1"`
	SNMPPollInterval time.Duration `help:"SNMP interface poll interval" default:"5m"`
	SNMPAutoDiscover bool          `help:"Auto-discover exporters for SNMP polling" default:"true"`

	NDPIEnabled    bool   `help:"Enable nDPI classification from application telemetry" default:"true"`
	NDPICategories string `help:"Comma-separated list of allowed nDPI categories" default:"sip,video,audio,control,services"`

	L7Enabled    bool   `help:"Enable L7 application classification (port heuristics)" default:"false"`
	L7Categories string `help:"Comma-separated list of allowed L7 categories" default:"voice,video,audio,control,services,other"`

	// Deduplication Configuration
	DedupEnabled bool          `help:"Enable flow deduplication" default:"false"`
	DedupMaxSize int           `help:"Maximum dedup cache size" default:"100000"`
	DedupTTL     time.Duration `help:"Dedup cache entry TTL" default:"60s"`

	// Queue Configuration
	QueueSize int `help:"Packet queue size" default:"1000000"`

	// Proxy / Conversion
	ProxyNetflow         string        `help:"Forward raw NetFlow/IPFIX datagrams to comma-separated host:port list"`
	ProxySflow           string        `help:"Forward raw sFlow datagrams to comma-separated host:port list"`
	SflowToNetflow       string        `help:"Export sFlow as NetFlow v9 to comma-separated host:port list"`
	SflowTemplateID      uint16        `help:"NetFlow v9 template ID for sFlow conversion" default:"256"`
	SflowTemplateRefresh time.Duration `help:"NetFlow v9 template refresh interval" default:"30s"`

	// Syslog Flow Collection
	SyslogFlowListen  Address `help:"Syslog flow listen address:port (empty to disable)" default:""`
	SyslogFlowNetwork string  `help:"Syslog flow network [udp|tcp]" default:"udp"`
	SyslogFlowFormat  string  `help:"Syslog flow format [fortinet|json]" default:"fortinet"`

	// Logging
	LogLevel  string `short:"l" help:"Log level [error|warn|info|debug|trace]" default:"info" enum:"error,warn,info,debug,trace"`
	LogFormat string `help:"Log format [default|json]" default:"default" enum:"default,json"`

	Version bool `short:"v" help:"Print version and copyright info"`
}

func parseCSV(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	var out []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func LoadMappingYaml() (*protoproducer.ProducerConfig, error) {
	config := &protoproducer.ProducerConfig{}
	dec := yaml.NewDecoder(strings.NewReader(localformatters.MappingYaml))
	err := dec.Decode(config)
	return config, err
}

func main() {
	var err error
	log = logrus.New()
	log.SetFormatter(&logrus.TextFormatter{
		DisableLevelTruncation: true,
		PadLevelText:           true,
		DisableTimestamp:       false,
	})

	parser := kong.Must(
		&rctx.cli,
		kong.Name("netflow2ng"),
		kong.Description("High-throughput NetFlow v9/IPFIX/sFlow collector for ntopng"),
		kong.UsageOnError(),
	)

	rctx.Kctx, err = parser.Parse(os.Args[1:])
	parser.FatalIfErrorf(err)

	if rctx.cli.Version {
		PrintVersion()
		os.Exit(0)
	}

	lvl, _ := logrus.ParseLevel(rctx.cli.LogLevel)
	switch rctx.cli.LogFormat {
	case "json":
		log.SetFormatter(&logrus.JSONFormatter{})
	case "default":
		log.Debugf("Using default log style")
	}

	log.SetLevel(lvl)
	localformatters.SetLogger(log)
	localtransport.SetLogger(log)
	collector.SetLogger(log)
	sampling.SetLogger(log)
	dedup.SetLogger(log)
	sflow.SetLogger(log)
	enrich.SetLogger(log)

	categories := parseCSV(rctx.cli.NDPICategories)
	localformatters.SetNDPIClassifier(enrich.NewNDPIClassifier(enrich.NDPIConfig{
		Enabled:           rctx.cli.NDPIEnabled,
		AllowedCategories: categories,
	}))
	localformatters.SetL7Classifier(enrich.NewL7Classifier(enrich.L7Config{
		Enabled:           rctx.cli.L7Enabled,
		AllowedCategories: parseCSV(rctx.cli.L7Categories),
	}))
	localformatters.SetInterfaceAutoDiscover(rctx.cli.SNMPAutoDiscover)

	var enrichCancel context.CancelFunc
	if rctx.cli.SNMPEnabled {
		enrichCtx, cancel := context.WithCancel(context.Background())
		enrichCancel = cancel
		cache := enrich.NewInterfaceCache()
		fetcher := enrich.NewSNMPFetcher(enrich.SNMPFetcherConfig{
			Community: rctx.cli.SNMPCommunity,
			Port:      rctx.cli.SNMPPort,
			Version:   rctx.cli.SNMPVersion,
			Timeout:   rctx.cli.SNMPTimeout,
			Retries:   rctx.cli.SNMPRetries,
		})
		poller := enrich.NewSNMPPoller(cache, fetcher, rctx.cli.SNMPPollInterval)
		poller.Start(enrichCtx)
		localformatters.SetInterfaceEnricher(enrich.NewInterfaceEnrichment(cache, poller))
		log.WithFields(logrus.Fields{
			"poll_interval": rctx.cli.SNMPPollInterval,
			"version":       rctx.cli.SNMPVersion,
			"port":          rctx.cli.SNMPPort,
		}).Info("SNMP interface enrichment enabled")
	}

	// Initialize sampling tracker
	samplingTracker := sampling.NewSamplingTracker(&sampling.SamplingTrackerConfig{
		DefaultRate:    uint32(rctx.cli.DefaultSampleRate),
		ScalingEnabled: !rctx.cli.DisableUpscaling,
		Metrics:        sampling.NewSamplingMetrics(METRICS_NAMESPACE),
	})
	localformatters.SetSamplingTracker(samplingTracker)

	// Initialize dedup cache if enabled
	var dedupCache *dedup.DedupCache
	if rctx.cli.DedupEnabled {
		dedupCache = dedup.NewDedupCache(&dedup.DedupCacheConfig{
			MaxSize: rctx.cli.DedupMaxSize,
			TTL:     rctx.cli.DedupTTL,
			Metrics: dedup.NewDedupMetrics(METRICS_NAMESPACE),
		})
		log.WithFields(logrus.Fields{
			"max_size": rctx.cli.DedupMaxSize,
			"ttl":      rctx.cli.DedupTTL,
		}).Info("Flow deduplication enabled")
	}

	exporterRegistry := collector.NewExporterRegistry(collector.NewExporterMetrics(METRICS_NAMESPACE))

	var msgType localtransport.MsgFormat
	var formatter *format.Format

	compress := false // For now, only compressing JSON.

	switch rctx.cli.Format {
	case "tlv":
		msgType = localtransport.TLV
		formatter, err = format.FindFormat("ntoptlv")
		log.Info("Using ntopng TLV format")
	case "jcompress":
		compress = true
		log.Info("Using ntopng compressed JSON format")
		fallthrough
	case "json":
		msgType = localtransport.JSON
		formatter, err = format.FindFormat("ntopjson")
		log.Info("Using ntopng JSON format")
	default:
		log.Fatal("Unknown output format")
	}

	if err != nil {
		log.Fatal("Avail formatters:", format.GetFormats(), err)
	}

	outputs := parseCSV(rctx.cli.Outputs)
	if len(outputs) == 0 {
		outputs = []string{"zmq"}
	}
	outputSet := make(map[string]bool, len(outputs))
	for _, out := range outputs {
		normalized := strings.ToLower(strings.TrimSpace(out))
		if normalized != "" {
			outputSet[normalized] = true
		}
	}
	if len(outputSet) == 0 {
		log.Fatal("no outputs configured")
	}
	if (outputSet["elastic"] || outputSet["syslog"]) && rctx.cli.Format == "tlv" {
		log.Fatal("elastic/syslog outputs require JSON format (json or jcompress)")
	}

	var transports []*transport.Transport

	if outputSet["zmq"] {
		zmqEndpoints := localtransport.ParseZmqEndpoints(rctx.cli.ListenZmq)
		fanoutStrategy := localtransport.ParseFanoutStrategy(rctx.cli.FanoutStrategy)

		localtransport.RegisterZmqWithConfig(&localtransport.ZmqConfig{
			Endpoints:      zmqEndpoints,
			MsgType:        msgType,
			SourceId:       int(rctx.cli.SourceId),
			Compress:       compress,
			FanoutStrategy: fanoutStrategy,
			Topic:          rctx.cli.Topic,
			Metrics:        localtransport.NewZmqMetrics(METRICS_NAMESPACE),
		})

		if len(zmqEndpoints) > 1 {
			log.WithFields(logrus.Fields{
				"endpoints": zmqEndpoints,
				"strategy":  rctx.cli.FanoutStrategy,
			}).Info("Multi-endpoint ZMQ fan-out configured")
		}

		t, err := transport.FindTransport("zmq")
		if err != nil {
			log.Error("Avail transporters:", transport.GetTransports())
			log.Fatal("error transporter", err)
		}
		transports = append(transports, t)
	}

	if outputSet["kafka"] {
		localtransport.RegisterKafkaWithConfig(&localtransport.KafkaConfig{
			Brokers:      parseCSV(rctx.cli.KafkaBrokers),
			Topic:        rctx.cli.KafkaTopic,
			BatchBytes:   rctx.cli.KafkaBatchBytes,
			BatchTimeout: rctx.cli.KafkaBatchTimeout,
			RequiredAcks: rctx.cli.KafkaRequiredAcks,
			Compression:  rctx.cli.KafkaCompression,
		})
		t, err := transport.FindTransport("kafka")
		if err != nil {
			log.Error("Avail transporters:", transport.GetTransports())
			log.Fatal("error kafka transporter", err)
		}
		transports = append(transports, t)
	}

	if outputSet["elastic"] {
		localtransport.RegisterElasticWithConfig(&localtransport.ElasticConfig{
			URL:          rctx.cli.ElasticURL,
			Index:        rctx.cli.ElasticIndex,
			BulkSize:     rctx.cli.ElasticBulkSize,
			BulkInterval: rctx.cli.ElasticBulkInterval,
			QueueSize:    rctx.cli.ElasticQueueSize,
			Username:     rctx.cli.ElasticUsername,
			Password:     rctx.cli.ElasticPassword,
			APIKey:       rctx.cli.ElasticAPIKey,
			Insecure:     rctx.cli.ElasticInsecure,
		})
		t, err := transport.FindTransport("elastic")
		if err != nil {
			log.Error("Avail transporters:", transport.GetTransports())
			log.Fatal("error elastic transporter", err)
		}
		transports = append(transports, t)
	}

	if outputSet["syslog"] {
		localtransport.RegisterSyslogWithConfig(&localtransport.SyslogConfig{
			Network:  rctx.cli.SyslogNetwork,
			Address:  rctx.cli.SyslogAddr,
			Facility: rctx.cli.SyslogFacility,
			Severity: rctx.cli.SyslogSeverity,
			Hostname: rctx.cli.SyslogHostname,
			AppName:  rctx.cli.SyslogAppName,
			ProcID:   rctx.cli.SyslogProcID,
			MsgID:    rctx.cli.SyslogMsgID,
		})
		t, err := transport.FindTransport("syslog")
		if err != nil {
			log.Error("Avail transporters:", transport.GetTransports())
			log.Fatal("error syslog transporter", err)
		}
		transports = append(transports, t)
	}

	if len(transports) == 0 {
		log.Fatal("no valid transports configured")
	}

	var output outputTransport
	var pipeTransport transport.TransportInterface
	if len(transports) == 1 {
		output = transports[0]
		pipeTransport = transports[0]
	} else {
		fanout := &fanoutTransport{transports: transports}
		output = fanout
		pipeTransport = fanout
	}

	var flowProducer producer.ProducerInterface
	// instanciate a producer
	// unlike transport and format, the producer requires extensive configurations and can be chained

	// We use our own mapping config to keep goflow2 from overwriting IN_BYTES with 0 from OUT_BYTES
	cfgProducer, err := LoadMappingYaml()
	if err != nil {
		log.Fatal("error loading mapping config", err)
	}

	cfgm, err := cfgProducer.Compile() // converts configuration into a format that can be used by a protobuf producer
	if err != nil {
		log.Fatal(err)
	}

	flowProducer, err = protoproducer.CreateProtoProducer(cfgm, protoproducer.CreateSamplingSystem)
	if err != nil {
		log.Fatal("error creating producer", err)
	}

	// intercept panic and generate an error
	flowProducer = debug.WrapPanicProducer(flowProducer)
	flowProducer = newFilteringProducer(flowProducer, dedupCache, samplingTracker, exporterRegistry)
	// wrap producer with Prometheus metrics
	flowProducer = metrics.WrapPromProducer(flowProducer)

	wg := &sync.WaitGroup{}

	var collecting atomic.Bool
	// HTTP server for metrics, health, and templates
	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/__health", func(wr http.ResponseWriter, r *http.Request) {
		if !collecting.Load() {
			wr.WriteHeader(http.StatusServiceUnavailable)
			if _, err := wr.Write([]byte("Not OK\n")); err != nil {
				log.Error("error writing HTTP: ", err)
			}
		} else {
			wr.WriteHeader(http.StatusOK)
			if _, err := wr.Write([]byte("OK\n")); err != nil {
				log.Error("error writing HTTP: ", err)

			}
		}
	})

	// Sampling info endpoint
	http.HandleFunc("/sampling", func(wr http.ResponseWriter, r *http.Request) {
		info := samplingTracker.GetAllSamplingInfo()
		wr.Header().Add("Content-Type", "application/json")
		if body, err := json.MarshalIndent(info, "", "  "); err != nil {
			log.Error("error writing JSON body for /sampling", err)
			wr.WriteHeader(http.StatusInternalServerError)
		} else {
			wr.WriteHeader(http.StatusOK)
			if _, err := wr.Write(body); err != nil {
				log.Error("error writing HTTP", err)
			}
		}
	})

	// Dedup stats endpoint
	if dedupCache != nil {
		http.HandleFunc("/dedup", func(wr http.ResponseWriter, r *http.Request) {
			stats := map[string]interface{}{
				"cache_size": dedupCache.Size(),
				"max_size":   rctx.cli.DedupMaxSize,
				"ttl":        rctx.cli.DedupTTL.String(),
			}
			wr.Header().Add("Content-Type", "application/json")
			if body, err := json.MarshalIndent(stats, "", "  "); err != nil {
				log.Error("error writing JSON body for /dedup", err)
				wr.WriteHeader(http.StatusInternalServerError)
			} else {
				wr.WriteHeader(http.StatusOK)
				if _, err := wr.Write(body); err != nil {
					log.Error("error writing HTTP", err)
				}
			}
		})
	}

	http.HandleFunc("/exporters", func(wr http.ResponseWriter, r *http.Request) {
		snapshot := exporterRegistry.GetAllExporters()
		type exporterStatsResponse struct {
			ExporterIP     string    `json:"exporter_ip"`
			SourceID       uint32    `json:"source_id"`
			UDPPackets     uint64    `json:"udp_packets_received"`
			UDPBytes       uint64    `json:"udp_bytes_received"`
			FlowsProcessed uint64    `json:"flows_processed"`
			Errors         uint64    `json:"errors"`
			LastSeen       time.Time `json:"last_seen"`
		}
		payload := make([]exporterStatsResponse, 0, len(snapshot))
		for _, stats := range snapshot {
			payload = append(payload, exporterStatsResponse{
				ExporterIP:     stats.Key.IP,
				SourceID:       stats.Key.SourceID,
				UDPPackets:     stats.PacketsReceived,
				UDPBytes:       stats.BytesReceived,
				FlowsProcessed: stats.FlowsProcessed,
				Errors:         stats.Errors,
				LastSeen:       stats.LastSeen,
			})
		}
		wr.Header().Add("Content-Type", "application/json")
		if body, err := json.MarshalIndent(payload, "", "  "); err != nil {
			log.Error("error writing JSON body for /exporters", err)
			wr.WriteHeader(http.StatusInternalServerError)
		} else {
			wr.WriteHeader(http.StatusOK)
			if _, err := wr.Write(body); err != nil {
				log.Error("error writing HTTP", err)
			}
		}
	})

	srv := http.Server{
		Addr:              string(rctx.cli.Metrics),
		ReadHeaderTimeout: time.Second * 5,
	}
	if srv.Addr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := srv.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatal("HTTP server error", err.Error())
			}
			log.Info("Closed HTTP server")
		}()
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	q := make(chan bool)

	Nfv9Ip, Nfv9Port := rctx.cli.Listen.Value()

	netflowProxy, err := newUDPProxy(rctx.cli.ProxyNetflow)
	if err != nil {
		log.WithError(err).Fatal("Failed to configure NetFlow/IPFIX proxy")
	}

	sflowProxy, err := newUDPProxy(rctx.cli.ProxySflow)
	if err != nil {
		log.WithError(err).Fatal("Failed to configure sFlow proxy")
	}

	var sflowExporter *converter.NetFlowV9Exporter
	if strings.TrimSpace(rctx.cli.SflowToNetflow) != "" {
		sflowExporter, err = converter.NewNetFlowV9Exporter(converter.NetFlowV9Config{
			Targets:         parseCSV(rctx.cli.SflowToNetflow),
			SourceID:        uint32(rctx.cli.SourceId),
			TemplateID:      rctx.cli.SflowTemplateID,
			TemplateRefresh: rctx.cli.SflowTemplateRefresh,
		})
		if err != nil {
			log.WithError(err).Fatal("Failed to configure sFlow to NetFlow exporter")
		}
		if sflowExporter != nil {
			log.WithFields(logrus.Fields{
				"targets":          rctx.cli.SflowToNetflow,
				"template_id":      rctx.cli.SflowTemplateID,
				"template_refresh": rctx.cli.SflowTemplateRefresh,
			}).Info("sFlow to NetFlow v9 conversion enabled")
		}
	}

	// Goflow2 UDPReceiver config allows for more complexity, we're just using one socket and however many
	// workers were on the command-line.
	numWorkers := rctx.cli.Workers
	numSockets := 1
	if rctx.cli.Reuse && numWorkers > 0 {
		numSockets = numWorkers
	}
	queueSize := rctx.cli.QueueSize

	log.Info("Starting collection. It may take several minutes for the first flows to appear in ntopng.")

	cfg := &utils.UDPReceiverConfig{
		Sockets:          numSockets,
		Workers:          numWorkers,
		QueueSize:        queueSize,
		Blocking:         false,
		ReceiverCallback: metrics.NewReceiverMetric(),
	}
	nfRecv, err := utils.NewUDPReceiver(cfg)
	if err != nil {
		log.Fatal("Error creating UDP receiver", err.Error())
		os.Exit(1)
	}

	cfgPipe := &utils.PipeConfig{
		Format:           formatter,
		Transport:        pipeTransport,
		Producer:         flowProducer,
		NetFlowTemplater: metrics.NewDefaultPromTemplateSystem, // wrap template system to get Prometheus info
	}

	var decodeFunc utils.DecoderFunc
	nfPipe := utils.NewNetFlowPipe(cfgPipe)

	http.HandleFunc("/templates", func(wr http.ResponseWriter, r *http.Request) {
		templates := nfPipe.GetTemplatesForAllSources()
		if body, err := json.MarshalIndent(templates, "", "  "); err != nil {
			log.Error("error writing JSON body for /templates", err)
			wr.WriteHeader(http.StatusInternalServerError)
			if _, err := wr.Write([]byte("Internal Server Error\n")); err != nil {
				log.Error("error writing HTTP", err)
			}
		} else {
			wr.Header().Add("Content-Type", "application/json")
			wr.WriteHeader(http.StatusOK)
			if _, err := wr.Write(body); err != nil {
				log.Error("error writing HTTP", err)
			}
		}
	})

	decodeFunc = func(msg interface{}) error {
		if exporterRegistry != nil {
			if udpMsg, ok := msg.(*utils.Message); ok {
				if netflowProxy != nil {
					netflowProxy.Send(udpMsg.Payload)
				}
				exporterIP := netipAddrToIP(udpMsg.Src.Addr())
				if exporterIP != nil {
					sourceID, ok := parseObservationDomainID(udpMsg.Payload)
					if !ok {
						sourceID = 0
					}
					exporterRegistry.RecordPacket(exporterIP, sourceID, len(udpMsg.Payload))
				}
			}
		}
		return nfPipe.DecodeFlow(msg)
	}
	// intercept panic and generate error
	decodeFunc = debug.PanicDecoderWrapper(decodeFunc)
	// wrap decoder with Prometheus metrics
	decodeFunc = metrics.PromDecoderWrapper(decodeFunc, "netflow")

	// starts receivers
	// the function either returns an error
	if err := nfRecv.Start(Nfv9Ip, Nfv9Port, decodeFunc); err != nil {
		log.Fatal("Error starting netflow receiver: ", Nfv9Ip, Nfv9Port)
	} else {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for {
				select {
				case <-q:
					return
				case err := <-nfRecv.Errors():
					if errors.Is(err, net.ErrClosed) {
						log.Info("Closed receiver")
						continue
					} else if !errors.Is(err, netflow.ErrorTemplateNotFound) && !errors.Is(err, &debug.PanicErrorMessage{}) {
						log.Error("Error", err)
						continue
					} else {
						if errors.Is(err, netflow.ErrorTemplateNotFound) {
							log.Debug("Netflow packet received before template was set. Discarding")
							log.Trace("More info: ", err)
						} else if errors.Is(err, &debug.PanicErrorMessage{}) {
							var pErrMsg *debug.PanicErrorMessage
							log.Error("Intercepted panic", pErrMsg)
						} else {
							log.Error(err)
						}
					}
				}
			}
		}()
	}

	// Start sFlow collector if configured
	var sflowCollector *sflow.SFlowCollector
	if string(rctx.cli.SFlowListen) != "" {
		sflowIP, sflowPort := rctx.cli.SFlowListen.Value()

		// Create flow handler that sends sFlow data to the same transport
		sflowHandler := func(msg *sflow.FlowMessage) error {
			// Convert to goflow2 format and send through existing pipeline
			gfMsg := sflow.ConvertToGoflowMessage(msg)

			// Apply sampling upscaling if enabled
			if !rctx.cli.DisableUpscaling && msg.SamplingRate > 1 {
				gfMsg.Bytes *= uint64(msg.SamplingRate)
				gfMsg.Packets *= uint64(msg.SamplingRate)
			}

			if sflowExporter != nil {
				_ = sflowExporter.SendFlow(gfMsg)
			}

			if dedupCache != nil && isDuplicateFlow(dedupCache, gfMsg) {
				return nil
			}

			if exporterRegistry != nil {
				if msg.SamplerAddress != nil {
					exporterRegistry.RecordPacket(msg.SamplerAddress, msg.SourceID, clampUint64ToInt(gfMsg.Bytes))
					exporterRegistry.RecordFlows(msg.SamplerAddress, msg.SourceID, 1)
				}
			}

			var payload interface{} = gfMsg
			if len(msg.Extras) > 0 {
				payload = localformatters.NewFlowWithExtras(gfMsg, msg.Extras)
			}

			// Format and send
			key, data, err := formatter.Format(payload)
			if err != nil {
				return err
			}
			return output.Send(key, data)
		}

		sflowCollector = sflow.NewSFlowCollector(&sflow.SFlowCollectorConfig{
			ListenAddr:      sflowIP,
			ListenPort:      sflowPort,
			NumWorkers:      rctx.cli.SFlowWorkers,
			QueueSize:       rctx.cli.QueueSize,
			SamplingTracker: samplingTracker,
			FlowHandler:     sflowHandler,
			RawDatagramHandler: func(payload []byte) {
				if sflowProxy != nil {
					sflowProxy.Send(payload)
				}
			},
			Metrics:          sflow.NewSFlowMetrics(METRICS_NAMESPACE),
			PoolMetrics:      collector.NewPoolMetrics(METRICS_NAMESPACE + "_sflow"),
			ExporterRegistry: exporterRegistry,
		})

		if err := sflowCollector.Start(); err != nil {
			log.WithError(err).Fatal("Error starting sFlow collector")
		}

		log.WithFields(logrus.Fields{
			"addr": sflowIP,
			"port": sflowPort,
		}).Info("sFlow collector started")
	}

	// Start syslog flow collector if configured
	var syslogCollector *syslogflow.Collector
	if string(rctx.cli.SyslogFlowListen) != "" {
		syslogIP, syslogPort := rctx.cli.SyslogFlowListen.Value()
		syslogHandler := func(record *syslogflow.FlowRecord) error {
			if record == nil || record.Flow == nil {
				return nil
			}

			if dedupCache != nil && isDuplicateFlow(dedupCache, record.Flow) {
				return nil
			}

			if exporterRegistry != nil {
				if record.Flow.SamplerAddress != nil {
					exporterRegistry.RecordPacket(net.IP(record.Flow.SamplerAddress), 0, clampUint64ToInt(record.Flow.Bytes))
					exporterRegistry.RecordFlows(net.IP(record.Flow.SamplerAddress), 0, 1)
				}
			}

			var payload interface{} = record.Flow
			if len(record.Extras) > 0 {
				payload = localformatters.NewFlowWithExtras(record.Flow, record.Extras)
			}
			key, data, err := formatter.Format(payload)
			if err != nil {
				return err
			}
			return output.Send(key, data)
		}

		syslogCollector = syslogflow.NewCollector(&syslogflow.CollectorConfig{
			ListenAddr:       fmt.Sprintf("%s:%d", syslogIP, syslogPort),
			Network:          rctx.cli.SyslogFlowNetwork,
			Format:           rctx.cli.SyslogFlowFormat,
			Handler:          syslogHandler,
			Metrics:          syslogflow.NewMetrics(METRICS_NAMESPACE),
			ExporterRegistry: exporterRegistry,
		})

		if err := syslogCollector.Start(); err != nil {
			log.WithError(err).Fatal("Error starting syslog flow collector")
		}

		log.WithFields(logrus.Fields{
			"addr":   syslogIP,
			"port":   syslogPort,
			"format": rctx.cli.SyslogFlowFormat,
		}).Info("Syslog flow collector started")
	}

	collecting.Store(true)

	<-c

	collecting.Store(false)

	// Stop sFlow collector if running
	if sflowCollector != nil {
		if err := sflowCollector.Stop(); err != nil {
			log.WithError(err).Error("Error stopping sFlow collector")
		}
	}

	if syslogCollector != nil {
		syslogCollector.Stop()
	}

	if netflowProxy != nil {
		netflowProxy.Close()
	}
	if sflowProxy != nil {
		sflowProxy.Close()
	}
	if sflowExporter != nil {
		sflowExporter.Close()
	}

	if enrichCancel != nil {
		enrichCancel()
	}

	// stops receivers first, udp sockets will be down
	_ = nfRecv.Stop()
	// then stop pipe
	nfPipe.Close()
	flowProducer.Close()
	// close transporter (eg: flushes message to Kafka) ignore errors, we're exiting anyway
	if output != nil {
		_ = output.Close()
		log.Info("Transporter closed")
	}

	// Stop dedup cache cleanup
	if dedupCache != nil {
		dedupCache.Stop()
	}

	// close http server (prometheus + health check)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	if err := srv.Shutdown(ctx); err != nil {
		log.Error("Error shutting-down HTTP server", err)
	}
	cancel()
	close(q) // close errors
	wg.Wait()
}

func PrintVersion() {
	delta := ""
	if len(Delta) > 0 {
		delta = fmt.Sprintf(" [%s delta]", Delta)
		Tag = "Unknown"
	}
	fmt.Printf("netflow2ng v%s -- Copyright %s Aaron Turner\n", Version, COPYRIGHT_YEAR)
	fmt.Printf("%s (%s)%s built at %s\n", CommitID, Tag, delta, Buildinfos)
	fmt.Println("\nProtocol Support:")
	fmt.Println("  - NetFlow v9")
	fmt.Println("  - IPFIX (NetFlow v10)")
	fmt.Println("  - sFlow v5")
	fmt.Println("\nFeatures:")
	fmt.Println("  - Multi-endpoint ZMQ fan-out (hash/round-robin)")
	fmt.Println("  - Per-exporter sampling rate tracking and upscaling")
	fmt.Println("  - Flow deduplication with configurable TTL")
	fmt.Println("  - High-throughput worker pool architecture")
	fmt.Println("  - Kafka/Elastic/Syslog output backends")
	fmt.Println("  - sFlow to NetFlow v9 conversion and UDP proxying")
	fmt.Println("  - Syslog flow collection (Fortinet/JSON)")
}
