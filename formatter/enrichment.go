package formatter

import (
	"net"

	pb "github.com/netsampler/goflow2/v2/pb"
	"github.com/josiah-nelson/ngflow/enrich"
)

var interfaceEnricher enrich.InterfaceEnricher
var ndpiClassifier *enrich.NDPIClassifier
var l7Classifier *enrich.L7Classifier
var interfaceAutoDiscover = true

func SetInterfaceEnricher(enricher enrich.InterfaceEnricher) {
	interfaceEnricher = enricher
}

func SetInterfaceAutoDiscover(enabled bool) {
	interfaceAutoDiscover = enabled
}

func SetNDPIClassifier(classifier *enrich.NDPIClassifier) {
	ndpiClassifier = classifier
}

func SetL7Classifier(classifier *enrich.L7Classifier) {
	l7Classifier = classifier
}

func enrichInterfaces(exporterIP net.IP, inIf uint32, outIf uint32) (inMeta, outMeta enrich.InterfaceMetadata, inOk, outOk bool) {
	if interfaceEnricher == nil {
		return enrich.InterfaceMetadata{}, enrich.InterfaceMetadata{}, false, false
	}
	if interfaceAutoDiscover {
		interfaceEnricher.ObserveExporter(exporterIP)
	}
	if exporterIP == nil {
		return enrich.InterfaceMetadata{}, enrich.InterfaceMetadata{}, false, false
	}
	if inIf > 0 {
		if meta, ok := interfaceEnricher.Lookup(exporterIP, inIf); ok {
			inMeta = meta
			inOk = true
		}
	}
	if outIf > 0 {
		if meta, ok := interfaceEnricher.Lookup(exporterIP, outIf); ok {
			outMeta = meta
			outOk = true
		}
	}
	return inMeta, outMeta, inOk, outOk
}

func classifyFlow(appName string, appDescription string, flow *pb.FlowMessage) (enrich.NDPIClassification, bool) {
	if ndpiClassifier != nil {
		if classification, ok := ndpiClassifier.Classify(appName); ok {
			return classification, true
		}
		if classification, ok := ndpiClassifier.Classify(appDescription); ok {
			return classification, true
		}
	}
	if l7Classifier != nil {
		return l7Classifier.Classify(flow)
	}
	return enrich.NDPIClassification{}, false
}
