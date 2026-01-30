package formatter

import (
	"net"

	"github.com/synfinatic/netflow2ng/enrich"
)

var interfaceEnricher enrich.InterfaceEnricher
var ndpiClassifier *enrich.NDPIClassifier

func SetInterfaceEnricher(enricher enrich.InterfaceEnricher) {
	interfaceEnricher = enricher
}

func SetNDPIClassifier(classifier *enrich.NDPIClassifier) {
	ndpiClassifier = classifier
}

func enrichInterfaces(exporterIP net.IP, inIf uint32, outIf uint32) (inMeta, outMeta enrich.InterfaceMetadata, inOk, outOk bool) {
	if interfaceEnricher == nil {
		return enrich.InterfaceMetadata{}, enrich.InterfaceMetadata{}, false, false
	}
	interfaceEnricher.ObserveExporter(exporterIP)
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

func classifyNDPI(appName string) (enrich.NDPIClassification, bool) {
	if ndpiClassifier == nil {
		return enrich.NDPIClassification{}, false
	}
	return ndpiClassifier.Classify(appName)
}
