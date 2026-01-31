package enrich

import (
	"testing"

	flowpb "github.com/netsampler/goflow2/v2/pb"
)

func TestL7ClassifierPorts(t *testing.T) {
	classifier := NewL7Classifier(L7Config{Enabled: true})

	flow := &flowpb.FlowMessage{Proto: 6, SrcPort: 12345, DstPort: 22}
	classification, ok := classifier.Classify(flow)
	if !ok {
		t.Fatalf("expected classification")
	}
	if classification.Protocol != "ssh" {
		t.Fatalf("expected ssh protocol, got %q", classification.Protocol)
	}
	if classification.Category != "control" {
		t.Fatalf("expected control category, got %q", classification.Category)
	}
}

func TestL7ClassifierRTP(t *testing.T) {
	classifier := NewL7Classifier(L7Config{Enabled: true})

	flow := &flowpb.FlowMessage{Proto: 17, SrcPort: 5004, DstPort: 5005, Bytes: 5000, Packets: 50}
	classification, ok := classifier.Classify(flow)
	if !ok {
		t.Fatalf("expected classification")
	}
	if classification.Protocol == "unknown" {
		t.Fatalf("expected rtp classification")
	}
}
