package enrich

import "testing"

func TestNDPIClassifier(t *testing.T) {
	classifier := NewNDPIClassifier(NDPIConfig{
		Enabled:           true,
		AllowedCategories: []string{"sip", "video"},
	})

	classification, ok := classifier.Classify("SIP")
	if !ok {
		t.Fatalf("expected SIP to be classified")
	}
	if classification.Category != "sip" {
		t.Fatalf("expected sip category, got %q", classification.Category)
	}

	_, ok = classifier.Classify("HTTPS")
	if ok {
		t.Fatalf("expected HTTPS to be ignored")
	}
}

func TestNDPIClassifierDisabled(t *testing.T) {
	classifier := NewNDPIClassifier(NDPIConfig{Enabled: false})
	if _, ok := classifier.Classify("SIP"); ok {
		t.Fatalf("expected classifier to be disabled")
	}
}
