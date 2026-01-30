package formatter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type templateFixture struct {
	Vendor           string            `json:"vendor"`
	Platform         string            `json:"platform"`
	Version          string            `json:"version"`
	Protocols        []string          `json:"protocols"`
	Fields           []templateField   `json:"fields"`
	EnterpriseFields []enterpriseField `json:"enterprise_fields"`
}

type templateField struct {
	ID     uint16 `json:"id"`
	Name   string `json:"name"`
	Source string `json:"source"`
}

type enterpriseField struct {
	Pen  uint32 `json:"pen"`
	ID   uint16 `json:"id"`
	Name string `json:"name"`
}

type flowFixture struct {
	ExporterIP          string `json:"exporter_ip"`
	ObservationDomainId uint32 `json:"observation_domain_id"`
	ObservationPointId  uint32 `json:"observation_point_id"`
	InputIfIndex        uint32 `json:"input_ifindex"`
	OutputIfIndex       uint32 `json:"output_ifindex"`
	ApplicationId       uint32 `json:"application_id"`
	ApplicationName     string `json:"application_name"`
	NDPICategory        string `json:"ndpi_category"`
}

func TestExtremeTemplateFixtures(t *testing.T) {
	fixtures := []string{
		filepath.Join("..", "testdata", "extreme", "templates", "exos_switch_engine.json"),
		filepath.Join("..", "testdata", "extreme", "templates", "fabric_engine.json"),
	}

	requiredFields := map[string]bool{
		"applicationId":       true,
		"applicationName":     true,
		"observationPointId":  true,
		"observationDomainId": true,
	}

	for _, path := range fixtures {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed reading fixture %s: %v", path, err)
		}
		var fixture templateFixture
		if err := json.Unmarshal(raw, &fixture); err != nil {
			t.Fatalf("failed parsing fixture %s: %v", path, err)
		}
		if fixture.Vendor == "" || fixture.Platform == "" {
			t.Fatalf("fixture %s missing vendor/platform", path)
		}
		seen := make(map[string]bool)
		for _, field := range fixture.Fields {
			if field.Name != "" {
				seen[field.Name] = true
			}
		}
		for name := range requiredFields {
			if !seen[name] {
				t.Fatalf("fixture %s missing field %s", path, name)
			}
		}
	}
}

func TestExtremeFlowFixtures(t *testing.T) {
	fixtures := []string{
		filepath.Join("..", "testdata", "extreme", "flows", "exos_flow.json"),
		filepath.Join("..", "testdata", "extreme", "flows", "fabric_flow.json"),
	}

	for _, path := range fixtures {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("failed reading flow fixture %s: %v", path, err)
		}
		var fixture flowFixture
		if err := json.Unmarshal(raw, &fixture); err != nil {
			t.Fatalf("failed parsing flow fixture %s: %v", path, err)
		}
		if fixture.ExporterIP == "" || fixture.ApplicationName == "" {
			t.Fatalf("flow fixture %s missing exporter/app name", path)
		}
		if fixture.NDPICategory == "" {
			t.Fatalf("flow fixture %s missing ndpi_category", path)
		}
	}
}
