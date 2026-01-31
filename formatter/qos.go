package formatter

import (
	"math"
	"strings"

	"github.com/josiah-nelson/ngflow/enrich"
)

func addQoSMetrics(target map[string]interface{}, classification enrich.NDPIClassification, bytes, packets uint64, startNs, endNs uint64) {
	if target == nil {
		return
	}
	extras := buildQoSMetrics(classification, bytes, packets, startNs, endNs)
	for k, v := range extras {
		target[k] = v
	}
}

func appendQoSMetrics(items []ndpiItem, classification enrich.NDPIClassification, bytes, packets uint64, startNs, endNs uint64) []ndpiItem {
	extras := buildQoSMetrics(classification, bytes, packets, startNs, endNs)
	return appendExtras(items, extras)
}

func buildQoSMetrics(classification enrich.NDPIClassification, bytes, packets uint64, startNs, endNs uint64) map[string]interface{} {
	category := strings.ToLower(strings.TrimSpace(classification.Category))
	if category == "" {
		return nil
	}
	if category != "voice" && category != "audio" {
		return nil
	}

	if packets == 0 {
		return nil
	}
	if endNs <= startNs {
		return nil
	}

	duration := float64(endNs-startNs) / 1_000_000_000
	if duration <= 0 {
		return nil
	}

	avgPkt := float64(bytes) / float64(packets)
	bps := float64(bytes*8) / duration
	pps := float64(packets) / duration

	extras := map[string]interface{}{
		"qos.duration_sec":     duration,
		"qos.bitrate_bps":      bps,
		"qos.packets_per_sec":  pps,
		"qos.avg_packet_size":  avgPkt,
	}

	if codec := guessVoipCodec(avgPkt, pps); codec != "" {
		extras["voip.codec_guess"] = codec
	}

	return extras
}

func guessVoipCodec(avgPkt float64, pps float64) string {
	if pps <= 0 || avgPkt <= 0 {
		return ""
	}

	switch {
	case pps >= 45 && pps <= 55 && avgPkt >= 160 && avgPkt <= 220:
		return "g711"
	case pps >= 45 && pps <= 55 && avgPkt >= 120 && avgPkt < 160:
		return "opus"
	case pps >= 45 && pps <= 55 && avgPkt < 120:
		return "g729/g723"
	case pps >= 20 && pps < 45 && avgPkt > 200 && avgPkt <= 400:
		return "g722"
	}

	// Heuristic for wideband codecs with larger packets and lower pps
	if avgPkt > 300 && pps < 40 {
		return "wideband"
	}

	if !math.IsNaN(avgPkt) && !math.IsNaN(pps) {
		return "unknown"
	}
	return ""
}
