package formatter

import (
	"fmt"

	flowpb "github.com/netsampler/goflow2/v2/pb"
)

type FlowWithExtras struct {
	Flow   interface{}
	Extras map[string]interface{}
	key    []byte
}

func NewFlowWithExtras(flow *flowpb.FlowMessage, extras map[string]interface{}) *FlowWithExtras {
	return &FlowWithExtras{
		Flow:   flow,
		Extras: extras,
		key:    flowKeyBytes(flow),
	}
}

func (f *FlowWithExtras) FlowMessage() *flowpb.FlowMessage {
	if f == nil {
		return nil
	}
	if fm, ok := f.Flow.(*flowpb.FlowMessage); ok {
		return fm
	}
	return nil
}

func (f *FlowWithExtras) ExtraFields() map[string]interface{} {
	if f == nil {
		return nil
	}
	return f.Extras
}

func (f *FlowWithExtras) Key() []byte {
	if f == nil {
		return nil
	}
	return f.key
}

func appendExtras(items []ndpiItem, extras map[string]interface{}) []ndpiItem {
	if len(extras) == 0 {
		return items
	}
	for k, v := range extras {
		switch value := v.(type) {
		case string:
			items = append(items, ndpiItem{Key: k, Value: value})
		case int:
			items = append(items, ndpiItem{Key: k, Value: value})
		case int8:
			items = append(items, ndpiItem{Key: k, Value: value})
		case int16:
			items = append(items, ndpiItem{Key: k, Value: value})
		case int32:
			items = append(items, ndpiItem{Key: k, Value: value})
		case int64:
			items = append(items, ndpiItem{Key: k, Value: value})
		case uint:
			items = append(items, ndpiItem{Key: k, Value: value})
		case uint8:
			items = append(items, ndpiItem{Key: k, Value: value})
		case uint16:
			items = append(items, ndpiItem{Key: k, Value: value})
		case uint32:
			items = append(items, ndpiItem{Key: k, Value: value})
		case uint64:
			items = append(items, ndpiItem{Key: k, Value: value})
		case float32:
			items = append(items, ndpiItem{Key: k, Value: fmt.Sprintf("%.6f", value)})
		case float64:
			items = append(items, ndpiItem{Key: k, Value: fmt.Sprintf("%.6f", value)})
		default:
			items = append(items, ndpiItem{Key: k, Value: fmt.Sprintf("%v", value)})
		}
	}
	return items
}
