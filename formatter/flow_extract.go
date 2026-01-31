package formatter

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/josiah-nelson/ngflow/proto"
	flowpb "github.com/netsampler/goflow2/v2/pb"
	gf2proto "github.com/netsampler/goflow2/v2/producer/proto"
)

type extraFlowProvider interface {
	FlowMessage() *flowpb.FlowMessage
	ExtraFields() map[string]interface{}
	Key() []byte
}

func extractFlow(data interface{}) (key []byte, extFlow *proto.ExtendedFlowMessage, baseFlow *flowpb.FlowMessage, extras map[string]interface{}, err error) {
	if dataIf, ok := data.(interface{ Key() []byte }); ok {
		key = dataIf.Key()
	}

	switch v := data.(type) {
	case extraFlowProvider:
		baseFlow = v.FlowMessage()
		extras = v.ExtraFields()
		key = v.Key()
		if baseFlow == nil {
			return key, nil, nil, extras, errors.New("flow message missing base flow")
		}
		extFlow = &proto.ExtendedFlowMessage{BaseFlow: baseFlow}
	case *gf2proto.ProtoProducerMessage:
		extFlow, err = castToExtendedFlowMsg(v)
		if err != nil {
			return key, nil, nil, nil, err
		}
		baseFlow = extFlow.BaseFlow
	case gf2proto.ProtoProducerMessage:
		extFlow, err = castToExtendedFlowMsg(&v)
		if err != nil {
			return key, nil, nil, nil, err
		}
		baseFlow = extFlow.BaseFlow
	case *flowpb.FlowMessage:
		extFlow = &proto.ExtendedFlowMessage{BaseFlow: v}
		baseFlow = v
	default:
		return key, nil, nil, nil, errors.New("unsupported flow message type")
	}

	if baseFlow == nil {
		return key, nil, nil, extras, errors.New("flow message missing base flow")
	}

	if len(key) == 0 {
		key = flowKeyBytes(baseFlow)
	}

	return key, extFlow, baseFlow, extras, nil
}

func flowKeyBytes(flow *flowpb.FlowMessage) []byte {
	if flow == nil {
		return nil
	}
	var buf bytes.Buffer
	appendAddr := func(addr []byte) {
		buf.WriteByte(byte(len(addr)))
		if len(addr) > 0 {
			buf.Write(addr)
		}
	}

	appendAddr(flow.SamplerAddress)
	appendAddr(flow.SrcAddr)
	appendAddr(flow.DstAddr)

	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(flow.SrcPort))
	buf.Write(portBytes[:])
	binary.BigEndian.PutUint16(portBytes[:], uint16(flow.DstPort))
	buf.Write(portBytes[:])
	buf.WriteByte(byte(flow.Proto))

	return buf.Bytes()
}
