package snet

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/layers"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spse"
	"testing"
)

func TestSCIONLayer_Serialize(t *testing.T) {
	authExt, _ := spse.NewExtn(spse.AesCMac)
	authExt.Key = make(common.RawBytes, 32)
	pktInf := SCIONPacketInfo{
		Destination: SCIONAddress{
			IA: addr.IA{
				I: 1,
				A: 1,
			},
			Host: addr.HostFromIPStr("1.1.1.1"),
		},
		Source: SCIONAddress{
			IA: addr.IA{
				I: 0,
				A: 0,
			},
			Host: addr.HostFromIPStr("1.1.1.0"),

		},
		Path: &spath.Path{
			Raw:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8},
			InfOff: 0,
			HopOff: 0,
		},
		Extensions:  []common.Extension{
			layers.ExtnE2EDebug{ID: [5]byte{5, 5, 5, 5, 5}},
				layers.ExtnUnknown{
					ClassField: common.End2EndClass,
					TypeField:  2,
					Length:     4,
				},
				layers.ExtnUnknown{
					ClassField: common.HopByHopClass,
					TypeField:  1,
					Length:     5,
				},
		},
		AuthExt:     authExt,
		L4Header:    &l4.UDP{
			SrcPort:  1500,
			DstPort:  1501,
		},
		Payload:     common.RawBytes{10, 20, 30, 40, 50, 60, 70},
	}
	pkt := &SCIONPacket{
		SCIONPacketInfo: pktInf,
	}
	s := NewSCIONLayer(pkt)
	_, err := s.Serialize()
	if err != nil {
		t.Fatalf(err.Error())
	}
	for i := 0; i < len(s.Bytes); i+=8 {
		if i+8 < len(s.Bytes) {
			t.Log(s.Bytes[i:i+8])
		} else {
			t.Log(s.Bytes[i:])
		}
	}
	t.Log(s.Bytes)
}
