package snet

import (
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/layers"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spse"
	"github.com/scionproto/scion/go/lib/xtest"
	"testing"
)

//func TestSCIONLayer_serializeForAuth(t *testing.T) {
//	b := []byte{
//		0, 65, 0,
//		16, 0, 255, 170, 0, 0, 17, 1,
//		0, 1, 255, 170, 0, 0, 17, 3,
//		1, 1, 1, 100, 1, 1, 1, 8,
//		1, 2, 3, 4, 5, 6, 7, 8,
//		1, 2, 3, 4, 5, 6, 7, 8,
//		1, 2, 3, 4, 5, 6, 7, 8,
//		222, 1,
//		222, 3, 2, 0, 0, 0, 0, 0,
//		80, 61, 234, 240, 236, 19, 189, 187,
//		142, 123, 200, 129, 6, 230, 160, 210,
//		222, 1, 254, 5, 5, 5, 5, 5,
//		17, 1, 2, 0, 0, 0, 0, 0,
//		5, 220, 5, 221, 0, 15, 29, 229,
//		10, 20, 30, 40, 50, 60, 70,
//	}
//	authExt, _ := spse.NewExtn(spse.AesCMac)
//	authExt.Key = make(common.RawBytes, 32)
//	dstIA := xtest.MustParseIA("4096-ffaa:0:1101")
//	srcIA := xtest.MustParseIA("1-ffaa:0:1103")
//	pktInf := SCIONPacketInfo{
//		Destination: SCIONAddress{
//			IA:   dstIA,
//			Host: addr.HostFromIPStr("1.1.1.100"),
//		},
//		Source: SCIONAddress{
//			IA:   srcIA,
//			Host: addr.HostFromIPStr("1.1.1.8"),
//		},
//		Path: &spath.Path{
//			Raw:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8},
//			InfOff: 0,
//			HopOff: 0,
//		},
//		Extensions: []common.Extension{
//			layers.ExtnE2EDebug{ID: [5]byte{5, 5, 5, 5, 5}},
//			layers.ExtnUnknown{
//				ClassField: common.End2EndClass,
//				TypeField:  2,
//				Length:     4,
//			},
//			layers.ExtnUnknown{
//				ClassField: common.HopByHopClass,
//				TypeField:  1,
//				Length:     5,
//			},
//		},
//		AuthExt: authExt,
//		L4Header: &l4.UDP{
//			SrcPort: 1500,
//			DstPort: 1501,
//		},
//		Payload: common.RawBytes{10, 20, 30, 40, 50, 60, 70},
//	}
//	pkt := &SCIONPacket{
//		SCIONPacketInfo: pktInf,
//	}
//	s := NewSCIONLayer(pkt)
//	s.Serialize()
//	bf := gopacket.NewSerializeBuffer()
//
//	err := s.serializeForAuth(bf)
//	if err != nil {
//		t.Fatal(err.Error())
//	}
//
//	if len(bf.Bytes()) != len(b) {
//		t.Fatal("Lengths of two buffers should be equal")
//	}
//	bfBytes := bf.Bytes()
//
//	bytes.Compare(b, bfBytes)
//}

func TestSCIONLayer_Serialize(t *testing.T) {
	authExt, _ := spse.NewExtn(spse.AesCMac)
	authExt.Key = make(common.RawBytes, 32)
	dstIA := xtest.MustParseIA("4096-ffaa:0:1101")
	srcIA := xtest.MustParseIA("1-ffaa:0:1103")
	pktInf := SCIONPacketInfo{
		Destination: SCIONAddress{
			IA:   dstIA,
			Host: addr.HostFromIPStr("1.1.1.100"),
		},
		Source: SCIONAddress{
			IA:   srcIA,
			Host: addr.HostFromIPStr("1.1.1.8"),
		},
		Path: &spath.Path{
			Raw:    []byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8},
			InfOff: 0,
			HopOff: 0,
		},
		Extensions: []common.Extension{
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
		AuthExt: authExt,
		L4Header: &l4.UDP{
			SrcPort: 23,
			DstPort: 24,
		},
		Payload: common.RawBytes{10, 20, 30, 40, 50, 60, 70},
	}
	pkt := &SCIONPacket{
		SCIONPacketInfo: pktInf,
	}

	err := pkt.Serialize()
	if err != nil {
		t.Fatalf(err.Error())
	}
	for i := 0; i < len(pkt.Bytes); i += 8 {
		if i+8 < len(pkt.Bytes) {
			t.Log(pkt.Bytes[i : i+8])
		} else {
			t.Log(pkt.Bytes[i:])
		}
	}
	b := []byte{
		0, 65, 0, 119, 7, 0, 0, 0,
		16, 0, 255, 170, 0, 0, 17, 1,
		0, 1, 255, 170, 0, 0, 17, 3,
		1, 1, 1, 100, 1, 1, 1, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8,
		222, 1, 1, 0, 0, 0, 0, 0,
		222, 3, 2, 0, 0, 0, 0, 0,
		80, 61, 234, 240, 236, 19, 189, 187,
		142, 123, 200, 129, 6, 230, 160, 210,
		222, 1, 254, 5, 5, 5, 5, 5,
		17, 1, 2, 0, 0, 0, 0, 0,
		0, 23, 0, 24, 0, 15, 41, 111,
		10, 20, 30, 40, 50, 60, 70,
	}
	if len(b) != len(pkt.Bytes) {
		t.Fatalf("Length should be %d, but is %d", len(b), len(pkt.Bytes))
	}
	for i := range pkt.Bytes {
		if b[i] != pkt.Bytes[i] {
			t.Fatalf("Bytes #%d should be %b but is %b", i, b[i], pkt.Bytes[i])

		}
	}
}
