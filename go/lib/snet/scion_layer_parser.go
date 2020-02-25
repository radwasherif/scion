package snet

import (
	"github.com/scionproto/scion/go/lib/spkt"
)

func (s *scionLayer) Decode() {

}

func (s *scionLayer) decodeCmdHdr() error {
	err := s.CmnHdr.Parse(s.Bytes[:spkt.CmnHdrLen])
	if err != nil {
		return err
	}
	return nil
}

func (s *scionLayer) decodeAddrHdr() {
	//bytes := common.RawBytes(s.Bytes[spkt.CmnHdrLen:])
	//s.Destination = SCIONAddress{}
	//s.Source = SCIONAddress{}
	//s.Destination.IA.Parse(bytes[:addr.IABytes])
	//s.Source.IA.Parse(bytes[addr.IABytes : 2*addr.IABytes])
	//
	//dstLen, err := addr.HostLen(s.CmnHdr.DstType)
	//if err != nil {
	//	return err
	//}
	//srcLen, err := addr.HostLen(s.CmnHdr.SrcType)
	//
	//switch s.CmnHdr.DstType:
	//	addr.HostIPv4{}
	//s.Destination.Host = addr.HostIPv4(bytes[2*addr.IABytes:2*addr.IABytes+dstLen])
}
