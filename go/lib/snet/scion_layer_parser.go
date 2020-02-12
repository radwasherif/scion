package snet

import (
	"github.com/scionproto/scion/go/lib/spkt"
)

func (s *SCIONLayer) Decode() {

}

func (s *SCIONLayer) decodeCmdHdr() error {
	err := s.CmnHdr.Parse(s.Bytes[:spkt.CmnHdrLen])
	if err != nil {
		return err
	}
	return nil
}

func (s *SCIONLayer) decodeAddrHdr() {
	//bytes := s.Bytes[spkt.CmnHdrLen:]

}
