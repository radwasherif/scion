package snet

import (
	"github.com/google/gopacket"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/layers"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/util"
)

// offsets holds start and end offsets for packet sections
type offsets struct {
	start, end int
}

// Processing/parsing callback type
type pktParser func() error

type scionPacketParser struct {
	*scionLayer
	// Current parse offset
	offset int

	// Protocol type of next header (L4, HBH class, E2E class)
	nextHdr common.L4ProtocolType

	// Memorize section start and end offsets for when we need to jump
	cmnHdrOffsets  offsets
	extHdrOffsets  offsets
	addrHdrOffsets offsets
	fwdPathOffsets offsets
	l4HdrOffsets   offsets
	pldOffsets     offsets

	// Methods for parsing various packet elements; can be overwritten by extensions
	// FIXME(scrye): when the need arises, these should probably be changed to queues
	// (e.g., when multiple handlers need to be chained)
	AddrHdrParser pktParser
	FwdPathParser pktParser
	L4Parser      pktParser
}

func newSCIONPacketParser(pkt *SCIONPacket) *scionPacketParser {
	s := &scionPacketParser{
		scionLayer:     &scionLayer{SCIONPacket: pkt, cmnHdr: spkt.CmnHdr{}},
	}
	s.AddrHdrParser = s.DefaultAddrHdrParser
	s.FwdPathParser = s.DefaultFwdPathParser
	s.L4Parser = s.DefaultL4Parser
	return s
}

func (d *scionPacketParser) parseExtensions() ([]common.Extension, []common.Extension, error) {
	var extns []common.Extension
	for d.nextHdr == common.HopByHopClass || d.nextHdr == common.End2EndClass {
		typ := common.ExtnType{Class: d.nextHdr, Type: d.Bytes[d.offset + 2]}
		if typ == common.ExtnSCIONPacketSecurityType {
			//d.parseSPSE()
		}
		var extn layers.Extension
		err := extn.DecodeFromBytes(d.Bytes[d.offset:], gopacket.NilDecodeFeedback)
		if err != nil {
			return nil, nil, common.NewBasicError("Unable to parse extensions", err)
		}

		//d.nextHdr is actually the class of the current extension
		extnData, err := layers.ExtensionFactory(d.nextHdr, &extn)
		if err != nil {
			return nil, nil, err
		}
		extns = append(extns, extnData)

		d.nextHdr = extn.NextHeader
		d.offset += len(extn.Contents)
	}
	return hpkt.ValidateExtensions(extns)
}

//func (d *scionPacketParser) parseSPSE() (*spse.Extn, error) {
//	var extn layers.SPSE
//	err := extn.DecodeFromBytes(d.Bytes[d.offset:], gopacket.NilDecodeFeedback)
//	if err != nil {
//		return nil, common.NewBasicError("Unable to parse SPSE", err)
//	}
//	extnData, err := layers.ExtensionFactory(d.nextHdr, extn)
//	if err != nil {
//		return nil, nil, err
//	}
//}

func (d *scionPacketParser) CmnHdrParser() error {
	d.cmnHdrOffsets.start = d.offset
	if err := d.cmnHdr.Parse(d.Bytes); err != nil {
		return err
	}
	d.offset += spkt.CmnHdrLen
	d.cmnHdrOffsets.end = d.offset

	if int(d.cmnHdr.TotalLen) != len(d.Bytes) {
		return common.NewBasicError("Malformed total packet length", nil,
			"expected", d.cmnHdr.TotalLen, "actual", len(d.Bytes))
	}

	if len(d.Bytes) < int(d.cmnHdr.HdrLenBytes()) {
		return common.NewBasicError("Malformed hdr length", nil,
			"expected", d.cmnHdr.HdrLenBytes(), "larger than ", len(d.Bytes))
	}
	return nil
}

func (d *scionPacketParser) DefaultAddrHdrParser() error {
	var err error
	d.addrHdrOffsets.start = d.offset
	d.Destination.IA.Parse(common.RawBytes(d.Bytes[d.offset:]))
	d.offset += addr.IABytes
	d.Source.IA.Parse(common.RawBytes(d.Bytes[d.offset:]))
	d.offset += addr.IABytes
	if d.Destination.Host, err = addr.HostFromRaw(common.RawBytes(d.Bytes[d.offset:]), d.cmnHdr.DstType); err != nil {
		return common.NewBasicError("Unable to parse destination host address", err)
	}
	d.offset += d.Destination.Host.Size()
	if d.Source.Host, err = addr.HostFromRaw(common.RawBytes(d.Bytes[d.offset:]), d.cmnHdr.SrcType); err != nil {
		return common.NewBasicError("Unable to parse source host address", err)
	}
	d.offset += d.Source.Host.Size()
	// Validate address padding bytes
	padBytes := util.CalcPadding(d.offset, common.LineLen)
	if pos, ok := isZeroMemory(d.Bytes[d.offset : d.offset+padBytes]); !ok {
		return common.NewBasicError("Invalid padding", nil,
			"position", pos, "expected", 0, "actual", d.Bytes[d.offset+pos])
	}
	d.offset += padBytes
	d.addrHdrOffsets.end = d.offset
	return nil
}

func (d *scionPacketParser) DefaultFwdPathParser() error {
	d.fwdPathOffsets.start = d.offset
	pathLen := d.cmnHdr.HdrLenBytes() - d.offset
	if pathLen > 0 {
		if d.Path == nil {
			d.Path = &spath.Path{}
		}
		d.Path.Raw = common.RawBytes(d.Bytes[d.offset : d.offset+pathLen])
		d.Path.InfOff = d.cmnHdr.InfoFOffBytes() - d.offset
		d.Path.HopOff = d.cmnHdr.HopFOffBytes() - d.offset
		d.offset += pathLen
	}
	d.fwdPathOffsets.end = d.offset
	return nil
}

func (d *scionPacketParser) DefaultL4Parser() error {
	var err error
	d.l4HdrOffsets.start = d.offset

	switch d.nextHdr {
	case common.L4UDP:
		if len(d.Bytes) < d.offset+l4.UDPLen {
			return common.NewBasicError("Unable to parse UDP header, small buffer size", err)
		}
		if d.L4Header, err = l4.UDPFromRaw(common.RawBytes(d.Bytes[d.offset : d.offset+l4.UDPLen])); err != nil {
			return common.NewBasicError("Unable to parse UDP header", err)
		}
	case common.L4SCMP:
		if len(d.Bytes) < d.offset+scmp.HdrLen {
			return common.NewBasicError("Unable to parse SCMP header, small buffer size", err)
		}
		if d.L4Header, err = scmp.HdrFromRaw(common.RawBytes(d.Bytes[d.offset : d.offset+scmp.HdrLen])); err != nil {
			return common.NewBasicError("Unable to parse SCMP header", err)
		}
	default:
		return common.NewBasicError("Unsupported NextHdr value", nil,
			"expected", common.L4UDP, "actual", d.nextHdr)
	}
	d.offset += d.L4Header.L4Len()
	d.l4HdrOffsets.end = d.offset

	// Parse L4 payload
	d.pldOffsets.start = d.offset
	pldLen := len(d.Bytes) - d.pldOffsets.start
	if err = d.L4Header.Validate(pldLen); err != nil {
		return common.NewBasicError("L4 validation failed", err)
	}
	switch d.nextHdr {
	case common.L4UDP:
		d.Payload = common.RawBytes(d.Bytes[d.offset : d.offset+pldLen])
	case common.L4SCMP:
		hdr, ok := d.L4Header.(*scmp.Hdr)
		if !ok {
			return common.NewBasicError(
				"Unable to extract SCMP payload, type assertion failed", nil)
		}
		d.Payload, err = scmp.PldFromRaw(common.RawBytes(d.Bytes[d.offset:d.offset+pldLen]),
			scmp.ClassType{Class: hdr.Class, Type: hdr.Type})
		if err != nil {
			return common.NewBasicError("Unable to parse SCMP payload", err)
		}
	}
	d.offset += pldLen
	d.pldOffsets.end = d.offset

	// Run checksum function
	err = l4.CheckCSum(d.L4Header, common.RawBytes(d.Bytes[d.addrHdrOffsets.start:d.addrHdrOffsets.end]),
		common.RawBytes(d.Bytes[d.pldOffsets.start:d.pldOffsets.end]))
	if err != nil {
		return common.NewBasicError("Checksum failed", err)
	}
	return nil
}

func isZeroMemory(b Bytes) (int, bool) {
	for i := range b {
		if b[i] != 0 {
			return i, false
		}
	}
	return 0, true
}

