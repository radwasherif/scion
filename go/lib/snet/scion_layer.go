package snet

import (
	"github.com/google/gopacket"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/layers"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/util"
)

type SCIONLayer struct {
	*SCIONPacket
	CmnHdr    spkt.CmnHdr
	CmnHdrRaw common.RawBytes

	AddrHdr common.RawBytes
	RawPath common.RawBytes

	HBH    []*layers.Extension
	HBHRaw common.RawBytes
	//we keep a separate field for the security extension, always parse it as first E2E extension
	SecExt    *layers.SPSE
	SecExtRaw common.RawBytes

	E2E    []*layers.Extension
	E2ERaw common.RawBytes

	L4         common.RawBytes
	RawPayload common.RawBytes

	nextHdr       []common.L4ProtocolType
	SecExtnBuffer common.RawBytes

	Buffer common.RawBytes
}

func NewSCIONLayer(s *SCIONPacket) *SCIONLayer {
	//starting with fields that have no "dependencies" and building around them
	sl := &SCIONLayer{SCIONPacket: s}
	sl.Buffer = common.RawBytes{}
	return sl
}
func (s *SCIONLayer) Serialize() (int, error) {
	//ORDER OF CALLS IS IMPORTANT
	//start with address and path, have no dependencies, save in struct fields, do not write to s.Buffer yet
	s.serializeAddrHdr(s.Source, s.Destination)
	s.serializePath(s.Path)
	s.RawPayload = make(common.RawBytes, s.Payload.Len())
	_, err := s.Payload.WritePld(s.RawPayload)
	if err != nil {
		return 0, common.NewBasicError("Error writing payload to buffer", err)
	}

	//writes L4 header and payload to s.Buffer
	//still could be replaced by lightweight byte slices
	err = s.serializeL4(s.L4Header) //L4 depends on: payload, address
	if err != nil {
		return 0, common.NewBasicError("Error serializing L4", err)
	}
	//serialize Extensions
	err = s.serializeExtensions() //extensions depend on: L4 (last nxtHdr)
	if err != nil {
		return 0, common.NewBasicError("Error serializing extensions", err)
	}

	err = s.serializeCommonHdr() //common header depends on: L4/extensions (nxtHdr), length of buffer for totalLen calculation
	if err != nil {
		return 0, common.NewBasicError("Error serializing common header", err)
	}

	if s.AuthExt != nil {
		bAuth := gopacket.NewSerializeBuffer()
		//special serialization for authentication
		//must be called after normal serialization logic above
		//assumption is that s.CmnHdr, s.HBH, s.E2E and s.SecExt all implicitly store special fields
		//which hold only the bytes needed for authentication,
		//this call merely "collects" these bytes slices and arranges them together
		err := s.serializeForAuth(bAuth)
		if err != nil {
			return 0, err
		}

		err = s.AuthExt.Sum(bAuth.Bytes())
		if err != nil {
			return 0, err
		}
		s.SecExt.SetAuthenticator(s.AuthExt.Authenticator)
	}

	s.serialize()
	copy(s.Bytes, s.Buffer)
	return len(s.Buffer), nil
}

func (s *SCIONLayer) serialize() {
	s.Buffer = append(s.Buffer, s.CmnHdrRaw...)
	s.Buffer = append(s.Buffer, s.AddrHdr...)
	s.Buffer = append(s.Buffer, s.RawPath...)
	s.Buffer = append(s.Buffer, s.HBHRaw...)
	s.Buffer = append(s.Buffer, s.SecExtnBuffer...)
	s.Buffer = append(s.Buffer, s.E2ERaw...)
	s.Buffer = append(s.Buffer, s.L4...)
	s.Buffer = append(s.Buffer, s.RawPayload...)
}

func (s *SCIONLayer) serializeForAuth(b gopacket.SerializeBuffer) error {
	err := s.serializeExtnForAuth(b)
	if err != nil {
		return err
	}
	headerBytes := s.CmnHdr.AuthenticatedBytes
	headerBytes = append(headerBytes, s.AddrHdr...)
	headerBytes = append(headerBytes, s.RawPath...)
	bytes, err := b.PrependBytes(len(headerBytes))
	if err != nil {
		return err
	}
	copy(bytes, headerBytes)

	l4PayloadBytes := s.L4
	l4PayloadBytes = append(l4PayloadBytes, s.RawPayload...)
	bytes, err = b.AppendBytes(len(l4PayloadBytes))
	if err != nil {
		return err
	}
	copy(bytes, l4PayloadBytes)
	return nil
}

func (s *SCIONLayer) serializeExtnForAuth(b gopacket.SerializeBuffer) error {
	for i := 0; i < len(s.E2E); i++ {
		bytes, err := b.PrependBytes(len(s.E2E[i].AuthenticatedBytes))
		if err != nil {
			return err
		}
		copy(bytes, s.E2E[i].AuthenticatedBytes)
	}
	bytes, err := b.PrependBytes(len(s.SecExt.AuthenticatedBytes))
	if err != nil {
		return err
	}
	copy(bytes, s.SecExt.AuthenticatedBytes)
	for i := 0; i < len(s.HBH); i++ {
		bytes, err := b.PrependBytes(len(s.HBH[i].AuthenticatedBytes))
		if err != nil {
			return err
		}
		copy(bytes, s.HBH[i].AuthenticatedBytes)
	}

	return nil

}

func (s *SCIONLayer) serializeCommonHdr() error {
	hdrLen := spkt.CmnHdrLen + len(s.AddrHdr) + len(s.RawPath)
	packtLen := len(s.HBHRaw) + len(s.E2ERaw) + len(s.SecExtnBuffer) + len(s.L4) + len(s.RawPayload)
	//still using this struct, because it's convenient and does the job
	s.CmnHdr = spkt.CmnHdr{
		Ver:       spkt.SCIONVersion,
		DstType:   s.Destination.Host.Type(),
		SrcType:   s.Source.Host.Type(),
		TotalLen:  uint16(hdrLen + packtLen),      //buffer should contain:l4 header, payload, extensions
		HdrLen:    uint8(hdrLen / common.LineLen), //in multiple of 8
		CurrInfoF: 0,
		CurrHopF:  0,
		NextHdr:   s.nextHdr[len(s.nextHdr)-1],
	}

	s.CmnHdrRaw = make(common.RawBytes, spkt.CmnHdrLen)
	s.CmnHdr.Write(s.CmnHdrRaw)
	return nil
}

func (s *SCIONLayer) serializeExtensions() error {
	StableSortExtensions(s.Extensions)
	hbh, e2e, err := hpkt.ValidateExtensions(s.Extensions)
	if err != nil {
		return err
	}

	s.E2ERaw, err = s.serializeExtensionsHelper(e2e)
	if err != nil {
		return nil
	}
	if s.AuthExt != nil {
		s.SecExt, err = layers.ExtensionDataToSPSELayer(s.nextHdr[len(s.nextHdr)-1], *s.AuthExt)
		if err != nil {
			return err
		}
		s.SecExtnBuffer = s.SecExt.Serialize()
		//s.SecExt.SetAuthenticator(common.RawBytes{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255})
		s.nextHdr = append(s.nextHdr, s.AuthExt.Class())
	}
	s.HBHRaw, err = s.serializeExtensionsHelper(hbh)
	if err != nil {
		return err
	}
	return nil

}

func (s *SCIONLayer) serializeExtensionsHelper(extensions []common.Extension) (common.RawBytes, error) {
	raw := common.RawBytes{}
	for i := len(extensions) - 1; i >= 0; i-- {
		extnLayer, err := layers.ExtensionDataToExtensionLayer(s.nextHdr[len(s.nextHdr)-1], extensions[i])
		if err != nil {
			return nil, err
		}

		bf := gopacket.NewSerializeBuffer()
		err = extnLayer.SerializeTo(bf, gopacket.SerializeOptions{FixLengths: true})
		if err != nil {
			return nil, err
		}
		switch extensions[i].Class() {
		case common.End2EndClass:
			s.E2E = append(s.E2E, extnLayer)
		case common.HopByHopClass:
			s.HBH = append(s.HBH, extnLayer)
		default:
			return nil, common.NewBasicError("Unexpected extensions type", nil)
		}
		raw = append(bf.Bytes(), raw...)
		s.nextHdr = append(s.nextHdr, extensions[i].Class())
	}
	return raw, nil
}

func (s *SCIONLayer) serializeL4(l4Hdr l4.L4Header) error {
	l4Hdr.SetPldLen(len(s.RawPayload))
	err := l4.SetCSum(l4Hdr, s.AddrHdr, s.RawPayload)
	if err != nil {
		return err
	}
	s.L4 = make(common.RawBytes, l4Hdr.L4Len())
	err = l4Hdr.Write(s.L4)
	if err != nil {
		return err
	}
	s.nextHdr = append(s.nextHdr, l4Hdr.L4Type())

	return nil
}

func (s *SCIONLayer) serializePath(path *spath.Path) {
	if !path.IsEmpty() {
		s.RawPath = path.Raw
	}
}
func (s *SCIONLayer) serializeAddrHdr(src, dst SCIONAddress) {

	// write dst first, then src
	IABuffer := make(common.RawBytes, addr.IABytes*2)
	src.IA.Write(IABuffer[addr.IABytes:])
	dst.IA.Write(IABuffer[:addr.IABytes])

	hostBuffer := make(common.RawBytes, dst.Host.Size()+src.Host.Size())
	copy(hostBuffer[:dst.Host.Size()], dst.Host.Pack())
	copy(hostBuffer[dst.Host.Size():], src.Host.Pack())

	addressBuffer := append(IABuffer, hostBuffer...)

	paddingLen := util.CalcPadding(len(addressBuffer), common.LineLen)
	padding := make(common.RawBytes, paddingLen)
	addressBuffer = append(addressBuffer, padding...)

	s.AddrHdr = addressBuffer
}
