package layers

import (
	"github.com/google/gopacket"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/spse"
	"github.com/scionproto/scion/go/lib/util"
)

type SCIONLayer struct {
	*snet.SCIONPacket
	CmnHdr  spkt.CmnHdr
	AddrHdr common.RawBytes
	RawPath common.RawBytes
	HBH     []*Extension
	//we keep a separate field for the security extension, always parse it as first E2E extension
	SecExt     *SPSE
	E2E     []*Extension

	L4         common.RawBytes
	RawPayload common.RawBytes

	Buffer  gopacket.SerializeBuffer
	nextHdr []common.L4ProtocolType
}

func NewSCIONLayer(s *snet.SCIONPacket) *SCIONLayer {
	//starting with fields that have no "dependencies" and building around them
	sl := &SCIONLayer{SCIONPacket: s}
	return sl
}
func (s *SCIONLayer) Serialize() (int, error) {
	//ORDER OF CALLS IS IMPORTANT
	//start with address and path, have no dependencies, save in struct fields, do not write to s.Buffer yet
	s.serializeAddrHdr(s.Source, s.Destination)
	s.serializePath(s.Path)
	s.Payload.WritePld(s.RawPayload)

	//writes L4 header and payload to s.Buffer, the idea is to start from the L4 header and payload
	//then use the PrependBytes to write above them
	//still could be replaced by lightweight byte slices
	s.serializeL4(s.L4Header) //L4 depends on: payload, address

	//writes extensions to s.Buffer
	s.serializeExtensions(s.Extensions, s.AuthExt) //extensions depend on: L4 (last nxtHdr)

	s.serializeCommonHdr() //common header depends on: L4/extensions (nxtHdr), length of buffer for totalLen calculation

	//now safely prepend address and path headers
	addrPath := s.AddrHdr
	addrPath = append(addrPath, s.RawPath...)
	bytes, err := s.Buffer.PrependBytes(len(addrPath))
	if err != nil {
		return 0, err
	}
	copy(bytes, addrPath)

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
	copy(s.Bytes, s.Buffer.Bytes())
	return len(s.Bytes), nil
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

	return nil
}

func (s *SCIONLayer) serializeExtnForAuth(b gopacket.SerializeBuffer) error {
	for i := len(s.E2E); i >= 0; i-- {
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
	for i := len(s.HBH); i >= 0; i-- {
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
	//still using this struct, because it's convenient and does the job
	s.CmnHdr = spkt.CmnHdr{
		Ver:       spkt.SCIONVersion,
		DstType:   s.Destination.Host.Type(),
		SrcType:   s.Source.Host.Type(),
		TotalLen:  uint16(hdrLen + len(s.Buffer.Bytes())), //buffer should contain:l4 header, payload, extensions
		HdrLen:    uint8(hdrLen / common.LineLen),         //in multiple of 8
		CurrInfoF: 0,
		CurrHopF:  0,
		NextHdr:   s.nextHdr[len(s.nextHdr)-1],
	}

	b, err := s.Buffer.PrependBytes(spkt.CmnHdrLen)
	if err != nil {
		return err
	}
	s.CmnHdr.Write(b)
	return nil
}

func (s *SCIONLayer) serializeExtensions(extensions []common.Extension, secExt *spse.Extn) error {
	snet.StableSortExtensions(extensions)
	hbh, e2e, err := hpkt.ValidateExtensions(extensions)
	if err != nil {
		return err
	}

	err = s.serializeExtensionsHelper(e2e, s.E2E)
	if err != nil {
		return nil
	}

	if secExt != nil {
		s.SecExt, err = ExtensionDataToSPSELayer(s.nextHdr[len(s.nextHdr)-1], *secExt)
		if err != nil {
			return err
		}
		err = s.SecExt.SerializeTo(s.Buffer, gopacket.SerializeOptions{FixLengths: true})
		if err != nil {
			return err
		}
		s.nextHdr = append(s.nextHdr, secExt.Class())
	}
	err = s.serializeExtensionsHelper(hbh, s.HBH)
	if err != nil {
		return err
	}
	return nil

}

func (s *SCIONLayer) serializeExtensionsHelper(extensions []common.Extension, layers []*Extension) error {
	for i := 0; i <= len(extensions); i-- {
		extnLayer, err := ExtensionDataToExtensionLayer(s.nextHdr[len(s.nextHdr)-1], extensions[i])
		if err != nil {
			return err
		}
		err = extnLayer.SerializeTo(s.Buffer, gopacket.SerializeOptions{FixLengths: true})
		if err != nil {
			return err
		}
		layers = append(layers, extnLayer)
		s.nextHdr = append(s.nextHdr, extensions[i].Class())
	}
	return nil
}

func (s *SCIONLayer) serializeL4(l4Hdr l4.L4Header) error {
	l4Hdr.SetPldLen(len(s.RawPayload))
	l4.SetCSum(l4Hdr, s.AddrHdr, s.RawPayload)
	l4Hdr.Write(s.L4)
	l4HdrPayload := s.L4
	l4HdrPayload = append(l4HdrPayload, s.RawPath...)
	bytes, err := s.Buffer.AppendBytes(len(l4HdrPayload))
	if err != nil {
		return err
	}
	copy(bytes, l4HdrPayload)

	s.nextHdr = append(s.nextHdr, l4Hdr.L4Type())

	return nil
}

func (s *SCIONLayer) serializePath(path *spath.Path) {
	if !path.IsEmpty() {
		s.RawPath = path.Raw
	}
}
func (s *SCIONLayer) serializeAddrHdr(src, dst snet.SCIONAddress) {

	// write dst first, then src
	IABuffer := make(common.RawBytes, addr.IABytes*2)
	dst.IA.Write(IABuffer[addr.IABytes:])
	src.IA.Write(IABuffer[:addr.IABytes])

	hostBuffer := make(common.RawBytes, dst.Host.Size()+src.Host.Size())
	copy(hostBuffer[:dst.Host.Size()], dst.Host.Pack())
	copy(hostBuffer[dst.Host.Size():], src.Host.Pack())

	addressBuffer := append(IABuffer, hostBuffer...)

	paddingLen := util.CalcPadding(len(addressBuffer), common.LineLen)
	padding := make(common.RawBytes, paddingLen)
	addressBuffer = append(addressBuffer, padding...)

	s.AddrHdr = addressBuffer
}
