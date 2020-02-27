package snet

import (
	"github.com/google/gopacket"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hpkt"
	"github.com/scionproto/scion/go/lib/l4"
	"github.com/scionproto/scion/go/lib/layers"
	"github.com/scionproto/scion/go/lib/spkt"
	"github.com/scionproto/scion/go/lib/util"
)

type scionLayer struct {
	*SCIONPacket
	cmnHdr    spkt.CmnHdr

	HBH    []*layers.Extension

	//we keep a separate field for the security extension, always parse it as first E2E extension
	SecExtnLayer  *layers.SPSE
	SecExtnBuffer []byte

	E2E    []*layers.Extension

	nextHdr       []common.L4ProtocolType

}

func (s *scionLayer) serialize() (int, error) {
	//ORDER OF CALLS IS IMPORTANT
	//start with address and path, have no dependencies, save in struct fields, do not write to s.Buffer yet
	hdrLen := spkt.CmnHdrLen
	addrRaw := s.serializeAddrHdr(hdrLen)
	hdrLen += len(addrRaw)
	pathRaw := s.serializePath(hdrLen)
	hdrLen += len(pathRaw)

	totalLen := hdrLen

	payloadRaw := make([]byte, s.Payload.Len())
	_, err := s.Payload.WritePld(payloadRaw)
	if err != nil {
		return 0, common.NewBasicError("Error writing payload to buffer", err)
	}

	//writes L4 header and payload to s.Buffer
	l4Raw, err := s.serializeL4(addrRaw, payloadRaw) //L4 depends on: payload, address
	if err != nil {
		return 0, common.NewBasicError("Error serializing L4", err)
	}
	//serialize Extensions
	hbhRaw, e2eRaw, secExtnOffset, err := s.serializeExtensions(hdrLen) //extensions depend on: L4 (last nxtHdr)
	if err != nil {
		return 0, common.NewBasicError("Error serializing extensions", err)
	}


	totalLen += len(hbhRaw) + len(s.SecExtnBuffer) + len(e2eRaw)

	copy(s.Bytes[totalLen:], l4Raw)
	totalLen += len(l4Raw)
	copy(s.Bytes[totalLen:], payloadRaw)
	totalLen += len(payloadRaw)

	err = s.serializeCommonHdr(hdrLen, totalLen) //common header depends on: L4/extensions (nxtHdr), length of buffer for totalLen calculation
	if err != nil {
		return 0, common.NewBasicError("Error serializing common header", err)
	}

	if s.AuthExt != nil {
		bAuth := gopacket.NewSerializeBuffer()
		//special serialization for authentication
		//must be called after normal serialization logic above
		//assumption is that s.CmnHdr, s.HBH, s.E2E and s.SecExtnLayer all implicitly store special fields
		//which hold only the bytes needed for authentication,
		//this call merely "collects" these bytes slices and arranges them in the correct order
		err := s.serializeForAuth(hdrLen, bAuth)
		if err != nil {
			return 0, err
		}
		l4PayloadBytes := l4Raw
		l4PayloadBytes = append(l4PayloadBytes, payloadRaw...)
		bytes, err := bAuth.AppendBytes(len(l4PayloadBytes))
		if err != nil {
			return 0, err
		}
		copy(bytes, l4PayloadBytes)

		err = s.AuthExt.Sum(bAuth.Bytes())
		if err != nil {
			return 0, err
		}
		//SecExtnLayer has a pointer to the buffer where the MAC should be stored,
		//this is maintained by the order of the calls in this function
		s.SecExtnLayer.SetAuthenticator(s.AuthExt.Authenticator)
		//s.SecExtnBuffer now has the serialized security extension with the MAC written in the correct location
		copy(s.Bytes[secExtnOffset:], s.SecExtnBuffer)

	}

	return totalLen, nil
}


func (s *scionLayer) serializeForAuth(hdrLen int, b gopacket.SerializeBuffer) error {
	err := s.serializeExtnForAuth(b)
	if err != nil {
		return err
	}
	headerBytes := s.cmnHdr.AuthenticatedBytes
	headerBytes = append(headerBytes, s.Bytes[spkt.CmnHdrLen:hdrLen]...)
	bytes, err := b.PrependBytes(len(headerBytes))
	if err != nil {
		return err
	}
	copy(bytes, headerBytes)


	return nil
}

func (s *scionLayer) serializeExtnForAuth(b gopacket.SerializeBuffer) error {
	for i := 0; i < len(s.E2E); i++ {
		bytes, err := b.PrependBytes(len(s.E2E[i].AuthenticatedBytes))
		if err != nil {
			return err
		}
		copy(bytes, s.E2E[i].AuthenticatedBytes)
	}
	bytes, err := b.PrependBytes(len(s.SecExtnLayer.AuthenticatedBytes))
	if err != nil {
		return err
	}
	copy(bytes, s.SecExtnLayer.AuthenticatedBytes)
	for i := 0; i < len(s.HBH); i++ {
		bytes, err := b.PrependBytes(len(s.HBH[i].AuthenticatedBytes))
		if err != nil {
			return err
		}
		copy(bytes, s.HBH[i].AuthenticatedBytes)
	}

	return nil

}

func (s *scionLayer) serializeCommonHdr(hdrLen, totalLen int) error {
	//still using this struct, because it's convenient and does the job
	s.cmnHdr = spkt.CmnHdr{
		Ver:       spkt.SCIONVersion,
		DstType:   s.Destination.Host.Type(),
		SrcType:   s.Source.Host.Type(),
		TotalLen:  uint16(totalLen),      //buffer should contain:l4 header, payload, extensions
		HdrLen:    uint8(hdrLen / common.LineLen), //in multiple of 8
		CurrInfoF: 0,
		CurrHopF:  0,
		NextHdr:   s.nextHdr[len(s.nextHdr)-1],
	}

	s.cmnHdr.Write(s.Bytes[:spkt.CmnHdrLen])
	return nil
}

func (s *scionLayer) serializeExtensions(offset int) ([]byte, []byte, int, error) {
	StableSortExtensions(s.Extensions)
	hbh, e2e, err := hpkt.ValidateExtensions(s.Extensions)
	if err != nil {
		return nil, nil, 0, err
	}

	e2eRaw, err := s.serializeExtensionsHelper(e2e)
	if err != nil {
		return nil, nil, 0, err
	}
	if s.AuthExt != nil {
		s.SecExtnLayer, err = layers.ExtensionDataToSPSELayer(s.nextHdr[len(s.nextHdr)-1], *s.AuthExt)
		if err != nil {
			return nil, nil, 0, err
		}
		s.SecExtnBuffer = s.SecExtnLayer.Serialize()
		//s.SecExtnLayer.SetAuthenticator([]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255})
		s.nextHdr = append(s.nextHdr, s.AuthExt.Class())
	}
	hbhRaw, err := s.serializeExtensionsHelper(hbh)
	if err != nil {
		return nil, nil, 0, err
	}
	copy(s.Bytes[offset:], hbhRaw)
	secExtnOffset := offset + len(hbhRaw)
	copy(s.Bytes[secExtnOffset+len(s.SecExtnBuffer):], e2eRaw)
	return hbhRaw, e2eRaw, secExtnOffset, nil

}

func (s *scionLayer) serializeExtensionsHelper(extensions []common.Extension) ([]byte, error) {
	raw := []byte{}
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

func (s *scionLayer) serializeL4(addrRaw, payloadRaw []byte) ([]byte, error) {
	s.L4Header.SetPldLen(len(payloadRaw))
	err := l4.SetCSum(s.L4Header, addrRaw, payloadRaw)
	if err != nil {
		return nil, err
	}
	l4Raw := make([]byte, s.L4Header.L4Len())
	err = s.L4Header.Write(l4Raw)
	if err != nil {
		return nil, err
	}
	s.nextHdr = append(s.nextHdr, s.L4Header.L4Type())

	return l4Raw, nil
}

func (s *scionLayer) serializePath(offset int) []byte {
	if !s.Path.IsEmpty() {
		copy(s.Bytes[offset:], s.Path.Raw)
		return s.Path.Raw
	}
	return []byte{}
}

func (s *scionLayer) serializeAddrHdr(offset int) []byte {
	src := s.Source
	dst := s.Destination
	// write dst first, then src
	IABuffer := make([]byte, addr.IABytes*2)
	src.IA.Write(IABuffer[addr.IABytes:])
	dst.IA.Write(IABuffer[:addr.IABytes])

	hostBuffer := make([]byte, dst.Host.Size()+src.Host.Size())
	copy(hostBuffer[:dst.Host.Size()], dst.Host.Pack())
	copy(hostBuffer[dst.Host.Size():], src.Host.Pack())

	addressBuffer := append(IABuffer, hostBuffer...)

	paddingLen := util.CalcPadding(len(addressBuffer), common.LineLen)
	padding := make([]byte, paddingLen)
	addressBuffer = append(addressBuffer, padding...)

	copy(s.Bytes[offset:], addressBuffer)
	return addressBuffer
}
