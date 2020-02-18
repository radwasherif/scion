// Copyright 2019 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package layers

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
)

var (
	LayerTypeHopByHopExtension = gopacket.RegisterLayerType(1101,
		gopacket.LayerTypeMetadata{Name: "HopByHopExtension", Decoder: nil})
	LayerTypeEndToEndExtension = gopacket.RegisterLayerType(1102,
		gopacket.LayerTypeMetadata{Name: "EndToEndExtension", Decoder: nil})
	LayerTypeSCIONUDP = gopacket.RegisterLayerType(1103,
		gopacket.LayerTypeMetadata{Name: "SCIONUDP", Decoder: nil})
	LayerTypeSCMP = gopacket.RegisterLayerType(1104,
		gopacket.LayerTypeMetadata{Name: "SCMP", Decoder: nil})
)

var (
	LayerToHeaderMap = map[gopacket.LayerType]common.L4ProtocolType{
		LayerTypeHopByHopExtension: common.HopByHopClass,
		LayerTypeEndToEndExtension: common.End2EndClass,
		LayerTypeSCIONUDP:          common.L4UDP,
		LayerTypeSCMP:              common.L4SCMP,
	}
)

var (
	zeroes = make([]byte, common.MaxMTU)
)

type Extension struct {
	layers.BaseLayer
	NextHeader         common.L4ProtocolType
	NumLines           uint8
	Type               common.ExtnType
	Data               []byte
	AuthenticatedBytes []byte
}

func (e *Extension) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < common.ExtnSubHdrLen {
		df.SetTruncated()
		return common.NewBasicError("Invalid SCION Extension header, small raw length",
			nil, "actual", len(data), "wanted", common.ExtnSubHdrLen)
	}

	expectedLength := int(data[1]) * common.LineLen
	if expectedLength <= 0 {
		df.SetTruncated()
		return serrors.New("Invalid SCION Extension header, length is zero")
	}

	if len(data) < expectedLength {
		df.SetTruncated()
		return common.NewBasicError("Invalid SCION Extension body, actual length too short", nil,
			"actual", len(data), "wanted", expectedLength)
	}

	e.NextHeader = common.L4ProtocolType(data[0])
	e.NumLines = data[1]
	e.Type.Type = data[2]
	e.Data = data[3:expectedLength]
	e.BaseLayer.Contents = data[:expectedLength]
	e.BaseLayer.Payload = data[expectedLength:]
	return nil
}

func (e *Extension) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := e.serialize(b, opts)
	if err != nil {
		return err
	}

	//The bytes that need to be authenticated
	switch e.Type.Class {
	case common.HopByHopClass:
		e.AuthenticatedBytes = []byte{bytes[0], bytes[2]} //HBH: only next header and type
	case common.End2EndClass: //E2E: entire extension
		e.AuthenticatedBytes = bytes
	}

	return nil
}
func (e *Extension) serialize(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) ([]byte, error) {
	totalLength := common.ExtnSubHdrLen + len(e.Data)
	paddingSize := 0
	if opts.FixLengths {
		paddingSize = util.CalcPadding(totalLength, common.LineLen)
		totalLength += paddingSize
		e.NumLines = uint8(totalLength / common.LineLen)
	}
	bytes, err := b.PrependBytes(totalLength)
	if err != nil {
		return nil, err
	}
	bytes[0] = uint8(e.NextHeader)
	bytes[1] = e.NumLines
	bytes[2] = e.Type.Type
	copy(bytes[3:], e.Data)
	copy(bytes[3+len(e.Data):], zeroes[:paddingSize])

	return bytes, nil
}

type SPSE struct {
	Extension
	//AuthenticatorBuffer is a pointer to the serialization buffer where the MAC is written
	AuthenticatorBuffer []byte
	//AuthStartOffset the start offset of the authenticator relative to the Data field
	AuthStartOffset int
	//AuthEndOffset the end offset of the authenticator relative to the Data field
	AuthEndOffset int
}

func (e *SPSE) SetAuthenticator(b []byte) {
	copy(e.AuthenticatorBuffer, b)
}

func (e *SPSE) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := e.serialize(b, opts)
	if err != nil {
		return err
	}
	//The bytes that need to be authenticated
	e.AuthenticatedBytes = bytes

	//Keep pointer to the buffer containing authenticator
	//Initialized to zero, set later by call to SetAuthenticator after MAC computation
	e.AuthenticatorBuffer = bytes[3+e.AuthStartOffset : 3+e.AuthEndOffset]
	return nil
}

func (e *SPSE) Serialize() []byte {
	totalLength := common.ExtnSubHdrLen + len(e.Data)
	paddingSize := util.CalcPadding(totalLength, common.LineLen)
	totalLength += paddingSize
	e.NumLines = uint8(totalLength / common.LineLen)
	bytes := make([]byte, totalLength)
	bytes[0] = uint8(e.NextHeader)
	bytes[1] = e.NumLines
	bytes[2] = e.Type.Type
	copy(bytes[3:], e.Data)
	copy(bytes[3+len(e.Data):], zeroes[:paddingSize])
	//The bytes that need to be authenticated
	e.AuthenticatedBytes = bytes

	//Keep pointer to the buffer containing authenticator
	//Initialized to zero, set later by call to SetAuthenticator after MAC computation
	e.AuthenticatorBuffer = bytes[common.ExtnSubHdrLen+e.AuthStartOffset : common.ExtnSubHdrLen+e.AuthEndOffset]

	return bytes

}
