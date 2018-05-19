package address

import (
	"encoding/hex"
	"conseweb.com/wallet/icebox/common/crypto/koblitz/kelliptic"
	"math/big"
	"github.com/conseweb/coinutil/base58"
	"crypto/elliptic"
)

type PublicKey struct {
	*kelliptic.Curve
	X, Y *big.Int
}

func NewPublickKey(name string) *PublicKey {
	pk := new(PublicKey)
	switch name {
	case "256":
		pk.Curve = kelliptic.S256()
	case "160":
		pk.Curve = kelliptic.S160()
	case "192":
		pk.Curve = kelliptic.S192()
	case "224":
		pk.Curve = kelliptic.S224()
	default:
		return nil
	}
	return pk
}

func (p *PublicKey) String() string {
	return hex.EncodeToString(p.Bytes())
}

func (p *PublicKey) Bytes() []byte {
	if p.X == nil || p.Y == nil {
		return []byte{}
	}

	return elliptic.Marshal(p.Curve, p.X, p.Y)
}

func FromBytes(curve kelliptic.Curve, b []byte) *PublicKey {
	if b == nil {
		return nil
	}

	pk := new(PublicKey)
	pk.Curve = &curve
	pk.X, pk.Y = Unmarshal(curve, b)
	return pk
}

func (p *PublicKey) Address() string {
	b := p.Bytes()

	hash := make([]byte, 21)
	copy(hash[1:], Hash160(b))

	return ToBase58(hash, 34)
}

func (p *PublicKey) Address2() string {
	b := p.Bytes()

	hash := make([]byte, 21)
	copy(hash[1:], Hash160(b))

	return base58.Encode(hash)
}

func (p *PublicKey) AddressBytes() []byte {
	return []byte(p.Address())
}

func (p *PublicKey) Compress() string {

	hash := make([]byte, 34)
	copy(hash[1:], p.Curve.CompressPoint(p.X, p.Y))

	return ToBase58(hash, 60)
}

func (p *PublicKey) CompressBytes() []byte {
	return p.Curve.CompressPoint(p.X, p.Y)
}

func DeCompress(bs string, pk *PublicKey) (err error) {
	cp, err := FromBase58(bs)
	if err != nil {
		return err
	}

	pk.Curve.DecompressPoint(cp)

	return nil
}

// Marshal converts a point into the uncompressed form specified in section 4.3.6 of ANSI X9.62.
//func Marshal(curve kelliptic.Curve, x, y *big.Int) []byte {
//	byteLen := (curve.Params().BitSize + 7) >> 3
//
//	ret := make([]byte, 1+2*byteLen)
//	ret[0] = 4 // uncompressed point
//
//	xBytes := x.Bytes()
//	copy(ret[1+byteLen-len(xBytes):], xBytes)
//	yBytes := y.Bytes()
//	copy(ret[1+2*byteLen-len(yBytes):], yBytes)
//	return ret
//}

// Unmarshal converts a point, serialized by Marshal, into an x, y pair.
// It is an error if the point is not in uncompressed form or is not on the curve.
// On error, x = nil.
func Unmarshal(curve kelliptic.Curve, data []byte) (x, y *big.Int) {
	byteLen := (curve.Params().BitSize + 7) >> 3
	if len(data) != 1+2*byteLen {
		return
	}
	if data[0] != 4 { // uncompressed form
		return
	}
	p := curve.Params().P
	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
	y = new(big.Int).SetBytes(data[1+byteLen:])
	if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
		return nil, nil
	}
	if !curve.IsOnCurve(x, y) {
		return nil, nil
	}
	return
}