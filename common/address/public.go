package address

import (
	"crypto/elliptic"
	"encoding/hex"
	"conseweb.com/wallet/icebox/common/crypto/koblitz/kelliptic"
	"math/big"
	"conseweb.com/wallet/icebox/coinutil/base58"
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