package dr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/hmac"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"

	"golang.org/x/crypto/hkdf"
)

// nist implements Ratchet using a NIST curve, 256-bit AES-GCM,
// HKDF and HMAC with the provided hash function.
type nist struct {
	// curve is the underlying curve.
	curve elliptic.Curve
	// hash is the underlying hash
	hash func() hash.Hash
	// mkInfo is the HKDF info used when deriving message keys.
	mkInfo []byte
	// rkInfo is the HKDF info used when deriving root keys.
	rkInfo []byte
}

var _ Ratchet = (*nist)(nil)

// NIST creates a Ratchet using NIST curves, 256-bit AES-GCM, and
// HKDF and HMAC with the provided hash function.
//
// The namespace is used to bind keys to a particular application
// or context.
func NIST(curve elliptic.Curve, hash func() hash.Hash, namespace string) Ratchet {
	return &nist{
		curve:  curve,
		hash:   hash,
		mkInfo: []byte(namespace + "MessageKeys"),
		rkInfo: []byte(namespace + "Ratchet"),
	}
}

// byteLen returns the size of the underlying curve in bytes.
func (n *nist) byteLen() int {
	return (n.curve.Params().BitSize + 7) / 8
}

// privKeyLen returns the size in bytes of a PrivateKey.
func (n *nist) privKeyLen() int {
	// PrivateKey is priv || pub.
	return n.byteLen() + n.pubKeyLen()
}

// pubKeyLen returns the size in bytes of a PublicKey.
//
// The public key is in ANSI X9.62 compressed form.
func (n *nist) pubKeyLen() int {
	return 1 + n.byteLen()
}

func (n *nist) Generate(r io.Reader) (PrivateKey, error) {
	d, x, y, err := elliptic.GenerateKey(n.curve, r)
	if err != nil {
		return nil, err
	}
	pub := elliptic.MarshalCompressed(n.curve, x, y)
	priv := make(PrivateKey, n.privKeyLen())
	m := copy(priv, d)
	m += copy(priv[m:], pub)
	if m != len(priv) {
		panic("dr: key size mismatch")
	}
	return priv, nil
}

func (n *nist) Public(priv PrivateKey) PublicKey {
	if len(priv) != n.privKeyLen() {
		panic("dr: invalid private key size: " + strconv.Itoa(len(priv)))
	}
	pub := make(PublicKey, n.pubKeyLen())
	copy(pub, priv[n.byteLen():])
	return pub
}

func (n *nist) DH(priv PrivateKey, pub PublicKey) ([]byte, error) {
	if len(priv) != n.privKeyLen() {
		panic("dr: invalid private key size: " + strconv.Itoa(len(priv)))
	}
	if len(pub) != n.pubKeyLen() {
		panic("dr: invalid public key size: " + strconv.Itoa(len(pub)))
	}

	x, y := elliptic.UnmarshalCompressed(n.curve, pub)
	if x == nil {
		return nil, errors.New("dr: invalid public key")
	}
	k := priv[:n.byteLen()]

	secret, _ := n.curve.ScalarMult(x, y, k)
	dh := make([]byte, n.byteLen())
	secret.FillBytes(dh)
	return dh, nil
}

func (n *nist) KDFrk(rk RootKey, dh []byte) (RootKey, ChainKey) {
	if len(rk) != 32 {
		panic("dr: invalid RootKey size: " + strconv.Itoa(len(rk)))
	}
	buf := make([]byte, 2*32)
	// The Double Ratchet spec says:
	//
	//    as the out of applying a KDF keyed by a 32-byte root
	//    key rk to a Diffie-Hellman output dh_out
	//
	// And so at first blush setting IKM=dh, info=rk might seem
	// backward since the PRK extracted from the IKM is used to
	// key the HMAC used in the expand step. But this is not the
	// case, and checking other DR implementations confirms this.
	r := hkdf.New(n.hash, dh, rk, n.rkInfo)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		panic(err)
	}
	return buf[:32:32], buf[32 : 2*32 : 2*32]
}

func (n *nist) KDFck(ck ChainKey) (ChainKey, MessageKey) {
	if len(ck) != 32 {
		panic("dr: invalid ChainKey size: " + strconv.Itoa(len(ck)))
	}

	h := hmac.New(n.hash, ck)

	const (
		ckConst = 0x02
		mkConst = 0x01
	)

	h.Write([]byte{ckConst})
	ck = h.Sum(nil)

	h.Reset()
	h.Write([]byte{mkConst})
	mk := h.Sum(nil)

	return ck, mk
}

// derive derives a 256-bit AES-GCM key and 96-bit AES-GCM nonce.
func (n *nist) derive(ikm []byte) (key, nonce []byte) {
	buf := make([]byte, 32+12)
	r := hkdf.New(n.hash, ikm, nil, n.mkInfo)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		panic(err)
	}
	return buf[0:32:32], buf[32 : 32+12 : 32+12]
}

func (n *nist) Seal(key MessageKey, plaintext, additionalData []byte) []byte {
	if len(key) != 32 {
		panic("dr: invalid message key size: " + strconv.Itoa(len(key)))
	}

	key, nonce := n.derive(key)
	defer wipe(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead.Seal(nil, nonce, plaintext, additionalData)
}

func (n *nist) Open(key MessageKey, ciphertext, additionalData []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("dr: invalid message key size: %d", len(key))
	}
	key, nonce := n.derive(key)
	defer wipe(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, additionalData)
}

func (n *nist) Header(priv PrivateKey, prevChainLength, messageNum int) Header {
	if len(priv) != n.privKeyLen() {
		panic("dr: invalid key pair size: " + strconv.Itoa(len(priv)))
	}
	return Header{
		PublicKey: n.Public(priv),
		PN:        prevChainLength,
		N:         messageNum,
	}
}

func (nist) Concat(additionalData []byte, h Header) []byte {
	return Concat(additionalData, h)
}
