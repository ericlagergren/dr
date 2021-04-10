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

// nist implements Ratchet using NIST curves, 256-bit AES-GCM,
// HKDF with SHA-256, and HMAC-SHA-256.
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

// privLen returns the size in bytes of a private key on the
// underlying curve.
func (n *nist) privLen() int {
	return (n.curve.Params().BitSize + 7) / 8
}

// pubLen returns the size in bytes of a public key on the
// underlying curve.
//
// The public key is in ANSI X9.62 uncompressed form.
func (n *nist) pubLen() int {
	return 1 + 2*n.privLen()
}

// pairLen returns the size in bytes of a key pair on the
// underlying curve.
func (n *nist) keyPairLen() int {
	return n.privLen() + n.pubLen()
}

// secretLen returns the size in bytes of a Diffie-Hellman value
// on the underlying curve.
func (n *nist) secretLen() int {
	return n.privLen()
}

func (n *nist) Generate(r io.Reader) (KeyPair, error) {
	priv, x, y, err := elliptic.GenerateKey(n.curve, r)
	if err != nil {
		return nil, err
	}
	pub := elliptic.Marshal(n.curve, x, y)
	key := make([]byte, n.keyPairLen())
	copy(key[0:n.privLen()], priv)
	copy(key[n.privLen():], pub)
	return key, nil
}

func (n *nist) Public(priv KeyPair) PublicKey {
	if len(priv) != n.keyPairLen() {
		panic("DH: invalid key pair size: " + strconv.Itoa(len(priv)))
	}
	return append(PublicKey(nil), priv[n.privLen():]...)
}

func (n *nist) DH(priv KeyPair, pub PublicKey) ([]byte, error) {
	if len(priv) != n.keyPairLen() {
		panic("DH: invalid key pair size: " + strconv.Itoa(len(priv)))
	}
	if len(pub) != n.pubLen() {
		panic("DH: invalid public key size: " + strconv.Itoa(len(pub)))
	}

	x, y := elliptic.Unmarshal(n.curve, pub)
	if x == nil {
		return nil, errors.New("invalid public key")
	}
	k := priv[:n.privLen()]

	secret, _ := n.curve.ScalarMult(x, y, k)
	dh := make([]byte, n.secretLen())
	secret.FillBytes(dh)
	return dh, nil
}

func (n *nist) KDFrk(rk RootKey, dh []byte) (RootKey, ChainKey) {
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
	return buf[0:32:32], buf[32 : 2*32 : 2*32]
}

func (n *nist) KDFck(ck ChainKey) (ChainKey, MessageKey) {
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
		panic("Seal: invalid message key size: " + strconv.Itoa(len(key)))
	}

	key, nonce := n.derive(key)
	defer subtleZero(key)

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
		return nil, fmt.Errorf("Open: invalid message key size: %d", len(key))
	}
	key, nonce := n.derive(key)
	defer subtleZero(key)

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

func (n *nist) Header(priv KeyPair, prevChainLength, messageNum int) Header {
	if len(priv) != n.keyPairLen() {
		panic("Header: invalid key pair size: " + strconv.Itoa(len(priv)))
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
