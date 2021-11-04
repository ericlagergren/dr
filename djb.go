package dr

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"
	"strconv"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// djb implements Ratchet using x25519, 256-bit
// XChaCha20-Poly1305, HKDF with SHA-256, and HMAC-SHA-256.
type djb struct {
	// mkInfo is the HKDF info used when deriving message keys.
	mkInfo []byte
	// rkInfo is the HKDF info used when deriving root keys.
	rkInfo []byte
}

var _ Ratchet = (*djb)(nil)

// DJB creates a Ratchet using x25519, 256-bit
// XChaCha20-Poly1305, HKDF with SHA-256, and HMAC-SHA-256.
//
// The namespace is used to bind keys to a particular application
// or context.
func DJB(namespace string) Ratchet {
	return &djb{
		mkInfo: []byte(namespace + "MessageKeys"),
		rkInfo: []byte(namespace + "Ratchet"),
	}
}

func (djb) Generate(r io.Reader) (KeyPair, error) {
	const (
		S = curve25519.ScalarSize
		P = curve25519.PointSize
	)
	key := make([]byte, S+P)
	if _, err := io.ReadFull(r, key[:S]); err != nil {
		return nil, err
	}
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	pub, err := curve25519.X25519(key[:S], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(key[S:], pub)
	return key, nil
}

func (djb) Public(priv KeyPair) PublicKey {
	if len(priv) != curve25519.ScalarSize+curve25519.PointSize {
		panic("DH: invalid key pair size: " + strconv.Itoa(len(priv)))
	}
	return append(PublicKey(nil), priv[curve25519.ScalarSize:]...)
}

func (djb) DH(priv KeyPair, pub PublicKey) ([]byte, error) {
	if len(priv) != curve25519.ScalarSize+curve25519.PointSize {
		panic("DH: invalid key pair size: " + strconv.Itoa(len(priv)))
	}
	if len(pub) != curve25519.PointSize {
		panic("DH: invalid public key size: " + strconv.Itoa(len(pub)))
	}
	return curve25519.X25519(priv[:curve25519.ScalarSize], pub)
}

func (d djb) KDFrk(rk RootKey, dh []byte) (RootKey, ChainKey) {
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
	r := hkdf.New(sha256.New, dh, rk, d.rkInfo)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		panic(err)
	}
	return buf[0:32:32], buf[32 : 2*32 : 2*32]
}

func (djb) KDFck(ck ChainKey) (ChainKey, MessageKey) {
	h := hmac.New(sha256.New, ck)

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

// derive derives a 256-bit XChaCha20-Poly1305 key and 192-bit
// XChaCha20-Poly1305 nonce.
func (d djb) derive(ikm []byte) (key, nonce []byte) {
	const (
		K = chacha20poly1305.KeySize
		N = chacha20poly1305.NonceSizeX
	)
	buf := make([]byte, K+N)
	r := hkdf.New(sha256.New, ikm, nil, d.mkInfo)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		panic(err)
	}
	return buf[0:K:K], buf[K : K+N : K+N]
}

func (d djb) Seal(key MessageKey, plaintext, additionalData []byte) []byte {
	if len(key) != chacha20poly1305.KeySize {
		panic("Seal: invalid message key size: " + strconv.Itoa(len(key)))
	}

	key, nonce := d.derive(key)
	defer secureZero(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		panic(err)
	}
	return aead.Seal(nil, nonce, plaintext, additionalData)
}

func (d djb) Open(key MessageKey, ciphertext, additionalData []byte) ([]byte, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("Open: invalid message key size: %d", len(key))
	}
	key, nonce := d.derive(key)
	defer secureZero(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		panic(err)
	}
	return aead.Open(nil, nonce, ciphertext, additionalData)
}

func (d djb) Header(priv KeyPair, prevChainLength, messageNum int) Header {
	if len(priv) != curve25519.ScalarSize+curve25519.PointSize {
		panic("Header: invalid key pair size: " + strconv.Itoa(len(priv)))
	}
	return Header{
		PublicKey: d.Public(priv),
		PN:        prevChainLength,
		N:         messageNum,
	}
}

func (djb) Concat(additionalData []byte, h Header) []byte {
	return Concat(additionalData, h)
}
