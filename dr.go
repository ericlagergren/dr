// Package dr implements the Double Ratchet scheme.
//
// Overview
//
// What follows is a high-level overview of the Double Ratchet
// scheme, mostly paraphrased from the whitepaper [signal].
//
// Double Ratchet Algorithm
//
// The Double Ratchet Algorithm is comprised of two "ratchets"
// over three KDF chains. A ratchet is a construction where each
// step forward is constructed with a one-way function, making it
// impossible to recover previous keys (forward secrecy).
//
// KDF Chains
//
// KDF chains are the core construction of the Double Ratchet
// Algorithm.
//
// A KDF chain is a construction where part of the output of
// the KDF is used to key the next invocation of the KDF, and the
// rest is used for some other purpose (like message encryption).
//
//              key
//               v
//            ┌─────┐
//    input > │ KDF │
//            └──┬──┘
//               ├─> output key
//               v
//              key
//               v
//            ┌─────┐
//    input > │ KDF │
//            └──┬──┘
//               ├─> output key
//               v
//              key
//
// This construction has some desirable properties, including
// forward security and resilience against attackers that can
// manipulate the KDF inputs.
//
// In a Double Ratchet session both parties have three chains:
//
//    1. root chain
//    2. sending chain
//    3. receiving chain
//
// Each party's sending chain will match the other's receiving
// chain and vice versa. The root chain is the same for both
// parties.
//
// Diffie-Hellman Ratchet
//
// Both parties have their own ephemeral ratchet key pair. Each
// time a message is sent the sender generates a new key pair and
// attaches the new public key to the message. The sender then
// uses the shared Diffie-Hellman value as input to the sending
// chain, advancing it one step. Likewise, when the recipient
// receives the message (and is informed of the sender's new
// public key), the recipient uses the shared Diffie-Hellman
// value as input to the receiving chain, advancing it one step
// and keeping it in sync with the other party's sending chain.
//
// In other words, when Alice sends Bob a message she creates
// a new Diffie-Hellman key pair and uses her private key and
// Bob's public key to compute the shared Diffie-Hellman value.
// When Bob receives the message, he uses Alice's new public key
// and his private key to also compute the shared Diffie-Hellman
// value.
//
// Symmetric-Key Ratchet
//
// As each message is sent and received the sending and receiving
// chains are advanced. The output of advancing each chain is
// used as a message key to encrypt each individual message.
//
// Notes
//
// This package does not implement encrypted headers.
//
// References
//
// More information can be found in the following links.
//
//    [signal]: https://signal.org/docs/specifications/doubleratchet/doubleratchet.pdf
//
package dr

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime"
)

// PrivateKey is a complete (private, public) key pair.
type PrivateKey []byte

// PublicKey is a peer's public.
type PublicKey []byte

// RootKey is a key generated by each step in the root chain.
//
// RootKeys are always 32 bytes.
type RootKey []byte

// ChainKey is an ephemeral key used to key the KDF used to
// generate message keys.
//
//              chain key
//                  v
//               ┌─────┐
//    constant > │ kdf │
//               └──┬──┘
//                  ├─> message key
//                  v
//               chain key
//                  v
//               ┌─────┐
//    constant > │ kdf │
//               └──┬──┘
//                  ├─> message key
//                  v
//               chain key
//
// ChainKeys are always 32 bytes.
type ChainKey []byte

// MessageKey is an ephemeral key used to encrypt a single
// message.
//
// MessageKeys are output from the sending and receiving KDF
// chains.
//
// MessageKeys are always 32 bytes.
type MessageKey []byte

// Header is generated alongside each message.
type Header struct {
	// PublicKey is the sender's new public key.
	PublicKey []byte
	// PN is the previous chain length.
	PN int
	// N is the current message number.
	N int
}

// Append serializes the Header and appends it to buf.
func (h Header) Append(buf []byte) []byte {
	n := len(buf)
	buf = append(buf, make([]byte, 16+len(h.PublicKey))...)
	binary.BigEndian.PutUint64(buf[n:n+8], uint64(h.PN))
	binary.BigEndian.PutUint64(buf[n+8:n+16], uint64(h.N))
	buf = append(buf[n+16:], h.PublicKey...)
	return buf
}

// Decode deserializes a Header from data.
func (h *Header) Decode(data []byte) error {
	if len(data) < 16 {
		return fmt.Errorf("invalid data length: %d", len(data))
	}
	h.PN = int(binary.BigEndian.Uint64(data[0:8]))
	h.N = int(binary.BigEndian.Uint64(data[8:16]))
	h.PublicKey = append(h.PublicKey[:0], data[16:]...)
	return nil
}

// Ratchet implements the Double Ratchet scheme.
//
// Ratchet should be safe for concurrent use by multiple distinct
// goroutines.
type Ratchet interface {
	// Generate creates a new Diffie-Hellman pair.
	//
	// Generate might use entropy from the provided Reader.
	Generate(io.Reader) (PrivateKey, error)
	// Public returns a copy of the public key portion of the key
	// pair.
	Public(PrivateKey) PublicKey
	// DH returns the Diffie-Hellman value computed with the key
	// pair and public key.
	DH(PrivateKey, PublicKey) ([]byte, error)
	// KDFrk applies a KDF keyed by the root key to the
	// Diffie-Hellman value and returns a (root key, chain key)
	// pair.
	KDFrk(RootKey, []byte) (RootKey, ChainKey)
	// KDFck applies a KDF keyed by the chain key to some
	// constant value and returns a (root key, chain key) pair.
	KDFck(ChainKey) (ChainKey, MessageKey)
	// Seal encrypts and authenticates plaintext, authenticates
	// additionalData, and appends the ciphertext to dst.
	//
	// Because each message key is only used once the nonce can
	// be handled in one of several ways:
	//
	//    1. fixed to a constant
	//    2. derived from mk alongside an independent AEAD
	//       encryption key
	//    3. derived as additional output of KDFck
	//    4. chosen randomly and transmitted
	//
	Seal(key MessageKey, plaintext, additionalData []byte) []byte
	// Open decrypts and authenticates ciphertext, authenticates
	// additionalData, and appends the plaintext to dst.
	Open(key MessageKey, ciphertext, additionalData []byte) ([]byte, error)
	// Header creates a message header from the key pair,
	// previous chain length, and current message number.
	//
	// The header contains the Diffie-Hellman public ratchet key.
	Header(priv PrivateKey, prevChainLength, messageNum int) Header
	// Concat encodes a message header and prepends the
	// additional data.
	//
	// Concact should ensure that the additional data and header
	// can be differentiated.
	//
	// See the Concat function for a default implementation.
	Concat(additionalData []byte, h Header) []byte
}

// Concat is a default implementation of Ratchet.Concat.
func Concat(additionalData []byte, h Header) []byte {
	const (
		max64 = binary.MaxVarintLen64
	)
	buf := make([]byte, 0, max64+len(additionalData)+8+len(h.PublicKey))
	i := binary.PutVarint(buf[:max64], int64(len(additionalData)))
	buf = append(buf[:i], additionalData...)
	buf = h.Append(buf)
	return buf
}

// State is the current state of a session.
type State struct {
	// DHs is the sending (self) ratchet key pair.
	DHs PrivateKey
	// DHr is the peer's ratchet public key.
	DHr PublicKey
	// RK is the current root key.
	RK RootKey
	// CKs is the sending chain key.
	CKs ChainKey
	// CKr is the receivinb chain key.
	CKr ChainKey
	// NS is the sending message number.
	Ns int
	// Nr is the receiving message number.
	Nr int
	// PN is the number of messages in the previous sending
	// chain.
	PN int
}

// Clone performs a deep copy of the session state.
func (s *State) Clone() *State {
	return &State{
		DHs: append(PrivateKey(nil), s.DHs...),
		DHr: append(PublicKey(nil), s.DHr...),
		RK:  append(RootKey(nil), s.RK...),
		CKs: append(ChainKey(nil), s.CKs...),
		CKr: append(ChainKey(nil), s.CKr...),
		Ns:  s.Ns,
		Nr:  s.Nr,
		PN:  s.PN,
	}
}

func (s *State) wipe() {
	wipe(s.DHs)
	wipe(s.DHr)
	wipe(s.RK)
	wipe(s.CKs)
	wipe(s.CKr)
}

// ErrNotFound is returned by Store when a message key is not
// found in the Store.
var ErrNotFound = errors.New("dr: key not found")

// Store saves session state.
type Store interface {
	// Save saves the state.
	Save(s *State) error
	// StoreKey stores a skipped message's key under the (Nr,
	// PublicKey) tuple.
	//
	// StoreKey must return an error if too many messages have
	// been Skipped.
	StoreKey(Nr int, pub PublicKey, key MessageKey) error
	// LoadKey retrieves a message key using the (Nr, PublicKey)
	// tuple.
	//
	// If the message key is not found LoadKey returns
	// ErrNotFound.
	LoadKey(Nr int, pub PublicKey) (MessageKey, error)
	// DeleteKey removes a message key using the (Nr, PublicKey)
	// tuple.
	DeleteKey(Nr int, pub PublicKey) error
}

// memory is an in-memory Store.
type memory struct {
	maxSkip int
	keys    map[string][]byte
}

var _ Store = (*memory)(nil)

func (memory) key(Nr int, pub PublicKey) string {
	return fmt.Sprintf("%d:%x", Nr, pub)
}

func (m *memory) Save(_ *State) error {
	return nil
}

func (m *memory) StoreKey(Nr int, pub PublicKey, key MessageKey) error {
	if m.keys == nil {
		m.keys = make(map[string][]byte)
	}
	if len(m.keys) > m.maxSkip {
		return errors.New("too many skipped messages")
	}
	m.keys[m.key(Nr, pub)] = key
	return nil
}

func (m *memory) LoadKey(Nr int, pub PublicKey) (MessageKey, error) {
	key, ok := m.keys[m.key(Nr, pub)]
	if !ok {
		return nil, ErrNotFound
	}
	return key, nil
}

func (m *memory) DeleteKey(Nr int, pub PublicKey) error {
	delete(m.keys, m.key(Nr, pub))
	return nil
}

// Session encapsulates an asynchronous conversation between two
// parties.
type Session struct {
	// r is the underlying Ratchet.
	r Ratchet
	// state is the current session state.
	state *State
	// store is the underlying session stte store.
	store Store
}

// defaultMaxSkip is the default maximum number of messages that
// can be skipped.
const defaultMaxSkip = 1000

// Option configures a Session.
type Option func(*Session)

// WithStore configures some backing store for saving state and
// skipped messages.
//
// Saving session state allows the session to be paused and
// resumed at a later time.
//
// Messages are skipped and queued when they arrive out of order.
//
// By default, skipped messages are stored in memory and sessions
// are ephemeral.
func WithStore(t Store) Option {
	return func(s *Session) {
		s.store = t
	}
}

// Resume continues an existing Session.
func Resume(r Ratchet, state *State, opts ...Option) (*Session, error) {
	s := &Session{
		r:     r,
		state: state,
	}
	for _, fn := range opts {
		fn(s)
	}
	if s.store == nil {
		s.store = &memory{maxSkip: defaultMaxSkip}
	}
	return s, nil
}

// NewSend creates a new Session for initiating communication
// with some peer.
//
// The shared key SK must be negotiated with the peer ahead of
// time.
func NewSend(r Ratchet, SK []byte, peer PublicKey, opts ...Option) (*Session, error) {
	s := &Session{
		r: r,
	}
	for _, fn := range opts {
		fn(s)
	}
	if s.store == nil {
		s.store = &memory{maxSkip: defaultMaxSkip}
	}
	priv, err := r.Generate(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("NewSend: Generate failed: %w", err)
	}
	dh, err := r.DH(priv, peer)
	if err != nil {
		return nil, fmt.Errorf("NewSend: DH failed: %w", err)
	}
	rk, ck := r.KDFrk(SK, dh)
	s.state = &State{
		DHs: priv,
		DHr: peer,
		RK:  rk,
		CKs: ck,
	}
	return s, nil
}

// NewRecv creates a new Session for receiving communication
// initiated by some peer.
//
// The shared key SK must be negotiated with the peer ahead of
// time.
func NewRecv(r Ratchet, SK []byte, priv PrivateKey, opts ...Option) (*Session, error) {
	s := &Session{
		r: r,
	}
	for _, fn := range opts {
		fn(s)
	}
	if s.store == nil {
		s.store = &memory{maxSkip: defaultMaxSkip}
	}
	s.state = &State{
		DHs: priv,
		RK:  SK,
	}
	return s, nil
}

// Message is a messages encrypted with the Double Ratchet
// Algorithm.
type Message struct {
	Header     Header
	Ciphertext []byte
}

// Seal encrypts and authenticates plaintext, authenticates
// additionalData, and returns the resulting message.
func (s *Session) Seal(plaintext, additionalData []byte) (Message, error) {
	state := s.state

	cks, mk := s.r.KDFck(state.CKs)
	h := s.r.Header(state.DHs, state.PN, state.Ns)
	additionalData = s.r.Concat(additionalData, h)
	msg := Message{
		Header:     h,
		Ciphertext: s.r.Seal(mk, plaintext, additionalData),
	}
	if err := s.store.Save(s.state); err != nil {
		return Message{}, err
	}
	state.CKs = cks
	state.Ns++
	return msg, nil
}

// Open decrypts and authenticates ciphertext, authenticates
// additionalData, and returns the resulting plaintext.
func (s *Session) Open(msg Message, additionalData []byte) ([]byte, error) {
	h := msg.Header

	switch mk, err := s.store.LoadKey(h.N, h.PublicKey); {
	case err == nil:
		plaintext, err := s.r.Open(mk,
			msg.Ciphertext, s.r.Concat(additionalData, h))
		if err != nil {
			return nil, err
		}
		err = s.store.DeleteKey(h.N, h.PublicKey)
		if err != nil {
			wipe(plaintext)
			return nil, err
		}
		return plaintext, nil
	case errors.Is(err, ErrNotFound):
		// OK
	default:
		return nil, err
	}

	// Create a temporary state so that failures aren't
	// persisted.
	tmp := s.state.Clone()

	if !hmac.Equal(h.PublicKey, tmp.DHr) {
		if err := tmp.skip(s.store, s.r, h.PN); err != nil {
			return nil, err
		}
		err := tmp.ratchet(s.r, h.PublicKey)
		if err != nil {
			return nil, err
		}
	}
	if err := tmp.skip(s.store, s.r, h.N); err != nil {
		return nil, err
	}

	var mk MessageKey
	tmp.CKr, mk = s.r.KDFck(tmp.CKr)
	tmp.Nr++
	plaintext, err := s.r.Open(mk,
		msg.Ciphertext, s.r.Concat(additionalData, h))
	if err != nil {
		return nil, err
	}
	if err := s.store.Save(tmp); err != nil {
		wipe(plaintext)
		return nil, err
	}
	s.state.wipe()
	s.state = tmp
	return plaintext, nil
}

// skip marks each message in [state.Nr, until) as skipped.
func (s *State) skip(store Store, r Ratchet, until int) error {
	if s.CKr == nil {
		return nil
	}
	for s.Nr < until {
		var mk MessageKey
		s.CKr, mk = r.KDFck(s.CKr)
		err := store.StoreKey(s.Nr, s.DHr, mk)
		if err != nil {
			return err
		}
		s.Nr++
	}
	return nil
}

// ratchet advances the state.
func (s *State) ratchet(r Ratchet, pub PublicKey) error {
	s.PN = s.Ns
	s.Ns = 0
	s.Nr = 0
	s.DHr = pub

	dh, err := r.DH(s.DHs, s.DHr)
	if err != nil {
		return err
	}
	s.RK, s.CKr = r.KDFrk(s.RK, dh)

	s.DHs, err = r.Generate(rand.Reader)
	if err != nil {
		return err
	}
	dh, err = r.DH(s.DHs, s.DHr)
	if err != nil {
		return err
	}
	s.RK, s.CKs = r.KDFrk(s.RK, dh)
	return nil
}

//go:noinline
func wipe(p []byte) {
	for i := range p {
		p[i] = 0
	}
	runtime.KeepAlive(p)
}
