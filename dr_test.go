package dr

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	mrand "golang.org/x/exp/rand"
)

var testCases = []struct {
	name string
	fn   func(*testing.T) Ratchet
}{
	{"P-256", func(t *testing.T) Ratchet {
		return NIST(elliptic.P256(), sha256.New, t.Name())
	}},
	{"DJB", func(t *testing.T) Ratchet { return DJB(t.Name()) }},
}

// TestAliceBob is a simple positive test that ping-pongs
// messages back and forth.
func TestAliceBob(t *testing.T) {
	test := func(t *testing.T, fn func(*testing.T) Ratchet) {
		SK := make([]byte, 32)
		_, err := rand.Read(SK)
		if err != nil {
			t.Fatal(err)
		}

		priv, err := fn(t).Generate(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		bob, err := NewRecv(fn(t), SK, priv)
		if err != nil {
			t.Fatal(err)
		}
		alice, err := NewSend(fn(t), SK, fn(t).Public(priv))
		if err != nil {
			t.Fatal(err)
		}

		N := 500

		send, recv := alice, bob
		plaintext := make([]byte, 100)
		ad := make([]byte, 100)
		for i := 0; i < N; i++ {
			mrand.Read(plaintext)
			mrand.Read(ad)
			msg := send.Seal(plaintext, ad)
			got, err := recv.Open(msg, ad)
			if err != nil {
				t.Fatalf("#%d: %v", i, err)
			}
			if !hmac.Equal(plaintext, got) {
				t.Fatalf("#%d: expected %q, got %q", i, plaintext, got)
			}
			send, recv = recv, send
		}
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			test(t, tc.fn)
		})
	}
}

// TestOutOfOrder tests out-of-order messages.
func TestOutOfOrder(t *testing.T) {
	test := func(t *testing.T, fn func(*testing.T) Ratchet) {
		SK := make([]byte, 32)
		_, err := rand.Read(SK)
		if err != nil {
			t.Fatal(err)
		}

		priv, err := fn(t).Generate(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		bob, err := NewRecv(fn(t), SK, priv)
		if err != nil {
			t.Fatal(err)
		}
		alice, err := NewSend(fn(t), SK, fn(t).Public(priv))
		if err != nil {
			t.Fatal(err)
		}

		N := 500
		msgs := make([]Message, N)
		ad := make([]byte, 100)
		plaintext := make([]byte, 100)
		for i := range msgs {
			msgs[i] = alice.Seal(plaintext, ad)
		}
		mrand.Shuffle(len(msgs), func(i, j int) {
			msgs[i], msgs[j] = msgs[j], msgs[i]
		})

		for i, msg := range msgs {
			got, err := bob.Open(msg, ad)
			if err != nil {
				t.Fatalf("#%d: %v", i, err)
			}
			if !hmac.Equal(plaintext, got) {
				t.Fatalf("#%d: expected %#x, got %#x", i, plaintext, got)
			}
		}
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			test(t, tc.fn)
		})
	}
}
