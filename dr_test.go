package dr

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	mrand "github.com/ericlagergren/saferand"
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

		const (
			N = 500
		)

		send, recv := alice, bob
		plaintext := make([]byte, 4096)
		ad := make([]byte, 172)
		for i := 0; i < N; i++ {
			rand.Read(plaintext)
			rand.Read(ad)
			msg, err := send.Seal(plaintext, ad)
			if err != nil {
				t.Fatalf("#%d: %v", i, err)
			}
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

		const (
			N = 500
		)
		msgs := make([]Message, N)
		ad := make([]byte, 100)
		plaintext := make([]byte, 100)
		for i := range msgs {
			msgs[i], err = alice.Seal(plaintext, ad)
			if err != nil {
				t.Fatalf("#%d: %v", i, err)
			}
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

func TestResume(t *testing.T) {
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

		const (
			N = 500
		)

		send, recv := alice, bob
		plaintext := make([]byte, 4096)
		ad := make([]byte, 172)
		for i := 0; i < N; i++ {
			if _, err := rand.Read(plaintext); err != nil {
				t.Fatal(err)
			}
			if _, err := rand.Read(ad); err != nil {
				t.Fatal(err)
			}
			msg, err := send.Seal(plaintext, ad)
			if err != nil {
				t.Fatalf("#%d: %v", i, err)
			}
			got, err := recv.Open(msg, ad)
			if err != nil {
				t.Fatalf("#%d: %v", i, err)
			}
			if !hmac.Equal(plaintext, got) {
				t.Fatalf("#%d: expected %q, got %q", i, plaintext, got)
			}

			// Swap and refresh state.
			rs, ss := send.state, recv.state

			send, err = Resume(fn(t), ss)
			if err != nil {
				t.Fatal(err)
			}
			recv, err = Resume(fn(t), rs)
			if err != nil {
				t.Fatal(err)
			}
		}
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			test(t, tc.fn)
		})
	}
}

func TestSendWithRecv(t *testing.T) {
	for _, tc := range testCases {
		fn := tc.fn
		t.Run(tc.name, func(t *testing.T) {
			SK := make([]byte, 32)
			priv, err := fn(t).Generate(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			bob, err := NewRecv(fn(t), SK, priv)
			if err != nil {
				t.Fatal(err)
			}
			panicked := didPanic(func() {
				bob.Seal(nil, nil)
			})
			if !panicked {
				t.Fatal("should have panicked")
			}
		})
	}
}

func didPanic(fn func()) (panicked bool) {
	defer func() {
		panicked = recover() != nil
	}()
	fn()
	return
}
