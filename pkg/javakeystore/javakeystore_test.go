package javakeystore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"
)

// TestParseAndEncodeMatchesKeytool round-trips a keystore written by keytool.
// Byte equality covers the entry layout, the modified-UTF-8 strings and the
// SHA-1 integrity digest all at once.
func TestParseAndEncodeMatchesKeytool(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/keytool.jks")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	format, entries, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if format != FormatJKS {
		t.Fatalf("Parse() format = %s, want JKS", format)
	}
	if len(entries) != 1 || entries[0].Alias != "testca" {
		t.Fatalf("Parse() entries = %+v, want one entry aliased testca", entries)
	}

	out, err := Encode(format, entries)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if !bytes.Equal(data, out) {
		t.Fatalf("Encode() output differs from keytool: got %d bytes, want %d", len(out), len(data))
	}
}

func TestRoundTripAddsCertificate(t *testing.T) {
	t.Parallel()

	for _, format := range []Format{FormatJKS, FormatPKCS12} {
		t.Run(format.String(), func(t *testing.T) {
			t.Parallel()

			first := newTestCert(t, "first")
			second := newTestCert(t, "second")

			encoded, err := Encode(format, []Entry{
				{Alias: "first", Cert: first, Time: time.UnixMilli(1_700_000_000_000)},
				{Alias: "second", Cert: second},
			})
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}

			gotFormat, entries, err := Parse(encoded)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if gotFormat != format {
				t.Fatalf("Parse() format = %s, want %s", gotFormat, format)
			}
			if len(entries) != 2 {
				t.Fatalf("Parse() returned %d entries, want 2", len(entries))
			}
			if !bytes.Equal(entries[0].Cert.Raw, first.Raw) || !bytes.Equal(entries[1].Cert.Raw, second.Raw) {
				t.Fatal("Parse() returned different certificates than were encoded")
			}
		})
	}
}

// Duplicate aliases silently drop entries in both formats: four of the roots
// shipped with the JDK share CN=GlobalSign.
func TestEncodeMakesAliasesUnique(t *testing.T) {
	t.Parallel()

	for _, format := range []Format{FormatJKS, FormatPKCS12} {
		t.Run(format.String(), func(t *testing.T) {
			t.Parallel()

			encoded, err := Encode(format, []Entry{
				{Alias: "dup", Cert: newTestCert(t, "a")},
				{Alias: "dup", Cert: newTestCert(t, "b")},
				{Alias: "dup", Cert: newTestCert(t, "c")},
			})
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}

			_, entries, err := Parse(encoded)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if len(entries) != 3 {
				t.Fatalf("Parse() returned %d entries, want 3", len(entries))
			}
			seen := map[string]struct{}{}
			for _, e := range entries {
				if _, dup := seen[e.Alias]; dup {
					t.Fatalf("duplicate alias %q survived encoding", e.Alias)
				}
				seen[e.Alias] = struct{}{}
			}
		})
	}
}

func TestParseRejectsPrivateKeyEntry(t *testing.T) {
	t.Parallel()

	// magic, version 2, one entry, tag 1 (private key), empty alias, timestamp.
	store := append([]byte{
		0xFE, 0xED, 0xFE, 0xED,
		0x00, 0x00, 0x00, 0x02,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00,
		0, 0, 0, 0, 0, 0, 0, 0,
	}, make([]byte, 20)...) // trailing digest

	if _, _, err := Parse(store); !errors.Is(err, ErrPrivateKeyEntry) {
		t.Fatalf("Parse() error = %v, want ErrPrivateKeyEntry", err)
	}
}

func TestParseRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	tests := map[string][]byte{
		"empty":          {},
		"unknown format": []byte("not a keystore"),
		"truncated jks":  {0xFE, 0xED, 0xFE, 0xED, 0, 0, 0, 2},
		"absurd count": append([]byte{
			0xFE, 0xED, 0xFE, 0xED,
			0x00, 0x00, 0x00, 0x02,
			0xFF, 0xFF, 0xFF, 0xFF,
		}, make([]byte, 20)...),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := Parse(data); err == nil {
				t.Fatal("Parse() error = nil, want an error")
			}
		})
	}
}

func newTestCert(t *testing.T, cn string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate() error = %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate() error = %v", err)
	}
	return cert
}
