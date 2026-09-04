// Package javakeystore reads and writes Java trust stores (JKS and PKCS#12).
//
// It exists so the hook can add a CA to a container's cacerts without needing
// keytool or a JVM inside the container. Only trusted-certificate entries are
// supported: a store holding private keys is refused rather than rewritten.
package javakeystore

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"software.sslmate.com/src/go-pkcs12"
)

// Format identifies the on-disk encoding of a Java trust store.
type Format int

// Supported trust store encodings.
const (
	FormatUnknown Format = iota
	FormatJKS
	FormatPKCS12
)

// String returns the keystore type name as Java knows it.
func (f Format) String() string {
	switch f {
	case FormatJKS:
		return "JKS"
	case FormatPKCS12:
		return "PKCS12"
	default:
		return "unknown"
	}
}

const (
	jksMagic       = 0xFEEDFEED
	jksVersion     = 2
	tagPrivateKey  = 1
	tagTrustedCert = 2
	digestSalt     = "Mighty Aphrodite"
	certTypeX509   = "X.509"

	// jksPassword keys the JKS integrity digest. JSSE skips the check when no
	// password is given, and "changeit" is the universal cacerts password, so
	// writing it keeps both the default trust store lookup and keytool working.
	jksPassword = "changeit"

	// maxEntries bounds allocation when parsing a store from a container image.
	maxEntries = 65536
	// maxCertLen bounds a single DER certificate.
	maxCertLen = 1 << 20
)

// ErrPrivateKeyEntry reports a keystore holding private keys, which this
// package will not rewrite.
var ErrPrivateKeyEntry = errors.New("keystore contains private key entries")

// Entry is one trusted certificate in a store.
type Entry struct {
	Alias string
	Time  time.Time
	Cert  *x509.Certificate
}

// Parse decodes a JKS or password-less/PKCS#12 trust store. The integrity
// digest is not verified: the store's password is unknown at this point.
func Parse(data []byte) (Format, []Entry, error) {
	switch {
	case len(data) >= 4 && binary.BigEndian.Uint32(data[:4]) == jksMagic:
		entries, err := parseJKS(data)
		return FormatJKS, entries, err
	case len(data) > 0 && data[0] == 0x30: // DER SEQUENCE
		entries, err := parsePKCS12(data)
		return FormatPKCS12, entries, err
	default:
		return FormatUnknown, nil, errors.New("unrecognised keystore format")
	}
}

// Encode serialises entries back into the given format.
func Encode(f Format, entries []Entry) ([]byte, error) {
	switch f {
	case FormatJKS:
		return encodeJKS(entries)
	case FormatPKCS12:
		return encodePKCS12(entries)
	default:
		return nil, fmt.Errorf("cannot encode keystore format %s", f)
	}
}

func parseJKS(data []byte) ([]Entry, error) {
	if len(data) < 12+sha1.Size {
		return nil, errors.New("jks: file too short")
	}
	// The trailing SHA-1 digest is not part of the entry stream.
	r := &reader{b: data[:len(data)-sha1.Size]}
	r.skip(4)
	version := r.u4()
	if version != 1 && version != 2 {
		return nil, fmt.Errorf("jks: unsupported version %d", version)
	}
	count := r.u4()
	if r.err != nil {
		return nil, r.err
	}
	if count > maxEntries {
		return nil, fmt.Errorf("jks: entry count %d exceeds limit %d", count, maxEntries)
	}

	entries := make([]Entry, 0, count)
	for i := uint32(0); i < count; i++ {
		tag := r.u4()
		alias := r.utf()
		millis := r.u8()
		if r.err != nil {
			return nil, r.err
		}
		if tag == tagPrivateKey {
			return nil, ErrPrivateKeyEntry
		}
		if tag != tagTrustedCert {
			return nil, fmt.Errorf("jks: unknown entry tag %d", tag)
		}
		if version == 2 {
			r.utf() // certificate type, always X.509
		}
		der := r.blob()
		if r.err != nil {
			return nil, r.err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("jks: entry %q: %w", alias, err)
		}
		entries = append(entries, Entry{Alias: alias, Time: time.UnixMilli(int64(millis)), Cert: cert})
	}
	return entries, r.err
}

func encodeJKS(entries []Entry) ([]byte, error) {
	entries = dedupeAliases(entries)

	var w writer
	w.u4(jksMagic)
	w.u4(jksVersion)
	w.u4(uint32(len(entries)))
	for _, e := range entries {
		if e.Cert == nil {
			return nil, fmt.Errorf("jks: entry %q has no certificate", e.Alias)
		}
		w.u4(tagTrustedCert)
		w.utf(e.Alias)
		w.u8(uint64(entryTime(e).UnixMilli()))
		w.utf(certTypeX509)
		w.u4(uint32(len(e.Cert.Raw)))
		w.raw(e.Cert.Raw)
	}
	if w.err != nil {
		return nil, w.err
	}
	out := w.buf.Bytes()
	digest := jksDigest(out)
	return append(out, digest...), nil
}

// jksDigest reproduces sun.security.provider.JavaKeyStore.getPreKeyedHash.
func jksDigest(data []byte) []byte {
	h := sha1.New()
	for _, u := range utf16.Encode([]rune(jksPassword)) {
		h.Write([]byte{byte(u >> 8), byte(u)})
	}
	h.Write([]byte(digestSalt))
	h.Write(data)
	return h.Sum(nil)
}

func parsePKCS12(data []byte) ([]Entry, error) {
	// cacerts is password-less from JDK 18 onwards and "changeit" before that.
	var lastErr error
	for _, pw := range []string{"", jksPassword} {
		certs, err := pkcs12.DecodeTrustStore(data, pw)
		if err != nil {
			lastErr = err
			continue
		}
		entries := make([]Entry, 0, len(certs))
		for _, c := range certs {
			entries = append(entries, Entry{Alias: aliasFor(c), Cert: c})
		}
		return entries, nil
	}
	return nil, fmt.Errorf("pkcs12: %w", lastErr)
}

func encodePKCS12(entries []Entry) ([]byte, error) {
	entries = dedupeAliases(entries)

	out := make([]pkcs12.TrustStoreEntry, 0, len(entries))
	for _, e := range entries {
		if e.Cert == nil {
			return nil, fmt.Errorf("pkcs12: entry %q has no certificate", e.Alias)
		}
		out = append(out, pkcs12.TrustStoreEntry{Cert: e.Cert, FriendlyName: e.Alias})
	}
	// Password-less: JSSE loads it with any password, so no secret has to travel
	// through JAVA_TOOL_OPTIONS.
	return pkcs12.Passwordless.EncodeTrustStoreEntries(out, "")
}

// dedupeAliases makes every alias unique. Both formats key entries by alias, so
// duplicates (four roots share CN=GlobalSign) would silently drop certificates.
func dedupeAliases(entries []Entry) []Entry {
	seen := make(map[string]struct{}, len(entries))
	out := make([]Entry, len(entries))
	copy(out, entries)
	for i := range out {
		base := out[i].Alias
		if base == "" {
			base = "cert"
		}
		alias := base
		for n := 2; ; n++ {
			if _, taken := seen[alias]; !taken {
				break
			}
			alias = fmt.Sprintf("%s-%d", base, n)
		}
		seen[alias] = struct{}{}
		out[i].Alias = alias
	}
	return out
}

func entryTime(e Entry) time.Time {
	if e.Time.IsZero() {
		return time.Now()
	}
	return e.Time
}

// aliasFor mirrors keytool's lowercase alias convention.
func aliasFor(c *x509.Certificate) string {
	if cn := c.Subject.CommonName; cn != "" {
		return strings.ToLower(cn)
	}
	return strings.ToLower(c.Subject.String())
}

// reader is a bounds-checked big-endian reader; the first error is sticky.
type reader struct {
	b   []byte
	i   int
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || r.i+n > len(r.b) {
		r.err = errors.New("jks: truncated keystore")
		return nil
	}
	out := r.b[r.i : r.i+n]
	r.i += n
	return out
}

func (r *reader) skip(n int) { r.take(n) }

func (r *reader) u4() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

func (r *reader) u8() uint64 {
	b := r.take(8)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

// utf reads a Java modified-UTF-8 string. Aliases and type names are ASCII in
// practice, so the bytes are kept verbatim and written back unchanged.
func (r *reader) utf() string {
	b := r.take(2)
	if b == nil {
		return ""
	}
	return string(r.take(int(binary.BigEndian.Uint16(b))))
}

func (r *reader) blob() []byte {
	n := r.u4()
	if r.err != nil {
		return nil
	}
	if n > maxCertLen {
		r.err = fmt.Errorf("jks: certificate length %d exceeds limit %d", n, maxCertLen)
		return nil
	}
	return r.take(int(n))
}

type writer struct {
	buf bytes.Buffer
	err error
}

func (w *writer) raw(b []byte) {
	if w.err == nil {
		w.buf.Write(b)
	}
}

func (w *writer) u4(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	w.raw(b[:])
}

func (w *writer) u8(v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	w.raw(b[:])
}

func (w *writer) utf(s string) {
	if len(s) > 0xFFFF {
		w.err = fmt.Errorf("jks: string too long (%d bytes)", len(s))
		return
	}
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(len(s)))
	w.raw(b[:])
	w.raw([]byte(s))
}
