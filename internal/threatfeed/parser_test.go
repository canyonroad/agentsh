package threatfeed

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostfileParser_Standard(t *testing.T) {
	input := "# comment line\n127.0.0.1 localhost\n0.0.0.0 malware.example.com\n127.0.0.1 phishing.bad.org  # trailing comment\n"
	p := &HostfileParser{}
	domains, err := p.Parse(strings.NewReader(input))
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"malware.example.com", "phishing.bad.org"}, domains)
}

func TestHostfileParser_SkipsLocalhost(t *testing.T) {
	input := "127.0.0.1 localhost\n0.0.0.0 localhost\n0.0.0.0 evil.com\n"
	p := &HostfileParser{}
	domains, err := p.Parse(strings.NewReader(input))
	require.NoError(t, err)
	assert.Equal(t, []string{"evil.com"}, domains)
}

func TestHostfileParser_Deduplicates(t *testing.T) {
	input := "0.0.0.0 evil.com\n127.0.0.1 evil.com\n0.0.0.0 EVIL.COM\n"
	p := &HostfileParser{}
	domains, err := p.Parse(strings.NewReader(input))
	require.NoError(t, err)
	assert.Equal(t, []string{"evil.com"}, domains)
}

func TestHostfileParser_EmptyInput(t *testing.T) {
	p := &HostfileParser{}
	domains, err := p.Parse(strings.NewReader(""))
	require.NoError(t, err)
	assert.Empty(t, domains)
}

func TestHostfileParser_CommentsOnly(t *testing.T) {
	input := "# This is a comment\n# Another comment\n"
	p := &HostfileParser{}
	domains, err := p.Parse(strings.NewReader(input))
	require.NoError(t, err)
	assert.Empty(t, domains)
}

func TestDomainListParser_Standard(t *testing.T) {
	input := "# Phishing domains\nevil.com\nbad.org\n\nUPPER.NET\n"
	p := &DomainListParser{}
	domains, err := p.Parse(strings.NewReader(input))
	require.NoError(t, err)
	assert.Equal(t, []string{"evil.com", "bad.org", "upper.net"}, domains)
}

func TestDomainListParser_Deduplicates(t *testing.T) {
	input := "evil.com\nevil.com\nEVIL.COM\n"
	p := &DomainListParser{}
	domains, err := p.Parse(strings.NewReader(input))
	require.NoError(t, err)
	assert.Equal(t, []string{"evil.com"}, domains)
}

func TestDomainListParser_EmptyInput(t *testing.T) {
	p := &DomainListParser{}
	domains, err := p.Parse(strings.NewReader(""))
	require.NoError(t, err)
	assert.Empty(t, domains)
}

func TestDomainListParser_InlineComments(t *testing.T) {
	input := "evil.com # known malware\nbad.org#phishing\n# full comment\ngood.net\n"
	p := &DomainListParser{}
	domains, err := p.Parse(strings.NewReader(input))
	require.NoError(t, err)
	assert.Equal(t, []string{"evil.com", "bad.org", "good.net"}, domains)
}

func TestHostfileParser_TrailingDot(t *testing.T) {
	input := "0.0.0.0 evil.com.\n0.0.0.0 bad.org\n"
	p := &HostfileParser{}
	domains, err := p.Parse(strings.NewReader(input))
	require.NoError(t, err)
	assert.Equal(t, []string{"evil.com", "bad.org"}, domains)
}

func TestDomainListParser_TrailingDot(t *testing.T) {
	input := "evil.com.\nbad.org\n"
	p := &DomainListParser{}
	domains, err := p.Parse(strings.NewReader(input))
	require.NoError(t, err)
	assert.Equal(t, []string{"evil.com", "bad.org"}, domains)
}

func TestHostfileParser_LongLine(t *testing.T) {
	// Line longer than default bufio.Scanner token size (64 KiB).
	longComment := strings.Repeat("x", 100*1024)
	input := "0.0.0.0 evil.com # " + longComment + "\n0.0.0.0 bad.org\n"
	p := &HostfileParser{}
	domains, err := p.Parse(strings.NewReader(input))
	require.NoError(t, err)
	assert.Contains(t, domains, "evil.com")
	assert.Contains(t, domains, "bad.org")
}

func TestDomainListParser_LongLine(t *testing.T) {
	// Line longer than default bufio.Scanner token size (64 KiB).
	longComment := strings.Repeat("x", 100*1024)
	input := "evil.com # " + longComment + "\nbad.org\n"
	p := &DomainListParser{}
	domains, err := p.Parse(strings.NewReader(input))
	require.NoError(t, err)
	assert.Contains(t, domains, "evil.com")
	assert.Contains(t, domains, "bad.org")
}
