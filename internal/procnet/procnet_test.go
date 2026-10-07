package procnet

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Rows below use documentation address ranges only (RFC 5737, RFC 3849).
// 192.0.2.10 little-endian hex = 0A0200C0; 198.51.100.7 = 076433C6.
const tcp4Table = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:2328 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4101 1 0000000000000000 100 0 0 10 0
   1: 0A0200C0:2328 076433C6:D431 01 00000000:00000000 00:00000000 00000000     0        0 4102 1 0000000000000000 20 4 30 10 -1
   2: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4103 1 0000000000000000 100 0 0 10 0
`

func TestParseTableIPv4(t *testing.T) {
	socks, skipped, err := ParseTable(TCP, strings.NewReader(tcp4Table))
	if err != nil || skipped != 0 {
		t.Fatalf("err=%v skipped=%d", err, skipped)
	}
	if len(socks) != 3 {
		t.Fatalf("got %d sockets", len(socks))
	}
	want := []Socket{
		{TCP, netip.MustParseAddrPort("0.0.0.0:9000"), netip.MustParseAddrPort("0.0.0.0:0"), Listen, 4101},
		{TCP, netip.MustParseAddrPort("192.0.2.10:9000"), netip.MustParseAddrPort("198.51.100.7:54321"), Established, 4102},
		{TCP, netip.MustParseAddrPort("127.0.0.1:53"), netip.MustParseAddrPort("0.0.0.0:0"), Listen, 4103},
	}
	for i := range want {
		if socks[i] != want[i] {
			t.Errorf("row %d = %+v; want %+v", i, socks[i], want[i])
		}
	}
	if !socks[0].IsListener() || socks[1].IsListener() {
		t.Error("listener classification wrong")
	}
	if socks[0].HasRemote() || !socks[1].HasRemote() {
		t.Error("HasRemote wrong")
	}
}

func TestParseRowIPv6AndMapped(t *testing.T) {
	cases := []struct {
		row          string
		local, remot string
		state        State
	}{
		// 2001:db8::1 port 443 -> 2001:db8::2 port 50000
		{"0: B80D0120000000000000000001000000:01BB B80D0120000000000000000002000000:C350 01 0:0 0:0 0 0 0 77",
			"[2001:db8::1]:443", "[2001:db8::2]:50000", Established},
		// ::ffff:192.0.2.10 port 9000 <- ::ffff:198.51.100.7 port 54321, unmapped to IPv4
		{"1: 0000000000000000FFFF00000A0200C0:2328 0000000000000000FFFF0000076433C6:D431 06 0:0 0:0 0 0 0 0",
			"192.0.2.10:9000", "198.51.100.7:54321", TimeWait},
		// [::]:8080 listening
		{"2: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 0:0 0:0 0 0 0 5",
			"[::]:8080", "[::]:0", Listen},
	}
	for _, c := range cases {
		s, err := ParseRow(TCP, c.row)
		if err != nil {
			t.Fatalf("ParseRow(%q): %v", c.row, err)
		}
		if s.Local != netip.MustParseAddrPort(c.local) || s.Remote != netip.MustParseAddrPort(c.remot) || s.State != c.state {
			t.Errorf("ParseRow(%q) = %v %v %v; want %s %s %v", c.row, s.Local, s.Remote, s.State, c.local, c.remot, c.state)
		}
	}
}

func TestUDPListenerVsConnected(t *testing.T) {
	unconnected, _ := ParseRow(UDP, "0: 00000000:0035 00000000:0000 07 0:0 0:0 0 0 0 1")
	connected, _ := ParseRow(UDP, "1: 0A0200C0:A000 076433C6:0035 01 0:0 0:0 0 0 0 2")
	ephemeralUnbound, _ := ParseRow(UDP, "2: 00000000:0000 00000000:0000 07 0:0 0:0 0 0 0 3")
	if !unconnected.IsListener() {
		t.Error("bound unconnected UDP should be a listener")
	}
	if connected.IsListener() || !connected.HasRemote() {
		t.Error("connected UDP is not a listener and has a remote")
	}
	if ephemeralUnbound.IsListener() {
		t.Error("UDP socket bound to port 0 is not a listener")
	}
}

func TestParseRowRejectsMalformed(t *testing.T) {
	bad := []string{
		"",
		"garbage",
		"0: 0100007F 00000000:0000 0A",       // no port
		"0: ZZ00007F:0035 00000000:0000 0A",  // bad hex
		"0: 0100007F:0035 00000000:0000 XYZ", // bad state
		"0: 01007F:0035 00000000:0000 0A",    // 3-byte address
		"0: 0100007F:FFFFF 00000000:0000 0A", // port overflow
		"0100007F:0035 00000000:0000 0A 0",   // missing slot number
	}
	for _, row := range bad {
		if _, err := ParseRow(TCP, row); err == nil {
			t.Errorf("ParseRow(%q) succeeded; want error", row)
		}
	}
}

func TestParseTableCountsSkippedRows(t *testing.T) {
	in := tcp4Table + "   3: nonsense here\n"
	socks, skipped, err := ParseTable(TCP, strings.NewReader(in))
	if err != nil || len(socks) != 3 || skipped != 1 {
		t.Fatalf("socks=%d skipped=%d err=%v", len(socks), skipped, err)
	}
}

func TestStateString(t *testing.T) {
	if Established.String() != "ESTABLISHED" || Listen.String() != "LISTEN" || State(0x42).String() != "STATE_42" {
		t.Fatal("State.String mismatch")
	}
}

func framed(samples ...string) string {
	var b strings.Builder
	b.WriteString("@@podpeers v1\n")
	for _, s := range samples {
		b.WriteString(s)
	}
	return b.String()
}

func TestParseSamplerOutput(t *testing.T) {
	s1 := "@@sample 1700000000\n@@file tcp\n" + tcp4Table + "@@file tcp6\n  sl  local_address\n@@file udp\n" +
		"  sl  local_address\n   0: 00000000:0035 00000000:0000 07 0:0 0:0 0 0 0 1\n@@file udp6\n"
	s2 := "@@sample 1700000005\n@@file tcp\n   0: 00000000:2328 00000000:0000 0A 0:0 0:0 0 0 0 1\n@@file tcp6\n@@file udp\n@@file udp6\n"
	out, err := ParseSamplerOutput(strings.NewReader(framed(s1, s2, "@@end\n")))
	if err != nil {
		t.Fatal(err)
	}
	if !out.Complete || len(out.Samples) != 2 {
		t.Fatalf("complete=%v samples=%d", out.Complete, len(out.Samples))
	}
	if got := out.Samples[0]; got.Time != time.Unix(1700000000, 0).UTC() || len(got.Sockets) != 4 {
		t.Fatalf("sample0 = %v with %d sockets", got.Time, len(got.Sockets))
	}
	if out.Samples[0].Sockets[3].Protocol != UDP {
		t.Error("udp table rows should be tagged UDP")
	}
	if len(out.Samples[1].Sockets) != 1 {
		t.Errorf("sample1 has %d sockets", len(out.Samples[1].Sockets))
	}
}

func TestParseSamplerOutputTruncated(t *testing.T) {
	s1 := "@@sample 1700000000\n@@file tcp\n" + tcp4Table
	s2 := "@@sample 1700000005\n@@file tcp\n   0: 00000000:2328" // cut mid-row, no end marker
	out, err := ParseSamplerOutput(strings.NewReader(framed(s1, s2)))
	if err != nil {
		t.Fatal(err)
	}
	if out.Complete {
		t.Error("truncated output reported complete")
	}
	if len(out.Samples) != 1 {
		t.Fatalf("want only the finished sample, got %d", len(out.Samples))
	}
}

func TestParseSamplerOutputErrors(t *testing.T) {
	if _, err := ParseSamplerOutput(strings.NewReader("hello\n")); err == nil {
		t.Error("missing header should error")
	}
	if _, err := ParseSamplerOutput(strings.NewReader(framed("@@sample notanumber\n"))); err == nil {
		t.Error("bad sample marker should error")
	}
	if _, err := ParseSamplerOutput(strings.NewReader(framed("@@sample 1\n@@file raw\n"))); err == nil {
		t.Error("unknown table should error")
	}
}

func TestSamplerScript(t *testing.T) {
	for _, c := range []struct {
		d, i     time.Duration
		end, slp string
	}{
		{30 * time.Second, time.Second, "+ 3000 ))", "sleep 1\n"},
		{60 * time.Second, 200 * time.Millisecond, "+ 6000 ))", "sleep 0.2\n"},
		{5 * time.Minute, 1500 * time.Millisecond, "+ 30000 ))", "sleep 1.5\n"},
	} {
		s := SamplerScript(c.d, c.i)
		for _, want := range []string{"@@podpeers v2", "@@anchor", "read up rest < /proc/uptime", c.end, c.slp,
			"cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6", "@@end"} {
			if !strings.Contains(s, want) {
				t.Errorf("script(%s, %s) missing %q:\n%s", c.d, c.i, want, s)
			}
		}
		// Two process starts per sample: exactly one cat and one sleep in the loop.
		loop := s[strings.Index(s, "while :; do"):strings.Index(s, "done")]
		if strings.Count(loop, "cat ") != 1 || strings.Count(loop, "sleep ") != 1 || strings.Contains(loop, "date") {
			t.Errorf("loop must start only cat and sleep:\n%s", loop)
		}
		if strings.Contains(s, "%!") {
			t.Errorf("format verb leaked into script:\n%s", s)
		}
	}
}

// Real kernel header lines (Linux 6.8), trailing spaces trimmed.
const (
	hdrTCP  = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
	hdrTCP6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
	hdrUDP  = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops"
	hdrUDP6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops"
)

func TestParseV2SubSecondAndHeaderClassification(t *testing.T) {
	tcp := "   0: 0A0200C0:2328 076433C6:D431 01 0:0 0:0 0 0 0 1\n"
	udp := "   0: 0A0200C0:A028 C80200C0:0035 01 0:0 0:0 0 0 0 3\n"
	in := "@@podpeers v2\n@@anchor 1700000000 1000.00\n" +
		"@@sample 1000.00\n" + hdrTCP + "\n" + tcp + hdrTCP6 + "\n" + hdrUDP + "\n" + udp + hdrUDP6 + "\n" +
		"@@sample 1000.20\n" + hdrTCP + "\n" + tcp + hdrUDP + "\n" + udp + // tcp6 file absent this time
		"@@sample 1000.45\n" + hdrTCP + "\n" + hdrTCP6 + "\n" + hdrUDP + "\n" + hdrUDP6 + "\n" +
		"@@end\n"
	out, err := ParseSamplerOutput(strings.NewReader(in))
	if err != nil || !out.Complete || len(out.Samples) != 3 {
		t.Fatalf("err=%v complete=%v samples=%d", err, out.Complete, len(out.Samples))
	}
	base := time.Unix(1700000000, 0).UTC()
	for i, off := range []time.Duration{0, 200 * time.Millisecond, 450 * time.Millisecond} {
		if got := out.Samples[i].Time; !got.Equal(base.Add(off)) {
			t.Errorf("sample %d time = %v; want %v", i, got, base.Add(off))
		}
	}
	for i := 0; i < 2; i++ {
		socks := out.Samples[i].Sockets
		if len(socks) != 2 || socks[0].Protocol != TCP || socks[1].Protocol != UDP {
			t.Errorf("sample %d: tables misclassified: %+v", i, socks)
		}
	}
	if len(out.Samples[2].Sockets) != 0 {
		t.Error("empty tables should yield no sockets")
	}
}

func TestParseV2Errors(t *testing.T) {
	for name, in := range map[string]string{
		"sample before anchor": "@@podpeers v2\n@@sample 1000.00\n",
		"bad anchor":           "@@podpeers v2\n@@anchor nope\n",
		"bad sample":           "@@podpeers v2\n@@anchor 1 2.00\n@@sample x\n",
	} {
		if _, err := ParseSamplerOutput(strings.NewReader(in)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}
