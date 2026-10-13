package procnet

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
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
		d, i      time.Duration
		end, step string
	}{
		{30 * time.Second, time.Second, "+ 3000 ))", "next + 100 ))"},
		{60 * time.Second, 200 * time.Millisecond, "+ 6000 ))", "next + 20 ))"},
		{5 * time.Minute, 1500 * time.Millisecond, "+ 30000 ))", "next + 150 ))"},
	} {
		s := SamplerScript(c.d, c.i)
		for _, want := range []string{"@@podpeers v2", "@@anchor", "read up rest < /proc/uptime", c.end, c.step,
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

// uptimeFile is /proc/uptime where it exists; elsewhere a stand-in in the
// same format, kept current until the test ends, so the script's timing
// logic runs on every machine the tests do.
func uptimeFile(t *testing.T) string {
	if _, err := os.Stat("/proc/uptime"); err == nil {
		return "/proc/uptime"
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "uptime")
	start, stop := time.Now(), make(chan struct{})
	write := func() {
		tmp := p + ".tmp"
		os.WriteFile(tmp, []byte(fmt.Sprintf("%.2f 0.00\n", 1000+time.Since(start).Seconds())), 0o644)
		os.Rename(tmp, p) // whole lines only
	}
	write()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
				write()
			}
		}
	}()
	t.Cleanup(func() { close(stop); <-done })
	return p
}

func TestSamplerScriptRunsOnAFixedGrid(t *testing.T) {
	// The real script under sh. At 100ms the time left to the next tick is
	// under 10 centiseconds, so it must be zero-padded (0.08s, not 0.8s).
	// A broken schedule is off on every run; a loaded machine (the guard
	// sweep runs six of these at once) can delay one sample once. So each
	// case gets three tries, and fails only if all three do.
	uptime := uptimeFile(t)
	for _, c := range []struct {
		d, i time.Duration
		n    int
	}{{2 * time.Second, 200 * time.Millisecond, 11}, {time.Second, 100 * time.Millisecond, 11}} {
		var why string
		for try := 0; try < 3; try++ {
			if why = gridRun(t, uptime, c.d, c.i, c.n); why == "" {
				break
			}
			t.Logf("%s at %s, try %d: %s", c.d, c.i, try+1, why)
		}
		if why != "" {
			t.Errorf("%s at %s: %s", c.d, c.i, why)
		}
	}
}

// gridRun runs the sampler once and says what is wrong with its schedule,
// or "" if nothing is.
func gridRun(t *testing.T, uptime string, d, i time.Duration, n int) string {
	t.Helper()
	script := strings.ReplaceAll(SamplerScript(d, i), "/proc/uptime", uptime)
	out, err := exec.Command("sh", "-c", script).Output()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSamplerOutput(bytes.NewReader(out))
	if err != nil || !parsed.Complete {
		return fmt.Sprintf("err=%v complete=%v", err, parsed.Complete)
	}
	if got := len(parsed.Samples); got != n {
		return fmt.Sprintf("a fixed grid takes %d samples, got %d", n, got)
	}
	// On a fixed grid, each sample sits near its own slot (start + k*i),
	// however late the one before it was. Process starts jitter a sample by
	// tens of milliseconds (more on macOS); a broken schedule is off by most
	// of an interval or more (an unpadded 0.8s sleep for 0.08s, or none).
	for k, smp := range parsed.Samples {
		off := smp.Time.Sub(parsed.Samples[0].Time) - time.Duration(k)*i
		if off < 0 {
			off = -off
		}
		if off > 150*time.Millisecond {
			return fmt.Sprintf("sample %d is %s off its grid slot", k, off)
		}
	}
	return ""
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
		"empty sample":         "@@podpeers v2\n@@anchor 1 2.00\n@@sample \n", // used to panic
		"cut after marker":     "@@podpeers v2\n@@anchor 1 2.00\n@@sample ",
		"headerless empty":     "@@sample \n",
	} {
		if _, err := ParseSamplerOutput(strings.NewReader(in)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestParseRotatedLogKeepsLatestSamples(t *testing.T) {
	// The first part of the log (header, anchor, early samples) was rotated
	// away: the stream starts mid-table. Self-describing sample lines still
	// time the rest; the result is marked truncated and not complete.
	row := "   0: 0A0200C0:2328 076433C6:D431 01 0:0 0:0 0 0 0 1\n"
	in := "   7: 0A0200C0:2328 076433C6:D432 01 0:0 0:0 0 0 0 9\n" + // tail of a lost sample
		"@@sample 1000.40 1700000000 1000.00\n" + hdrTCP + "\n" + row +
		"@@sample 1000.60 1700000000 1000.00\n" + hdrTCP + "\n" + row +
		"@@end\n"
	out, err := ParseSamplerOutput(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if !out.Truncated || out.Complete || len(out.Samples) != 2 {
		t.Fatalf("truncated=%v complete=%v samples=%d", out.Truncated, out.Complete, len(out.Samples))
	}
	if got := out.Samples[0].Time; !got.Equal(time.Unix(1700000000, 0).UTC().Add(400 * time.Millisecond)) {
		t.Errorf("time = %v", got)
	}
	// Without self-describing markers there is nothing to time samples by.
	if _, err := ParseSamplerOutput(strings.NewReader("@@sample 1000.40\n")); err == nil {
		t.Error("a headerless log with bare sample markers must be rejected")
	}
}

// An anchor whose fields are not numbers is an error, not a zero timestamp.
func TestNonNumericAnchorIsAnError(t *testing.T) {
	for _, in := range []string{"@@podpeers v2\n@@anchor x 1.00\n", "@@podpeers v2\n@@anchor 1 y\n"} {
		if _, err := ParseSamplerOutput(strings.NewReader(in)); err == nil || !strings.Contains(err.Error(), "bad anchor") {
			t.Errorf("%q: want a bad anchor error, got %v", in, err)
		}
	}
}

// A socket has a peer when either half of the remote address is set: a UDP
// socket connected to an address with no port is not a listener.
func TestHasRemoteNeedsOnlyOneHalf(t *testing.T) {
	for remote, want := range map[string]bool{
		"0.0.0.0:0":       false,
		"192.0.2.1:0":     true,
		"0.0.0.0:53":      true,
		"192.0.2.1:5353":  true,
		"[::]:0":          false,
		"[2001:db8::1]:0": true,
	} {
		s := Socket{Protocol: UDP, Local: netip.MustParseAddrPort("192.0.2.10:5353"), Remote: netip.MustParseAddrPort(remote)}
		if s.HasRemote() != want || s.IsListener() == want {
			t.Errorf("remote %s: HasRemote %v, IsListener %v; want HasRemote %v", remote, s.HasRemote(), s.IsListener(), want)
		}
	}
}

// A log whose beginning was lost is read from its self-describing samples
// only when their anchor parses whole; half an anchor is no anchor.
func TestHalfAnAnchorIsNoAnchor(t *testing.T) {
	for _, in := range []string{"@@sample 1000.20 x 1000.00\n@@end\n", "@@sample 1000.20 1700000000 y\n@@end\n"} {
		if _, err := ParseSamplerOutput(strings.NewReader(in)); err == nil {
			t.Errorf("%q: want an error, not samples timed from a guessed anchor", in)
		}
	}
}

// Rows are read only inside a sample, after their table's header: a row
// before the first sample, or before any header, is not a socket, and not a
// row that failed to parse either.
func TestRowsOutsideASampleOrTableAreIgnored(t *testing.T) {
	row := "   0: 0A0200C0:2328 076433C6:D431 01 0:0 0:0 0 0 0 1\n"
	in := "@@podpeers v2\n@@anchor 1700000000 1000.00\n" + hdrTCP + "\n" + row + // before any sample
		"@@sample 1000.00\n" + row + // in a sample, before a header
		hdrTCP + "\n" + row + "@@end\n"
	out, err := ParseSamplerOutput(strings.NewReader(in))
	if err != nil || len(out.Samples) != 1 || len(out.Samples[0].Sockets) != 1 || out.Skipped != 0 {
		t.Fatalf("err=%v samples=%+v skipped=%d", err, out.Samples, out.Skipped)
	}
}

// A row needs four fields; the inode is the tenth, and read only when
// present.
func TestRowFieldCountsAtTheEdges(t *testing.T) {
	if _, err := ParseRow(TCP, "0: 0100007F:0035 00000000:0000 0A"); err != nil {
		t.Errorf("four fields are enough: %v", err)
	}
	if _, err := ParseRow(TCP, "0: 0100007F:0035 00000000:0000"); err == nil {
		t.Error("three fields are not")
	}
	nine := "0: 0100007F:0035 00000000:0000 0A 0:0 0:0 0 0 0"
	if s, err := ParseRow(TCP, nine); err != nil || s.Inode != 0 {
		t.Errorf("nine fields: no inode: %+v %v", s, err)
	}
	if s, err := ParseRow(TCP, nine+" 4242"); err != nil || s.Inode != 4242 {
		t.Errorf("ten fields: inode 4242: %+v %v", s, err)
	}
}

// The sleep to the next tick is formatted seconds.centiseconds: 110cs is
// 1.10, not 1.010. With a frozen clock every wait is a whole interval, and
// a stand-in sleep records each one.
func TestSamplerSleepsAreFormattedExactly(t *testing.T) {
	dir := t.TempDir()
	uptime := filepath.Join(dir, "uptime")
	os.WriteFile(uptime, []byte("1000.00 0.00\n"), 0o644)
	log := filepath.Join(dir, "sleeps")
	bin := filepath.Join(dir, "bin")
	os.MkdirAll(bin, 0o755)
	os.WriteFile(filepath.Join(bin, "sleep"), []byte("#!/bin/sh\necho \"$1\" >> "+log+"\n"), 0o755)
	cmd := exec.Command("sh", "-c", strings.ReplaceAll(SamplerScript(2200*time.Millisecond, 1100*time.Millisecond), "/proc/uptime", uptime))
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	got, _ := os.ReadFile(log)
	if string(got) != "1.10\n2.20\n" {
		t.Fatalf("sleeps:\n%s", got)
	}
}
