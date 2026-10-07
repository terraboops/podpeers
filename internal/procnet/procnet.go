// Package procnet parses the kernel's socket tables (/proc/net/tcp, tcp6, udp,
// udp6) and the framed sampler output that podpeers' debug container emits.
//
// Reading these files is the dependency-free equivalent of `netstat -tun`: every
// container in a pod shares one network namespace, so an ephemeral container
// that cats /proc/net/* sees exactly the pod's sockets.
package procnet

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Protocol is "tcp" or "udp". IPv4 and IPv6 sockets share a protocol name; the
// address family is carried by the addresses themselves.
type Protocol string

const (
	TCP Protocol = "tcp"
	UDP Protocol = "udp"
)

// State is the kernel's socket state (include/net/tcp_states.h).
type State uint8

const (
	Established State = 0x01
	SynSent     State = 0x02
	SynRecv     State = 0x03
	FinWait1    State = 0x04
	FinWait2    State = 0x05
	TimeWait    State = 0x06
	Close       State = 0x07
	CloseWait   State = 0x08
	LastAck     State = 0x09
	Listen      State = 0x0A
	Closing     State = 0x0B
)

var stateNames = map[State]string{
	Established: "ESTABLISHED", SynSent: "SYN_SENT", SynRecv: "SYN_RECV",
	FinWait1: "FIN_WAIT1", FinWait2: "FIN_WAIT2", TimeWait: "TIME_WAIT",
	Close: "CLOSE", CloseWait: "CLOSE_WAIT", LastAck: "LAST_ACK",
	Listen: "LISTEN", Closing: "CLOSING",
}

func (s State) String() string {
	if n, ok := stateNames[s]; ok {
		return n
	}
	return fmt.Sprintf("STATE_%02X", uint8(s))
}

// Socket is one row of a /proc/net socket table.
type Socket struct {
	Protocol Protocol
	Local    netip.AddrPort
	Remote   netip.AddrPort
	State    State
	Inode    uint64
}

// IsListener reports whether the socket is a server endpoint: a TCP socket in
// LISTEN, or an unconnected UDP socket bound to a port.
func (s Socket) IsListener() bool {
	switch s.Protocol {
	case TCP:
		return s.State == Listen
	case UDP:
		return !s.HasRemote() && s.Local.Port() != 0
	}
	return false
}

// HasRemote reports whether the socket has a peer address (is connected).
func (s Socket) HasRemote() bool {
	return s.Remote.Port() != 0 || !s.Remote.Addr().IsUnspecified()
}

// ParseTable parses the contents of one /proc/net/{tcp,tcp6,udp,udp6} file.
// Malformed rows are skipped and counted rather than failing the whole table,
// because a partial view of a pod is more useful than none.
func ParseTable(proto Protocol, r io.Reader) (socks []Socket, skipped int, err error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "sl ") {
			continue
		}
		s, perr := ParseRow(proto, line)
		if perr != nil {
			skipped++
			continue
		}
		socks = append(socks, s)
	}
	return socks, skipped, sc.Err()
}

// ParseRow parses a single socket-table row such as
//
//	0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 12345 1 ...
func ParseRow(proto Protocol, line string) (Socket, error) {
	f := strings.Fields(line)
	if len(f) < 4 || !strings.HasSuffix(f[0], ":") {
		return Socket{}, fmt.Errorf("procnet: short or unnumbered row %q", line)
	}
	local, err := parseHexAddrPort(f[1])
	if err != nil {
		return Socket{}, fmt.Errorf("procnet: local address: %w", err)
	}
	remote, err := parseHexAddrPort(f[2])
	if err != nil {
		return Socket{}, fmt.Errorf("procnet: remote address: %w", err)
	}
	st, err := strconv.ParseUint(f[3], 16, 8)
	if err != nil {
		return Socket{}, fmt.Errorf("procnet: state %q: %w", f[3], err)
	}
	s := Socket{Protocol: proto, Local: local, Remote: remote, State: State(st)}
	if len(f) > 9 {
		if ino, err := strconv.ParseUint(f[9], 10, 64); err == nil {
			s.Inode = ino
		}
	}
	return s, nil
}

// parseHexAddrPort decodes the kernel's "ADDR:PORT" hex encoding. The address is
// printed as a sequence of host-endian 32-bit words (one for IPv4, four for
// IPv6); the port is printed in network order. Every architecture Kubernetes
// nodes realistically run on (amd64, arm64) is little-endian, which is assumed.
// IPv4-mapped IPv6 addresses are unmapped so a dual-stack listener and an IPv4
// peer compare equal.
func parseHexAddrPort(s string) (netip.AddrPort, error) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return netip.AddrPort{}, fmt.Errorf("missing ':' in %q", s)
	}
	raw, err := hex.DecodeString(s[:i])
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("address %q: %w", s[:i], err)
	}
	port, err := strconv.ParseUint(s[i+1:], 16, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("port %q: %w", s[i+1:], err)
	}
	var addr netip.Addr
	switch len(raw) {
	case 4:
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], binary.LittleEndian.Uint32(raw))
		addr = netip.AddrFrom4(b)
	case 16:
		var b [16]byte
		for w := 0; w < 4; w++ {
			binary.BigEndian.PutUint32(b[w*4:], binary.LittleEndian.Uint32(raw[w*4:]))
		}
		addr = netip.AddrFrom16(b).Unmap()
	default:
		return netip.AddrPort{}, fmt.Errorf("address %q has %d bytes", s[:i], len(raw))
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

// Sample is every socket the pod held at one instant.
type Sample struct {
	Time    time.Time
	Sockets []Socket
}

// Framing markers written by SamplerScript and consumed by ParseSamplerOutput.
const (
	markerHeader = "@@podpeers v1"
	markerSample = "@@sample "
	markerFile   = "@@file "
	markerEnd    = "@@end"
)

// SamplerScript returns the POSIX sh program the debug container runs. It takes
// a snapshot of the socket tables every interval until duration has elapsed,
// then exits on its own, so an interrupted operator never leaves a sampler
// running past the window. It needs only sh, cat, date and sleep.
func SamplerScript(duration, interval time.Duration) string {
	d := int(duration.Round(time.Second) / time.Second)
	iv := int(interval.Round(time.Second) / time.Second)
	if iv < 1 {
		iv = 1
	}
	return fmt.Sprintf(`echo '%s'
end=$(( $(date +%%s) + %d ))
while :; do
  now=$(date +%%s)
  echo "%s$now"
  for f in tcp tcp6 udp udp6; do echo "%s$f"; cat /proc/net/$f 2>/dev/null; done
  [ "$now" -ge "$end" ] && break
  sleep %d
done
echo '%s'
`, markerHeader, d, markerSample, markerFile, iv, markerEnd)
}

// SamplerOutput is the decoded log of one debug container.
type SamplerOutput struct {
	Samples  []Sample
	Complete bool // the end marker was seen: the sampler ran its whole window
	Skipped  int  // malformed rows ignored
}

// ParseSamplerOutput decodes the framed output of SamplerScript. A truncated log
// (container killed, log rotated) yields the samples that were complete and
// Complete=false.
func ParseSamplerOutput(r io.Reader) (SamplerOutput, error) {
	var out SamplerOutput
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	sawHeader := false
	var cur *Sample
	var proto Protocol
	flush := func() {
		if cur != nil {
			out.Samples = append(out.Samples, *cur)
			cur = nil
		}
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == markerHeader:
			sawHeader = true
		case strings.HasPrefix(line, markerSample):
			flush()
			sec, err := strconv.ParseInt(strings.TrimSpace(line[len(markerSample):]), 10, 64)
			if err != nil {
				return out, fmt.Errorf("procnet: bad sample marker %q", line)
			}
			cur = &Sample{Time: time.Unix(sec, 0).UTC()}
			proto = ""
		case strings.HasPrefix(line, markerFile):
			switch name := strings.TrimSpace(line[len(markerFile):]); name {
			case "tcp", "tcp6":
				proto = TCP
			case "udp", "udp6":
				proto = UDP
			default:
				return out, fmt.Errorf("procnet: unknown table %q", name)
			}
		case line == markerEnd:
			flush()
			out.Complete = true
		default:
			t := strings.TrimSpace(line)
			if cur == nil || proto == "" || t == "" || strings.HasPrefix(t, "sl ") {
				continue
			}
			s, err := ParseRow(proto, t)
			if err != nil {
				out.Skipped++
				continue
			}
			cur.Sockets = append(cur.Sockets, s)
		}
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	if !sawHeader {
		return out, fmt.Errorf("procnet: no podpeers header in sampler output")
	}
	// A sample that was cut off mid-table is incomplete; drop it unless the end
	// marker proved the stream finished.
	if !out.Complete {
		cur = nil
	}
	flush()
	return out, nil
}
