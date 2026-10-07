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
// v1 (whole-second `date` timestamps, one `cat` per table) is still parsed;
// SamplerScript writes v2.
const (
	markerHeaderV1 = "@@podpeers v1"
	markerHeader   = "@@podpeers v2"
	markerAnchor   = "@@anchor "
	markerSample   = "@@sample "
	markerFile     = "@@file "
	markerEnd      = "@@end"
)

// MinInterval is the shortest sample interval podpeers accepts. Each sample
// costs two process starts in the debug container (cat and sleep); much
// below this the sampler would mostly measure itself.
const MinInterval = 100 * time.Millisecond

// SamplerScript returns the POSIX sh program the debug container runs. It takes
// a snapshot of the socket tables every interval until duration has elapsed,
// then exits on its own, so an interrupted operator never leaves a sampler
// running past the window. It needs only sh, cat, date and sleep.
//
// Per sample it starts two processes: one cat over all four tables (each
// table is recognised by its own header line) and one sleep. Times come from
// /proc/uptime (10ms resolution), read with the shell builtin `read`, and are
// anchored to wall-clock time once with `date`. Sub-second intervals are
// passed to sleep as decimal seconds; callers validate them first (see
// MinInterval).
func SamplerScript(duration, interval time.Duration) string {
	durCS := int64(duration / (10 * time.Millisecond))
	sleep := strconv.FormatFloat(interval.Seconds(), 'f', -1, 64)
	return fmt.Sprintf(`echo '%s'
read up0 rest < /proc/uptime
echo "%s$(date +%%s) $up0"
end=$(( ${up0%%.*}${up0#*.} + %d ))
while :; do
  read up rest < /proc/uptime
  echo "%s$up"
  cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null
  [ "${up%%.*}${up#*.}" -ge "$end" ] && break
  sleep %s
done
echo '%s'
`, markerHeader, markerAnchor, durCS, markerSample, sleep, markerEnd)
}

// tableProtocol classifies a /proc/net socket-table header line. The kernel
// prints "... inode ref pointer drops" for UDP tables and "... inode" for TCP
// ones, in both address families, so one cat over all four files can be split
// without markers, even when a file (say tcp6, with IPv6 disabled) is absent.
func tableProtocol(header string) Protocol {
	if strings.Contains(header, "drops") {
		return UDP
	}
	return TCP
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
	version := 0
	var anchorWall int64
	var anchorUp float64
	haveAnchor := false
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
		t := strings.TrimSpace(line)
		switch {
		case line == markerHeaderV1:
			version = 1
		case line == markerHeader:
			version = 2
		case strings.HasPrefix(line, markerAnchor):
			f := strings.Fields(line[len(markerAnchor):])
			if len(f) != 2 {
				return out, fmt.Errorf("procnet: bad anchor %q", line)
			}
			w, err1 := strconv.ParseInt(f[0], 10, 64)
			u, err2 := strconv.ParseFloat(f[1], 64)
			if err1 != nil || err2 != nil {
				return out, fmt.Errorf("procnet: bad anchor %q", line)
			}
			anchorWall, anchorUp, haveAnchor = w, u, true
		case strings.HasPrefix(line, markerSample):
			flush()
			v := strings.TrimSpace(line[len(markerSample):])
			proto = ""
			if version == 1 {
				sec, err := strconv.ParseInt(v, 10, 64)
				if err != nil {
					return out, fmt.Errorf("procnet: bad sample marker %q", line)
				}
				cur = &Sample{Time: time.Unix(sec, 0).UTC()}
				continue
			}
			up, err := strconv.ParseFloat(v, 64)
			if err != nil || !haveAnchor {
				return out, fmt.Errorf("procnet: bad sample marker %q (anchor seen: %v)", line, haveAnchor)
			}
			// uptime is exact to 10ms; round away float noise.
			off := time.Duration((up-anchorUp)*1000+0.5) * time.Millisecond
			cur = &Sample{Time: time.Unix(anchorWall, 0).UTC().Add(off)}
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
		case strings.HasPrefix(t, "sl "):
			if version == 2 {
				proto = tableProtocol(t)
			}
		default:
			if cur == nil || proto == "" || t == "" {
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
	if version == 0 {
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
