// Command masque_interop drives quic-go's MASQUE libraries against
// masque's HTTP/3 listener and client. See masque_interop_SUITE.
//
// Each subcommand runs one scenario and prints result lines the suite
// matches; it exits non-zero on failure.
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		log.Fatal("usage: masque_interop udp-client|udp-refused|ip-client|proxy|ip-proxy ...")
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "udp-client":
		udpClient(args)
	case "udp-refused":
		udpRefused(args)
	case "ip-client":
		ipClient(args)
	case "proxy":
		proxy(args)
	case "ip-proxy":
		ipProxy(args)
	default:
		log.Fatalf("unknown command %q", os.Args[1])
	}
}

func clientTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}}
}

func clientQUIC() *quic.Config {
	return &quic.Config{EnableDatagrams: true, InitialPacketSize: 1350}
}

//====================================================================
// CONNECT-UDP client (masque-go)
//====================================================================

// udpClient opens `-tunnels' CONNECT-UDP tunnels over one QUIC
// connection and, on each, echoes one datagram per size. `-mode close'
// closes the tunnels afterwards and waits a little, so the proxy can be
// checked; `-mode wait' reads until the proxy ends the tunnel.
func udpClient(args []string) {
	fs := flag.NewFlagSet("udp-client", flag.ExitOnError)
	template := fs.String("t", "", "URI template")
	target := fs.String("target", "", "target host:port")
	payload := fs.String("payload", "ping", "payload, when -sizes is not given")
	sizes := fs.String("sizes", "", "comma-separated payload sizes")
	tunnels := fs.Int("tunnels", 1, "tunnels over one connection")
	mode := fs.String("mode", "echo", "echo|close|wait")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tmpl := uritemplate.MustNew(*template)
	u, err := url.Parse(strings.SplitN(*template, "{", 2)[0])
	if err != nil {
		log.Fatalf("template: %v", err)
	}
	qconn, err := quic.DialAddr(ctx, u.Host, clientTLS(), clientQUIC())
	if err != nil {
		log.Fatalf("quic: %v", err)
	}
	defer qconn.CloseWithError(0, "")
	cc, err := (&masque.Transport{}).NewClientConn(qconn)
	if err != nil {
		log.Fatalf("client conn: %v", err)
	}
	payloads := [][]byte{[]byte(*payload)}
	if *sizes != "" {
		payloads = nil
		for _, s := range strings.Split(*sizes, ",") {
			n, err := strconv.Atoi(s)
			if err != nil {
				log.Fatalf("size %q: %v", s, err)
			}
			b := make([]byte, n)
			for i := range b {
				b[i] = byte('a' + i%26)
			}
			payloads = append(payloads, b)
		}
	}
	conns := make([]*masque.Conn, *tunnels)
	for i := range conns {
		req, err := masque.NewRequest(ctx, tmpl, *target)
		if err != nil {
			log.Fatalf("request: %v", err)
		}
		conn, rsp, err := cc.Dial(req)
		if err != nil {
			log.Fatalf("dial %d: %v", i, err)
		}
		if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
			log.Fatalf("status %d", rsp.StatusCode)
		}
		conns[i] = conn
	}
	var wg sync.WaitGroup
	for i, conn := range conns {
		wg.Add(1)
		go func(i int, conn *masque.Conn) {
			defer wg.Done()
			for _, p := range payloads {
				echoUDP(conn, *target, i, p)
			}
		}(i, conn)
	}
	wg.Wait()
	switch *mode {
	case "echo":
		for _, c := range conns {
			c.Close()
		}
	case "close":
		for _, c := range conns {
			c.Close()
		}
		fmt.Println("closed")
		// Keep the QUIC connection up: only the tunnels end.
		time.Sleep(2 * time.Second)
	case "wait":
		fmt.Println("waiting")
		buf := make([]byte, 2048)
		_ = conns[0].SetReadDeadline(time.Now().Add(20 * time.Second))
		for {
			if _, _, err := conns[0].ReadFrom(buf); err != nil {
				var nerr net.Error
				if errors.As(err, &nerr) && nerr.Timeout() {
					log.Fatal("tunnel not ended by the proxy")
				}
				fmt.Println("ended")
				return
			}
		}
	}
}

func echoUDP(conn *masque.Conn, target string, tunnel int, p []byte) {
	buf := make([]byte, 65536)
	for try := 0; try < 20; try++ {
		if _, err := conn.WriteTo(p, nil); err != nil {
			log.Fatalf("write %d bytes: %v", len(p), err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		if string(buf[:n]) != string(p) {
			log.Fatalf("tunnel %d: echo of %d bytes came back as %d bytes", tunnel, len(p), n)
		}
		if len(p) < 16 {
			fmt.Printf("echo:%s\n", buf[:n])
		}
		fmt.Printf("echo:%d:%d\n", tunnel, n)
		return
	}
	log.Fatalf("tunnel %d: no echo of %d bytes from %s", tunnel, len(p), target)
}

// udpRefused expects the proxy to refuse and prints its status and
// Proxy-Status.
func udpRefused(args []string) {
	fs := flag.NewFlagSet("udp-refused", flag.ExitOnError)
	template := fs.String("t", "", "URI template")
	target := fs.String("target", "", "target host:port")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tr := masque.Transport{TLSClientConfig: clientTLS(), QUICConfig: clientQUIC()}
	req, err := masque.NewRequest(ctx, uritemplate.MustNew(*template), *target)
	if err != nil {
		log.Fatalf("request: %v", err)
	}
	conn, rsp, err := tr.Dial(req)
	if err == nil {
		conn.Close()
		log.Fatalf("tunnel opened, status %d", rsp.StatusCode)
	}
	if rsp == nil {
		log.Fatalf("no response: %v", err)
	}
	fmt.Printf("status:%d proxy-status:%s\n", rsp.StatusCode, rsp.Header.Get("Proxy-Status"))
}

//====================================================================
// CONNECT-IP client (connect-ip-go)
//====================================================================

// ipClient opens a CONNECT-IP tunnel and runs one scenario on it:
//   - ping: request an address of `-family', ping `-gateway'
//   - routes: print the routes the proxy advertised
//   - to-proxy: assign an address and advertise a route to the proxy
//   - answer: answer the proxy's address request
//   - dns: send DNS configuration and PREF64 capsules, then ping
//   - too-big: ping `-gateway' with a `-size' byte payload, larger than
//     the proxy's MTU, and print the ICMP error that comes back
//   - two: two tunnels over one connection, each gets an address
//   - close: close the tunnel, keep the connection up a little
//   - wait: read until the proxy ends the tunnel
func ipClient(args []string) {
	fs := flag.NewFlagSet("ip-client", flag.ExitOnError)
	rawURL := fs.String("url", "", "CONNECT-IP URL, no template variables")
	gateway := fs.String("gateway", "", "gateway address")
	size := fs.Int("size", 4, "echo payload size for -mode too-big")
	family := fs.Int("family", 4, "4 or 6")
	mode := fs.String("mode", "ping", "scenario")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	u, err := url.Parse(*rawURL)
	if err != nil {
		log.Fatalf("url: %v", err)
	}
	qconn, err := quic.DialAddr(ctx, u.Host, clientTLS(), clientQUIC())
	if err != nil {
		log.Fatalf("quic: %v", err)
	}
	defer qconn.CloseWithError(0, "")
	cc, err := (&connectip.Transport{}).NewClientConn(qconn)
	if err != nil {
		log.Fatalf("client conn: %v", err)
	}
	dial := func() *connectip.Conn {
		req, err := connectip.NewRequest(ctx, uritemplate.MustNew(*rawURL))
		if err != nil {
			log.Fatalf("request: %v", err)
		}
		conn, rsp, err := cc.Dial(req)
		if err != nil {
			log.Fatalf("dial: %v", err)
		}
		if rsp.StatusCode != http.StatusOK {
			log.Fatalf("status %d", rsp.StatusCode)
		}
		return conn
	}
	conn := dial()
	defer conn.Close()

	switch *mode {
	case "ping":
		src := requestAddress(ctx, conn, *family)
		from := ping(conn, src, netip.MustParseAddr(*gateway))
		fmt.Printf("assigned:%s reply-from:%s\n", src, from)
	case "routes":
		routes, err := conn.Routes(ctx)
		if err != nil {
			log.Fatalf("routes: %v", err)
		}
		var out []string
		for _, r := range routes {
			out = append(out, fmt.Sprintf("%s-%s/%d", r.StartIP, r.EndIP, r.IPProtocol))
		}
		fmt.Printf("routes:%s\n", strings.Join(out, ","))
	case "to-proxy":
		if err := conn.AssignAddresses([]netip.Prefix{netip.MustParsePrefix("192.0.2.7/32")}); err != nil {
			log.Fatalf("assign: %v", err)
		}
		if err := conn.AdvertiseRoute([]connectip.IPRoute{{
			StartIP: netip.MustParseAddr("192.0.2.0"), EndIP: netip.MustParseAddr("192.0.2.255"),
		}}); err != nil {
			log.Fatalf("advertise: %v", err)
		}
		fmt.Println("sent")
		time.Sleep(2 * time.Second)
	case "answer":
		req, err := conn.ReceiveAddressRequest(ctx)
		if err != nil {
			log.Fatalf("address request: %v", err)
		}
		if err := req.Respond([]netip.Prefix{netip.MustParsePrefix("10.77.0.1/32")}, nil); err != nil {
			log.Fatalf("respond: %v", err)
		}
		fmt.Println("answered")
		time.Sleep(2 * time.Second)
	case "dns":
		if err := conn.SendDNSConfiguration([]connectip.DNSConfiguration{{
			Nameservers: []connectip.DNSNameserver{{ServicePriority: 1, IPv4Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.53")}}},
		}}); err != nil {
			log.Fatalf("dns: %v", err)
		}
		if err := conn.SendPREF64Configuration([]netip.Prefix{netip.MustParsePrefix("64:ff9b::/96")}); err != nil {
			log.Fatalf("pref64: %v", err)
		}
		src := requestAddress(ctx, conn, 4)
		from := ping(conn, src, netip.MustParseAddr(*gateway))
		fmt.Printf("assigned:%s reply-from:%s\n", src, from)
	case "too-big":
		src := requestAddress(ctx, conn, *family)
		typ, code := pingExpectICMPError(conn, echoRequestSized(src, netip.MustParseAddr(*gateway), *size))
		fmt.Printf("icmp:%d/%d\n", typ, code)
	case "two":
		second := dial()
		defer second.Close()
		a := requestAddress(ctx, conn, 4)
		b := requestAddress(ctx, second, 4)
		if a == b {
			log.Fatalf("both tunnels got %s", a)
		}
		fmt.Printf("two:%s,%s\n", a, b)
	case "close":
		requestAddress(ctx, conn, 4)
		conn.Close()
		fmt.Println("closed")
		time.Sleep(2 * time.Second)
	case "wait":
		requestAddress(ctx, conn, 4)
		fmt.Println("waiting")
		buf := make([]byte, 2048)
		done := make(chan error, 1)
		go func() {
			for {
				if _, err := conn.ReadPacket(buf); err != nil {
					done <- err
					return
				}
			}
		}()
		select {
		case <-done:
			fmt.Println("ended")
		case <-time.After(20 * time.Second):
			log.Fatal("tunnel not ended by the proxy")
		}
	default:
		log.Fatalf("unknown mode %q", *mode)
	}
}

func requestAddress(ctx context.Context, conn *connectip.Conn, family int) netip.Addr {
	prefix := netip.MustParsePrefix("0.0.0.0/32")
	if family == 6 {
		prefix = netip.MustParsePrefix("::/128")
	}
	if _, err := conn.RequestAddresses([]netip.Prefix{prefix}); err != nil {
		log.Fatalf("request addresses: %v", err)
	}
	for {
		assigned, err := conn.ReceiveAddressAssignment(ctx)
		if err != nil {
			log.Fatalf("assignment: %v", err)
		}
		// Every ADDRESS_ASSIGN is the full set (RFC 9484 4.7.1): take
		// the newest address of the family asked for.
		for i := len(assigned) - 1; i >= 0; i-- {
			a := assigned[i]
			if a.Rejected() {
				log.Fatalf("request rejected: %v", assigned)
			}
			addr := a.IPPrefix.Addr()
			if (family == 6) == addr.Is6() {
				return addr
			}
		}
	}
}

// ping sends one ICMP echo and returns the source of the reply.
func ping(conn *connectip.Conn, src, dst netip.Addr) netip.Addr {
	pkt := echoRequest(src, dst)
	if icmp, err := conn.WritePacket(pkt); err != nil {
		log.Fatalf("write: %v", err)
	} else if len(icmp) > 0 {
		log.Fatalf("local ICMP for our own packet: %x", icmp)
	}
	buf := make([]byte, 2048)
	for {
		n, err := conn.ReadPacket(buf)
		if err != nil {
			log.Fatalf("read: %v", err)
		}
		from, ok := echoReplyFrom(buf[:n])
		if ok {
			return from
		}
	}
}

// pingExpectICMPError sends `pkt' and returns the type and code of the
// ICMP error that comes back.
func pingExpectICMPError(conn *connectip.Conn, pkt []byte) (int, int) {
	if icmp, err := conn.WritePacket(pkt); err != nil {
		log.Fatalf("write: %v", err)
	} else if len(icmp) > 0 {
		log.Fatalf("refused locally, not by the proxy: %x", icmp)
	}
	buf := make([]byte, 2048)
	n, err := conn.ReadPacket(buf)
	if err != nil {
		log.Fatalf("read: %v", err)
	}
	p := buf[:n]
	if p[0]>>4 == 4 {
		ihl := int(p[0]&0x0f) * 4
		return int(p[ihl]), int(p[ihl+1])
	}
	return int(p[40]), int(p[41])
}

//====================================================================
// CONNECT-UDP proxy (masque-go)
//====================================================================

// proxy runs quic-go's CONNECT-UDP proxy until killed.
func proxy(args []string) {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	templateStr := fs.String("t", "", "URI template")
	bind := fs.String("b", "127.0.0.1:0", "bind address")
	certFile := fs.String("c", "", "certificate file")
	keyFile := fs.String("k", "", "key file")
	_ = fs.Parse(args)

	udpConn, port := listenUDP(*bind)
	// The proxy checks requests against the template's host, so the
	// template has to name the port we actually got.
	bound := strings.Replace(*templateStr, ":0/", fmt.Sprintf(":%d/", port), 1)
	template := uritemplate.MustNew(bound)
	p := masque.Proxy{}
	u, err := url.Parse(bound)
	if err != nil {
		log.Fatalf("template: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(u.Path, func(w http.ResponseWriter, r *http.Request) {
		req, err := masque.ParseProxyRequest(r, template)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = p.Proxy(r.Context(), w, req)
	})
	serve(udpConn, port, *certFile, *keyFile, mux)
}

//====================================================================
// CONNECT-IP proxy (connect-ip-go)
//====================================================================

// ipProxy runs connect-ip-go's proxy until killed. Each tunnel gets
// 10.88.0.1 when it asks, a route to 10.88.0.0/24, and its ICMP echo
// requests answered.
func ipProxy(args []string) {
	fs := flag.NewFlagSet("ip-proxy", flag.ExitOnError)
	path := fs.String("path", "/.well-known/masque/ip/*/*/", "request path")
	bind := fs.String("b", "127.0.0.1:0", "bind address")
	certFile := fs.String("c", "", "certificate file")
	keyFile := fs.String("k", "", "key file")
	_ = fs.Parse(args)

	udpConn, port := listenUDP(*bind)
	template := uritemplate.MustNew(fmt.Sprintf("https://127.0.0.1:%d%s", port, *path))
	p := connectip.Proxy{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		req, err := connectip.ParseProxyRequest(r, template)
		if err != nil {
			var perr *connectip.ProxyRequestParseError
			if errors.As(err, &perr) {
				log.Printf("refused %s: %v", r.URL.Path, err)
				w.WriteHeader(perr.HTTPStatus)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		conn, err := p.Proxy(w, req)
		if err != nil {
			log.Printf("proxy: %v", err)
			return
		}
		serveIPTunnel(r.Context(), conn)
	})
	serve(udpConn, port, *certFile, *keyFile, mux)
}

func serveIPTunnel(ctx context.Context, conn *connectip.Conn) {
	defer conn.Close()
	if err := conn.AdvertiseRoute([]connectip.IPRoute{{
		StartIP: netip.MustParseAddr("10.88.0.0"), EndIP: netip.MustParseAddr("10.88.0.255"),
	}}); err != nil {
		log.Printf("advertise: %v", err)
		return
	}
	go func() {
		for {
			req, err := conn.ReceiveAddressRequest(ctx)
			if err != nil {
				return
			}
			_ = req.Respond([]netip.Prefix{netip.MustParsePrefix("10.88.0.1/32")}, nil)
		}
	}()
	buf := make([]byte, 2048)
	for {
		n, err := conn.ReadPacket(buf)
		if err != nil {
			return
		}
		if reply, ok := echoReply(buf[:n]); ok {
			_, _ = conn.WritePacket(reply)
		}
	}
}

func listenUDP(bind string) (*net.UDPConn, int) {
	udpAddr, err := net.ResolveUDPAddr("udp", bind)
	if err != nil {
		log.Fatalf("bind: %v", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	return udpConn, udpConn.LocalAddr().(*net.UDPAddr).Port
}

func serve(udpConn *net.UDPConn, port int, certFile, keyFile string, h http.Handler) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("cert: %v", err)
	}
	server := http3.Server{
		TLSConfig:       http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		EnableDatagrams: true,
		Handler:         h,
	}
	fmt.Printf("ready:%d\n", port)
	log.Fatal(server.Serve(udpConn))
}

//====================================================================
// ICMP
//====================================================================

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// icmp6Checksum covers the IPv6 pseudo-header (RFC 4443 section 2.3).
func icmp6Checksum(src, dst netip.Addr, msg []byte) uint16 {
	s, d := src.As16(), dst.As16()
	pseudo := append(append([]byte{}, s[:]...), d[:]...)
	l := make([]byte, 8)
	binary.BigEndian.PutUint32(l, uint32(len(msg)))
	l[7] = 58
	pseudo = append(pseudo, l...)
	return checksum(append(pseudo, msg...))
}

func echoRequest(src, dst netip.Addr) []byte {
	return echoRequestSized(src, dst, 4)
}

// echoRequestSized builds an echo request with a `size' byte payload.
func echoRequestSized(src, dst netip.Addr, size int) []byte {
	body := make([]byte, size)
	copy(body, "ping")
	if src.Is6() {
		icmp := append([]byte{128, 0, 0, 0, 0, 1, 0, 1}, body...)
		c := icmp6Checksum(src, dst, icmp)
		icmp[2], icmp[3] = byte(c>>8), byte(c)
		h := make([]byte, 40)
		h[0] = 0x60
		binary.BigEndian.PutUint16(h[4:], uint16(len(icmp)))
		h[6], h[7] = 58, 64
		s, d := src.As16(), dst.As16()
		copy(h[8:], s[:])
		copy(h[24:], d[:])
		return append(h, icmp...)
	}
	icmp := append([]byte{8, 0, 0, 0, 0, 1, 0, 1}, body...)
	c := checksum(icmp)
	icmp[2], icmp[3] = byte(c>>8), byte(c)
	total := 20 + len(icmp)
	h := []byte{0x45, 0, byte(total >> 8), byte(total), 0, 0, 0, 0, 64, 1, 0, 0}
	s, d := src.As4(), dst.As4()
	h = append(h, s[:]...)
	h = append(h, d[:]...)
	c = checksum(h)
	h[10], h[11] = byte(c>>8), byte(c)
	return append(h, icmp...)
}

// echoReplyFrom returns the source of an ICMP or ICMPv6 echo reply.
func echoReplyFrom(p []byte) (netip.Addr, bool) {
	if len(p) >= 28 && p[0]>>4 == 4 {
		ihl := int(p[0]&0x0f) * 4
		if p[9] == 1 && p[ihl] == 0 {
			a, _ := netip.AddrFromSlice(p[12:16])
			return a, true
		}
		return netip.Addr{}, false
	}
	if len(p) >= 48 && p[0]>>4 == 6 && p[6] == 58 && p[40] == 129 {
		a, _ := netip.AddrFromSlice(p[8:24])
		return a, true
	}
	return netip.Addr{}, false
}

// echoReply turns an ICMP or ICMPv6 echo request into its reply.
func echoReply(p []byte) ([]byte, bool) {
	if len(p) >= 28 && p[0]>>4 == 4 && p[9] == 1 {
		ihl := int(p[0]&0x0f) * 4
		if p[ihl] != 8 {
			return nil, false
		}
		r := append([]byte{}, p...)
		copy(r[12:16], p[16:20])
		copy(r[16:20], p[12:16])
		r[ihl] = 0
		r[ihl+2], r[ihl+3] = 0, 0
		c := checksum(r[ihl:])
		r[ihl+2], r[ihl+3] = byte(c>>8), byte(c)
		r[10], r[11] = 0, 0
		c = checksum(r[:ihl])
		r[10], r[11] = byte(c>>8), byte(c)
		return r, true
	}
	if len(p) >= 48 && p[0]>>4 == 6 && p[6] == 58 && p[40] == 128 {
		r := append([]byte{}, p...)
		copy(r[8:24], p[24:40])
		copy(r[24:40], p[8:24])
		r[40] = 129
		r[42], r[43] = 0, 0
		src, _ := netip.AddrFromSlice(r[8:24])
		dst, _ := netip.AddrFromSlice(r[24:40])
		c := icmp6Checksum(src, dst, r[40:])
		r[42], r[43] = byte(c>>8), byte(c)
		return r, true
	}
	return nil, false
}
