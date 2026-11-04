// Command masque_interop drives quic-go's MASQUE libraries against
// masque's HTTP/3 listener and client. See masque_interop_SUITE.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
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
		log.Fatal("usage: masque_interop udp-client|ip-client|proxy ...")
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "udp-client":
		udpClient(args)
	case "ip-client":
		ipClient(args)
	case "proxy":
		proxy(args)
	default:
		log.Fatalf("unknown command %q", os.Args[1])
	}
}

// udpClient sends one datagram through a proxy and prints the echo.
func udpClient(args []string) {
	fs := flag.NewFlagSet("udp-client", flag.ExitOnError)
	template := fs.String("t", "", "URI template")
	target := fs.String("target", "", "target host:port")
	payload := fs.String("payload", "ping", "payload")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	tr := masque.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}},
		QUICConfig:      &quic.Config{EnableDatagrams: true, InitialPacketSize: 1350},
	}
	req, err := masque.NewRequest(ctx, uritemplate.MustNew(*template), *target)
	if err != nil {
		log.Fatalf("request: %v", err)
	}
	conn, rsp, err := tr.Dial(req)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		log.Fatalf("status %d", rsp.StatusCode)
	}
	addr, err := net.ResolveUDPAddr("udp", *target)
	if err != nil {
		log.Fatalf("resolve: %v", err)
	}
	buf := make([]byte, 2048)
	for i := 0; i < 20; i++ {
		if _, err := conn.WriteTo([]byte(*payload), addr); err != nil {
			log.Fatalf("write: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := conn.ReadFrom(buf)
		if err == nil {
			fmt.Printf("echo:%s\n", buf[:n])
			return
		}
	}
	log.Fatal("no echo")
}

// ipClient requests an address, sends an ICMP echo to a gateway address
// and prints the source of what comes back.
func ipClient(args []string) {
	fs := flag.NewFlagSet("ip-client", flag.ExitOnError)
	rawURL := fs.String("url", "", "CONNECT-IP URL, no template variables")
	gateway := fs.String("gateway", "", "gateway address")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	u, err := url.Parse(*rawURL)
	if err != nil {
		log.Fatalf("url: %v", err)
	}
	qconn, err := quic.DialAddr(ctx, u.Host,
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}},
		&quic.Config{EnableDatagrams: true, InitialPacketSize: 1350})
	if err != nil {
		log.Fatalf("quic: %v", err)
	}
	defer qconn.CloseWithError(0, "")
	tr := &http3.Transport{EnableDatagrams: true}
	h3 := tr.NewClientConn(qconn)
	req, err := connectip.NewRequest(ctx, uritemplate.MustNew(*rawURL))
	if err != nil {
		log.Fatalf("request: %v", err)
	}
	conn, rsp, err := connectip.NewClientConn(h3).Dial(req)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if rsp.StatusCode != http.StatusOK {
		log.Fatalf("status %d", rsp.StatusCode)
	}
	if _, err := conn.RequestAddresses([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/32")}); err != nil {
		log.Fatalf("request addresses: %v", err)
	}
	assigned, err := conn.ReceiveAddressAssignment(ctx)
	if err != nil {
		log.Fatalf("assignment: %v", err)
	}
	if len(assigned) != 1 {
		log.Fatalf("assigned %v", assigned)
	}
	src := assigned[0].IPPrefix.Addr()
	dst := netip.MustParseAddr(*gateway)
	if _, err := conn.WritePacket(icmpEcho(src, dst)); err != nil {
		log.Fatalf("write: %v", err)
	}
	buf := make([]byte, 2048)
	n, err := conn.ReadPacket(buf)
	if err != nil || n < 20 {
		log.Fatalf("read: %d %v", n, err)
	}
	from, _ := netip.AddrFromSlice(buf[12:16])
	fmt.Printf("assigned:%s reply-from:%s\n", src, from)
}

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

func icmpEcho(src, dst netip.Addr) []byte {
	icmp := []byte{8, 0, 0, 0, 0, 1, 0, 1, 'p', 'i', 'n', 'g'}
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

// proxy runs quic-go's CONNECT-UDP proxy until killed.
func proxy(args []string) {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	templateStr := fs.String("t", "", "URI template")
	bind := fs.String("b", "127.0.0.1:0", "bind address")
	certFile := fs.String("c", "", "certificate file")
	keyFile := fs.String("k", "", "key file")
	_ = fs.Parse(args)

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("cert: %v", err)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", *bind)
	if err != nil {
		log.Fatalf("bind: %v", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	// The proxy checks requests against the template's host, so the
	// template has to name the port we actually got.
	port := udpConn.LocalAddr().(*net.UDPAddr).Port
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
		_ = p.Proxy(w, req)
	})
	server := http3.Server{
		TLSConfig:       http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		EnableDatagrams: true,
		Handler:         mux,
	}
	fmt.Printf("ready:%d\n", port)
	log.Fatal(server.Serve(udpConn))
}
