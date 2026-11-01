package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// The orderer endpoints a client learns from the channel config block are in-cluster DNS names
// (orderer-router-1.fabricx.svc.cluster.local:7050). From outside the cluster they cannot be
// resolved and the ports are not exposed. The shim, which runs inside the node process only
// (no /etc/hosts change, no root), answers those names with 127.0.0.1 and forwards the
// ports to the cluster NodePorts.
//
//	{"hosts": {"orderer-router-1.fabricx.svc.cluster.local": "127.0.0.1"},
//	 "forwards": [{"listen": "127.0.0.1:7050", "target": "172.24.11.197:30050"}]}
type shimConfig struct {
	Hosts    map[string]string `json:"hosts"`
	Forwards []struct {
		Listen string `json:"listen"`
		Target string `json:"target"`
	} `json:"forwards"`
}

func startNetShim(path string) error {
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg shimConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return err
	}

	for _, f := range cfg.Forwards {
		l, err := net.Listen("tcp", f.Listen)
		if err != nil {
			// another node of this deployment already forwards this port: fine, same target
			log.Printf("netshim: %s already in use, assuming another node forwards it", f.Listen)
			continue
		}
		go serveForward(l, f.Target)
	}

	if len(cfg.Hosts) == 0 {
		return nil
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	go serveDNS(pc, cfg.Hosts)
	dnsAddr := pc.LocalAddr().String()
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "udp", dnsAddr)
		},
	}
	return nil
}

func serveForward(l net.Listener, target string) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			up, err := net.DialTimeout("tcp", target, 5*time.Second)
			if err != nil {
				log.Printf("netshim: dial %s: %v", target, err)
				return
			}
			defer up.Close()
			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
			go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
			<-done
		}()
	}
}

func serveDNS(pc net.PacketConn, hosts map[string]string) {
	buf := make([]byte, 1500)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		var req dnsmessage.Message
		if req.Unpack(buf[:n]) != nil || len(req.Questions) == 0 {
			continue
		}
		q := req.Questions[0]
		name := strings.TrimSuffix(strings.ToLower(q.Name.String()), ".")
		resp := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: req.Header.ID, Response: true, Authoritative: true, RecursionDesired: req.Header.RecursionDesired},
			Questions: req.Questions,
		}
		ip, ok := hosts[name]
		switch {
		case !ok:
			resp.Header.RCode = dnsmessage.RCodeNameError
			log.Printf("netshim: unknown name %q", name)
		case q.Type == dnsmessage.TypeA:
			var a [4]byte
			copy(a[:], net.ParseIP(ip).To4())
			resp.Answers = []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60},
				Body:   &dnsmessage.AResource{A: a},
			}}
		default: // AAAA etc: name exists, no such record
		}
		if out, err := resp.Pack(); err == nil {
			_, _ = pc.WriteTo(out, from)
		}
	}
}
