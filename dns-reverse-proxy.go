/*
Binary dns_reverse_proxy is a DNS reverse proxy to route queries to DNS servers.

To illustrate, imagine an HTTP reverse proxy but for DNS.
It listens on both TCP/UDP IPv4/IPv6 on specified port.
Since the upstream servers will not see the real client IPs but the proxy,
you can specify a list of IPs allowed to transfer (AXFR/IXFR).

Example usage:
        $ go run dns_reverse_proxy.go -address :53 \
                -default 8.8.8.8:53 \
                -route .example.com.=8.8.4.4:53 \
                -allow-transfer 1.2.3.4,::1

A query for example.net or example.com will go to 8.8.8.8:53, the default.
However, a query for subdomain.example.com will go to 8.8.4.4:53.
*/
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wheelcomplex/dns"
	"github.com/wheelcomplex/preinit/getopt"
	"github.com/wheelcomplex/preinit/misc"
)

// command line parser

var (
	opt = getopt.NewDefaultOpts()

	srvListenAddr = opt.OnceString("--listen", "127.0.0.1:53", "Address to listen to (TCP and UDP)")

	upstreamServers = opt.OnceStringList("--upstreams", "8.8.8.8:53,8.8.4.4:53,119.29.29.29:53",
		"Upstream DNS server where to send queries if no route matched (IP:port)")

	defaultServer string = ""

	// note: Bool option always default to false
	noraceproxy = opt.OnceBool("--norace", "disable race mode, send queries to first upstream only, by default, proxy send queries to all upstreams and use the first response")

	needhelp = opt.OnceBool("--help/-h", "show this usage")

	debuglevel = opt.OnceInt("--debug", "0", "debug level(0-8)")

	routeList = opt.OnceString("--routes", "*.google.com=8.8.8.8:53,*.facebook.com=8.8.8.8:53",
		"List of routes where to send queries (subdomain=IP:port)")
	routes map[string]string

	allowTransfer = opt.OnceString("allow-transfer", "127.0.0.1",
		"List of IPs allowed to transfer (AXFR/IXFR)")
	transferIPs []string
)

func main() {

	if needhelp {
		opt.Usage()
		os.Exit(0)
	}

	//
	for idx, _ := range upstreamServers {
		upstreamServers[idx] = strings.Trim(upstreamServers[idx], ":")
		if strings.Contains(upstreamServers[idx], ":") == false {
			upstreamServers[idx] = upstreamServers[idx] + ":53"
		}
	}

	//
	if len(upstreamServers) > 0 {
		defaultServer = upstreamServers[0]
	}
	if defaultServer == "" {
		log.Fatal("--upstreams is required")
		opt.Usage()
		os.Exit(1)
	}
	if srvListenAddr == "" {
		log.Fatal("--listen is required")
		opt.Usage()
		os.Exit(1)
	}
	transferIPs = strings.Split(allowTransfer, ",")
	routes = make(map[string]string)
	if routeList != "" {
		for _, s := range strings.Split(routeList, ",") {
			s := strings.SplitN(s, "=", 2)
			if len(s) != 2 {
				log.Fatal("invalid -routes format")
			}
			if !strings.HasSuffix(s[0], ".") {
				s[0] += "."
			}
			routes[s[0]] = s[1]
		}
	}

	// install signal USR1 for debug
	sigCh := make(chan os.Signal, 128)
	signal.Notify(sigCh, syscall.SIGUSR1)

	go func() {
		sig := <-sigCh
		if sig == syscall.SIGUSR1 {
			if debuglevel >= 8 {
				fmt.Printf("\n------ runtime stack start %v ------\n", time.Now())
				debug.PrintStack()
				fmt.Printf("\n------ runtime stack end ------\n")
			}
		}
	}()
	if debuglevel >= 1 {
		fmt.Printf("[%d]dns proxy listen(TCP+UDP) %s, upstreams %s ...\n", os.Getpid(), srvListenAddr, misc.ArgsToList(upstreamServers))
		if noraceproxy {
			fmt.Printf("race mode disabled.\n")
		} else {
			fmt.Printf("race mode enabled.\n")
		}
		fmt.Printf("debug level: %d\n", debuglevel)
	}
	udpServer := &dns.Server{Addr: srvListenAddr, Net: "udp"}
	tcpServer := &dns.Server{Addr: srvListenAddr, Net: "tcp"}
	dns.HandleFunc(".", route)
	go func() {
		log.Fatal(udpServer.ListenAndServe())
	}()
	log.Fatal(tcpServer.ListenAndServe())
	//
	// TODO: LRU cache
	//
}

func route(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 || !allowed(w, req) {
		dns.HandleFailed(w, req)
		return
	}
	for name, addr := range routes {
		if strings.HasSuffix(req.Question[0].Name, name) {
			proxy(addr, w, req)
			return
		}
	}
	if noraceproxy {
		proxy(defaultServer, w, req)
	} else {
		mproxy(upstreamServers, w, req)
	}
}

func isTransfer(req *dns.Msg) bool {
	for _, q := range req.Question {
		switch q.Qtype {
		case dns.TypeIXFR, dns.TypeAXFR:
			return true
		}
	}
	return false
}

var hostRE = regexp.MustCompile(`^\[?([0-9a-f:.]+)\]?:[0-9]+$`)

// extractHost extract host from host:port in IPv4 (1.2.3.4:1234) or IPv6 ([::1]:1234).
func extractHost(remoteAddr string) string {
	m := hostRE.FindStringSubmatch(remoteAddr)
	if m == nil {
		return ""
	}
	return m[1]
}

func allowed(w dns.ResponseWriter, req *dns.Msg) bool {
	if !isTransfer(req) {
		return true
	}
	remote := extractHost(w.RemoteAddr().String())
	for _, ip := range transferIPs {
		if ip == remote {
			return true
		}
	}
	return false
}

func proxy(addr string, w dns.ResponseWriter, req *dns.Msg) {
	transport := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		transport = "tcp"
	}
	if isTransfer(req) {
		if transport != "tcp" {
			dns.HandleFailed(w, req)
			return
		}
		t := new(dns.Transfer)
		c, err := t.In(req, addr)
		if err != nil {
			dns.HandleFailed(w, req)
			return
		}
		if err = t.Out(w, req, c); err != nil {
			dns.HandleFailed(w, req)
			return
		}
		return
	}
	c := &dns.Client{Net: transport}
	resp, _, err := c.Exchange(req, addr)
	if err != nil {
		dns.HandleFailed(w, req)
		return
	}
	w.WriteMsg(resp)
}

// send request to multi-dns-server and use the first response
func mproxy(addrs []string, w dns.ResponseWriter, req *dns.Msg) {
	transport := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		transport = "tcp"
	}
	if len(req.Question) == 0 {
		if debuglevel >= 2 {
			fmt.Printf("race proxying request from %s, upstream %s, transport %s, empty question discarded: \n%s\n", w.RemoteAddr().String(), misc.ArgsToList(addrs), transport, req.String())
		}
		return
	}
	if debuglevel >= 2 {
		fmt.Printf("race proxying request from %s, upstream %s, transport %s: %s\n", w.RemoteAddr().String(), misc.ArgsToList(addrs), transport, req.Question[0].String())
	} else if debuglevel >= 3 {
		fmt.Printf("race proxying request from %s, upstream %s, transport %s: \n%s\n", w.RemoteAddr().String(), misc.ArgsToList(addrs), transport, req.String())
	}
	if isTransfer(req) && len(addrs) > 0 {
		addr := addrs[0]
		if transport != "tcp" {
			dns.HandleFailed(w, req)
			return
		}
		t := new(dns.Transfer)
		c, err := t.In(req, addr)
		if err != nil {
			dns.HandleFailed(w, req)
			return
		}
		if err = t.Out(w, req, c); err != nil {
			dns.HandleFailed(w, req)
			return
		}
		return
	}

	//
	type result struct {
		resp *dns.Msg
		addr string
		err  error
	}

	respCh := make(chan *result, len(addrs))
	var mutex sync.Mutex
	var responsed uint64 = 0
	for _, addr := range addrs {
		go func(addr string) {
			if debuglevel >= 5 {
				fmt.Printf("launch race proxying request from %s, upstream %s, transport %s: \n%s\n", w.RemoteAddr().String(), addr, transport, req.String())
			}
			c := &dns.Client{Net: transport}
			resp, _, err := c.Exchange(req, addr)
			mutex.Lock()
			defer mutex.Unlock()
			raceresp := &result{
				resp: resp,
				addr: addr,
				err:  err,
			}
			if err != nil {
				if debuglevel >= 5 {
					fmt.Printf("race proxy from %s, upstream %s failed: %s\n", w.RemoteAddr().String(), addr, err.Error())
				}
				respCh <- raceresp
				return
			}
			if responsed == 0 {
				responsed++
				if debuglevel >= 5 {
					fmt.Printf("return response to %s, upstream %s: \n%s\n", w.RemoteAddr().String(), addr, resp.String())
				}
				respCh <- raceresp
				return
			}
			// discard response
			if debuglevel >= 5 {
				fmt.Printf("discard response from %s, upstream %s: \n%s\n", w.RemoteAddr().String(), addr, resp.String())
			}
			return
		}(addr)
	}
	// debug.PrintStack()
	errcnt := 0
	for raceresp := range respCh {
		if raceresp.err != nil {
			errcnt++
			if errcnt >= len(addrs) {
				if debuglevel >= 2 {
					fmt.Printf("race proxying for %s failed finally: %s\n", w.RemoteAddr().String(), raceresp.err.Error())
				}
				// all server failed
				dns.HandleFailed(w, req)
				return
			}
			continue
		}
		w.WriteMsg(raceresp.resp)
		if debuglevel >= 2 {
			fmt.Printf("return response to %s, upstream %s finally: %s\n", w.RemoteAddr().String(), raceresp.addr, raceresp.resp.Answer[0].String())
		} else if debuglevel >= 3 {
			fmt.Printf("return response to %s, upstream %s finally: \n%s\n", w.RemoteAddr().String(), raceresp.addr, raceresp.resp.String())
		}
		return
	}
	// never reach here
	panic("never reach here")
}
