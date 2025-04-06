package proxy

import (
	"chimney3/core"
	"chimney3/privacy"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

type ProxyServer interface {
	Serve()
	Close()
}

type proxyServer struct {
	Host     string
	Password string
	Which    string
	Exit     bool
}

func (p *proxyServer) Serve() {
	key := privacy.MakeCompressKey(p.Password)
	II := privacy.NewMethodWithName(p.Which)
	l, err := core.ListenSSL(p.Host, key, II)
	if err != nil {
		log.Println("listen failed ", err)
		return
	}

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	server.Serve(l)
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	dest_conn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	client_conn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	var wg sync.WaitGroup
	wg.Add(2)

	go transfer(dest_conn, client_conn, &wg)
	go transfer(client_conn, dest_conn, &wg)
	wg.Wait()
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func (p *proxyServer) Close() {
	// Implement the logic to close the proxy server
	p.Exit = true
}
