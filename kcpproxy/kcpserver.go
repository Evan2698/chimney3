package kcpproxy

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

type kcpServer struct {
	User     string
	PassWord string
	Host     string
	Exit     bool
}
type KCPServer interface {
	Serve()
	Close()
}

func NewKcpServer(User, Pass, Host string) KCPServer {
	return &kcpServer{
		User:     User,
		PassWord: Pass,
		Host:     Host,
		Exit:     false,
	}
}

func (c *kcpServer) Serve() {
	//ks := privacy.MakeCompressKey(c.PassWord)
	//salt := privacy.BuildMacHash(ks, c.User)

	//key := pbkdf2.Key(ks, salt, 4096, 32, sha1.New)
	//block, _ := kcp.NewSalsa20BlockCrypt(key)
	//l, err := kcp.ListenWithOptions(c.Host, block, 10, 3)
	l, err := net.Listen("tcp", c.Host)
	if err != nil {
		log.Println("listen failed", err)
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

func (c *kcpServer) Close() {
	c.Exit = true
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
	go transfer(dest_conn, client_conn)
	go transfer(client_conn, dest_conn)
}
func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
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
