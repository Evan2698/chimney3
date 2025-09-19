package socks5

import (
	"chimney3/settings"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sync"

	"golang.org/x/net/proxy"
)

type HttpProxyRoutineHandler struct {
	Dialer proxy.Dialer
}

func Run2HTTP(s *settings.Settings) error {
	httpUrl := s.Client.Httpurl
	socks5Url := net.JoinHostPort(fmt.Sprintf("socks5://%s", s.Client.IP),
		fmt.Sprintf("%d", s.Client.Port))
	socksURL, err := url.Parse(socks5Url)
	socks5Dialer, err := proxy.FromURL(socksURL, proxy.Direct)
	if err != nil {
		log.Fatalln("can not make proxy dialer:", err)
	}
	if err != nil {
		log.Fatalln("can not make proxy dialer:", err)
	}
	if err := http.ListenAndServe(httpUrl, &HttpProxyRoutineHandler{Dialer: socks5Dialer}); err != nil {
		log.Fatalln("can not start http server:", err)
	}

}
func (h *HttpProxyRoutineHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hijack, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
		return
	}

	port := r.URL.Port()
	if port == "" {
		port = "80"
	}
	socksConn, err := h.Dialer.Dial("tcp", r.URL.Hostname()+":"+port)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	defer socksConn.Close()
	httpConn, _, err := hijack.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	defer httpConn.Close()
	if r.Method == http.MethodConnect {
		httpConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	} else {
		r.Write(socksConn)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go transfer(httpConn, socksConn, &wg)
	go transfer(socksConn, httpConn, &wg)
	wg.Wait()

}
func transfer(src, dst net.Conn, wg *sync.WaitGroup) {
	io.Copy(dst, src)
	wg.Done()
}
