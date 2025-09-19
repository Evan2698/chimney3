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

// HttpProxyRoutineHandler 负责将 HTTP 请求转发到 SOCKS5 代理。
type HttpProxyRoutineHandler struct {
	Dialer proxy.Dialer
}

// Run2HTTP 启动 HTTP 到 SOCKS5 的代理服务。
func Run2HTTP(s *settings.Settings) error {
	httpUrl := s.Client.Httpurl
	socks5Addr := fmt.Sprintf("socks5://%s:%d", s.Client.IP, s.Client.Port)
	socksURL, err := url.Parse(socks5Addr)
	if err != nil {
		return fmt.Errorf("invalid socks5 url: %w", err)
	}
	socks5Dialer, err := proxy.FromURL(socksURL, proxy.Direct)
	if err != nil {
		return fmt.Errorf("cannot create proxy dialer: %w", err)
	}
	handler := &HttpProxyRoutineHandler{Dialer: socks5Dialer}
	log.Printf("HTTP proxy listening on %s, forwarding to SOCKS5 %s", httpUrl, socks5Addr)
	if err := http.ListenAndServe(httpUrl, handler); err != nil {
		return fmt.Errorf("cannot start http server: %w", err)
	}
	return nil
}

// ServeHTTP 处理 HTTP 请求并通过 SOCKS5 代理转发。
func (h *HttpProxyRoutineHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
		return
	}

	port := r.URL.Port()
	if port == "" {
		port = "80"
	}
	target := net.JoinHostPort(r.URL.Hostname(), port)
	socksConn, err := h.Dialer.Dial("tcp", target)
	if err != nil {
		http.Error(w, "SOCKS5 dial error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer socksConn.Close()

	httpConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Hijack error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer httpConn.Close()

	if r.Method == http.MethodConnect {
		_, _ = httpConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	} else {
		if err := r.Write(socksConn); err != nil {
			http.Error(w, "Request write error: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go transfer(httpConn, socksConn, &wg)
	go transfer(socksConn, httpConn, &wg)
	wg.Wait()
}

// transfer 用于连接两个 net.Conn 并转发数据。
func transfer(src, dst net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	_, _ = io.Copy(dst, src)
}
