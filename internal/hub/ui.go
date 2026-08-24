package hub

import (
	_ "embed"
	"net/http"
)

//go:embed web/index.html
var indexHTML []byte

func (s *Server) serveUI(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != "/" {
		http.NotFound(writer, request)
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(indexHTML)
}
