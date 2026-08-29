package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/qwid-org/qwid-node/cmd/explorer/handlers"
	clientrpc "github.com/qwid-org/qwid-node/rpc/client"
	"github.com/qwid-org/qwid-node/statistics"
)

//go:embed static/*
var staticFiles embed.FS

func main() {
	var ip string
	port := "8090"

	if len(os.Args) > 1 {
		ip = os.Args[1]
	} else {
		ip = "127.0.0.1"
	}
	if len(os.Args) > 2 {
		port = os.Args[2]
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	statistics.InitStatsManager()
	go clientrpc.ConnectRPC(ip)
	time.Sleep(time.Second)

	handlers.NodeIP = ip

	// Adopt the chain's signature schemes before serving anything, then keep
	// following them. This process holds its own copy of the encryption config,
	// starting at the build's compiled defaults; without this it decodes blocks
	// and transactions with the wrong key and signature lengths as soon as the
	// chain votes in a different scheme, and a restart does not help because it
	// never asks.
	if err := handlers.SyncEncryptionFromNode(); err != nil {
		fmt.Println("could not read the encryption config from the node:", err)
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if err := handlers.SyncEncryptionFromNode(); err != nil {
				fmt.Println("could not refresh the encryption config:", err)
			}
		}
	}()

	mux := http.NewServeMux()

	mux.HandleFunc("/api/stats", corsMiddleware(handlers.GetStats))
	mux.HandleFunc("/api/block", corsMiddleware(handlers.GetBlock))
	mux.HandleFunc("/api/blocks", corsMiddleware(handlers.GetBlocks))
	mux.HandleFunc("/api/tx", corsMiddleware(handlers.GetTransaction))
	mux.HandleFunc("/api/account", corsMiddleware(handlers.GetAccount))
	mux.HandleFunc("/api/search", corsMiddleware(handlers.Search))
	mux.HandleFunc("/api/validators", corsMiddleware(handlers.GetValidators))
	mux.HandleFunc("/api/validators/blocks", corsMiddleware(handlers.GetValidatorBlocks))
	mux.HandleFunc("/api/contact", corsMiddleware(handlers.SendContact))

	staticFS, _ := fs.Sub(staticFiles, "static")
	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	// Security headers wrap every route, static and API alike. They live here
	// rather than in the nginx vhost because WAN port 80 is forwarded straight
	// to this process (see deploy/TLS-explorer.md) and so never passes through
	// nginx at all — headers configured there would silently miss that path.
	// Rate limiting sits outside the header middleware so that a throttled 429
	// still carries them.
	handler := securityHeaders(rateLimit(mux))

	fmt.Printf("\n===========================================\n")
	fmt.Printf("  QWID Blockchain Explorer\n")
	fmt.Printf("===========================================\n")
	fmt.Printf("  Node IP: %s\n", ip)
	fmt.Printf("  Explorer: http://0.0.0.0:%s\n", port)
	fmt.Printf("  Press Ctrl+C to stop\n")
	fmt.Printf("===========================================\n\n")

	// WH-M12: bind address is configurable (default all interfaces for a public
	// explorer). Set BIND_ADDRESS=127.0.0.1 to restrict, e.g. behind a TLS proxy.
	bindHost := os.Getenv("BIND_ADDRESS")
	if bindHost == "" {
		bindHost = "0.0.0.0"
	}
	server := &http.Server{
		Addr:    bindHost + ":" + port,
		Handler: handler,
		// WH-M5: connection timeouts to mitigate Slowloris.
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Println("Failed to start server:", err)
			os.Exit(1)
		}
	}()

	<-stop
	fmt.Println("\nShutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		fmt.Println("Server shutdown error:", err)
	}
	fmt.Println("Server stopped")
}

// securityHeaders sets the response headers that are missing by default from
// net/http. Applied to every route; the API handlers below deliberately relax
// one of them.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()

		// HSTS. Browsers ignore this header when it arrives over plaintext, so
		// sending it unconditionally is safe even though port 80 reaches this
		// process directly.
		//
		// max-age is deliberately short for now. HSTS turns an expired
		// certificate from a warning the visitor can click through into a hard
		// block with no way past it, and this domain's certificate did expire
		// on 2026-08-12 because renewal had been failing unnoticed for a month.
		// Raise this to 31536000 (one year) once automatic renewal has been
		// observed to succeed on its own at least twice; do not add "preload"
		// before that, as preload entries are slow and painful to undo.
		h.Set("Strict-Transport-Security", "max-age=86400; includeSubDomains")

		// CSP. Note what is absent: 'unsafe-inline' appears nowhere.
		//
		// That is only possible because static/index.html carries no inline
		// <script>, no inline <style> and no onclick="" attributes — they were
		// moved into app.js and app.css precisely so this header could be
		// strict. Reintroducing any of them silently breaks the page rather
		// than weakening the policy, which is the intended failure direction.
		//
		// default-src 'none' means every fetch type not named below is denied
		// outright, so a directive missed here fails closed. connect-src 'self'
		// is enough because the page calls its own API on the same origin.
		h.Set("Content-Security-Policy",
			"default-src 'none'; "+
				"script-src 'self'; "+
				"style-src 'self'; "+
				"font-src 'self'; "+
				"img-src 'self' data:; "+
				"connect-src 'self'; "+
				"base-uri 'none'; "+
				"form-action 'none'; "+
				"frame-ancestors 'none'")

		// Never let the browser second-guess a declared Content-Type.
		h.Set("X-Content-Type-Options", "nosniff")

		// Clickjacking: nothing here is meant to be framed anywhere. Superseded
		// by CSP frame-ancestors once a policy is in place, but kept for older
		// browsers that do not implement it.
		h.Set("X-Frame-Options", "DENY")

		// Send the origin, never the full path, to other sites.
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// The explorer uses none of these capabilities; deny them outright so an
		// injected script cannot ask for them either.
		h.Set("Permissions-Policy",
			"accelerometer=(), autoplay=(), camera=(), display-capture=(), "+
				"encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), "+
				"magnetometer=(), microphone=(), midi=(), payment=(), "+
				"picture-in-picture=(), usb=(), xr-spatial-tracking=()")

		// Detach this browsing context from any window that opened it.
		h.Set("Cross-Origin-Opener-Policy", "same-origin")

		// Pages and assets are for this origin only. /api/* overrides this —
		// see corsMiddleware.
		h.Set("Cross-Origin-Resource-Policy", "same-origin")

		next.ServeHTTP(w, r)
	})
}

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The API is deliberately public — qwid.org fetches live network
		// figures from it — so it must override the same-origin resource
		// policy that securityHeaders applies to the rest of the site.
		w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Content-Type", "application/json")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

func jsonResponse(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, message string, code int) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
