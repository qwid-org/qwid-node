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

	"github.com/wonabru/qwid-node/cmd/explorer/handlers"
	clientrpc "github.com/wonabru/qwid-node/rpc/client"
	"github.com/wonabru/qwid-node/statistics"
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

	fmt.Printf("\n===========================================\n")
	fmt.Printf("  QWID Blockchain Explorer\n")
	fmt.Printf("===========================================\n")
	fmt.Printf("  Node IP: %s\n", ip)
	fmt.Printf("  Explorer: http://0.0.0.0:%s\n", port)
	fmt.Printf("  Press Ctrl+C to stop\n")
	fmt.Printf("===========================================\n\n")

	server := &http.Server{
		Addr:    "0.0.0.0:" + port,
		Handler: mux,
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

func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
