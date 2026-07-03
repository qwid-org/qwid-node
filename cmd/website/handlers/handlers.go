package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/wonabru/qwid-node/wallet"
)

type contextKey string

const sessionContextKey contextKey = "session"

func contextWithSession(ctx context.Context, sess *Session) context.Context {
	return context.WithValue(ctx, sessionContextKey, sess)
}

func GetSession(ctx context.Context) *Session {
	sess, _ := ctx.Value(sessionContextKey).(*Session)
	return sess
}

var NodeWallet *wallet.Wallet
var NodeIP string
var DelegatedAccount int
var SigName string
var SigName2 string
var WebsiteBasePath string

// func SignMessage(line []byte) []byte {
// 	operation := string(line[0:4])
// 	verificationNeeded := true
// 	for _, noVerification := range common.ConnectionsWithoutVerification {
// 		if bytes.Equal([]byte(operation), noVerification) {
// 			verificationNeeded = false
// 			break
// 		}
// 	}
// 	if verificationNeeded {
// 		if NodeWallet == nil || (!NodeWallet.Check() || !NodeWallet.Check2()) {
// 			logger.GetLogger().Println("node wallet not loaded yet")
// 			return line
// 		}
// 		if common.IsPaused() == false {
// 			// primary encryption used
// 			line = common.BytesToLenAndBytes(line)
// 			sign, err := NodeWallet.Sign(line, true)
// 			if err != nil {
// 				logger.GetLogger().Println(err)
// 				return line
// 			}
// 			line = append(line, sign.GetBytes()...)
// 		} else {
// 			// secondary encryption
// 			line = common.BytesToLenAndBytes(line)
// 			sign, err := NodeWallet.Sign(line, false)
// 			if err != nil {
// 				logger.GetLogger().Println(err)
// 				return line
// 			}
// 			line = append(line, sign.GetBytes()...)
// 		}
// 	} else {
// 		line = common.BytesToLenAndBytes(line)
// 	}
// 	return line
// }

// func SetCurrentEncryptions() (string, string, error) {
// 	type result struct {
// 		sig1, sig2 string
// 		err        error
// 	}
// 	ch := make(chan result, 1)
// 	go func() {
// 		clientrpc.InRPC <- SignMessage([]byte("ENCR"))
// 		reply := <-clientrpc.OutRPC
// 		if bytes.Equal(reply, []byte("Timeout")) {
// 			ch <- result{err: fmt.Errorf("timeout")}
// 			return
// 		}
// 		enc1b, left, err := common.BytesWithLenToBytes(reply)
// 		if err != nil {
// 			ch <- result{err: err}
// 			return
// 		}
// 		enc2b, _, err := common.BytesWithLenToBytes(left)
// 		if err != nil {
// 			ch <- result{err: err}
// 			return
// 		}
// 		enc1, err := blocks.FromBytesToEncryptionConfig(enc1b, true)
// 		if err != nil {
// 			ch <- result{err: err}
// 			return
// 		}
// 		common.SetEncryption(enc1.SigName, enc1.PubKeyLength, enc1.PrivateKeyLength, enc1.SignatureLength, enc1.IsPaused, true)
// 		enc2, err := blocks.FromBytesToEncryptionConfig(enc2b, false)
// 		if err != nil {
// 			ch <- result{err: err}
// 			return
// 		}
// 		common.SetEncryption(enc2.SigName, enc2.PubKeyLength, enc2.PrivateKeyLength, enc2.SignatureLength, enc2.IsPaused, false)
// 		ch <- result{sig1: enc1.SigName, sig2: enc2.SigName}
// 	}()
// 	select {
// 	case r := <-ch:
// 		return r.sig1, r.sig2, r.err
// 	case <-time.After(5 * time.Second):
// 		s1, s2 := common.SigName(), common.SigName2()
// 		if s1 != "" && s2 != "" {
// 			return s1, s2, nil
// 		}
// 		return "", "", fmt.Errorf("timeout retrieving encryption config")
// 	}
// }

// isAllowedOrigin reflects only origins listed in the CORS_ALLOWED_ORIGINS
// environment variable (comma-separated). WH-C2: replaces the wildcard
// Access-Control-Allow-Origin so arbitrary sites cannot script the wallet API.
// With no env set, no cross-origin is allowed (same-origin still works).
func isAllowedOrigin(origin string) bool {
	if origin == "" {
		return false
	}
	for _, a := range strings.Split(os.Getenv("CORS_ALLOWED_ORIGINS"), ",") {
		if strings.TrimSpace(a) == origin && a != "" {
			return true
		}
	}
	return false
}

func CorsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); isAllowedOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		// WH-H5: security headers.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Type", "application/json")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := Sessions.GetFromRequest(r)
		if sess == nil {
			JsonError(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		// Store session in request context
		ctx := r.Context()
		ctx = contextWithSession(ctx, sess)
		next(w, r.WithContext(ctx))
	}
}

func JsonResponse(w http.ResponseWriter, data interface{}) {
	json.NewEncoder(w).Encode(data)
}

func JsonError(w http.ResponseWriter, message string, code int) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
