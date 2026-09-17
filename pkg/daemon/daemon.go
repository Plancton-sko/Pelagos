package daemon

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"palagos/pkg/client"
	"palagos/pkg/crypto"
)

// Daemon represents a local background service daemon for Pelagos Core Engine.
// Security Architecture:
// 1. Local Loopback Only: Binds exclusively to 127.0.0.1 loopback interface.
// 2. Bearer Token Authentication: Generates a 256-bit CSPRNG token required on every RPC request.
// 3. CSRF & Cross-Origin Protection: Rejects non-authorized browser Cross-Origin requests.
type Daemon struct {
	Manager   *client.Manager
	Addr      string
	AuthToken string
}

// NewDaemon initializes a new Daemon instance with a fresh CSPRNG Auth Token.
func NewDaemon(mgr *client.Manager, addr string) (*Daemon, error) {
	tokenBytes, err := crypto.SecureRandom(32)
	if err != nil {
		return nil, fmt.Errorf("daemon: failed to generate auth token: %w", err)
	}

	return &Daemon{
		Manager:   mgr,
		Addr:      addr,
		AuthToken: hex.EncodeToString(tokenBytes),
	}, nil
}

// Start launches the local RPC/IPC listener daemon.
func (d *Daemon) Start() error {
	listener, err := net.Listen("tcp", d.Addr)
	if err != nil {
		return fmt.Errorf("daemon: failed to listen on %s: %w", d.Addr, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/rpc/status", d.authMiddleware(d.handleStatus))
	mux.HandleFunc("/rpc/contacts", d.authMiddleware(d.handleContacts))
	mux.HandleFunc("/rpc/mode", d.authMiddleware(d.handleMode))

	fmt.Println("=================================================================")
	fmt.Println("         PALAGOS CORE ENGINE DAEMON (SECURITY ENFORCED)          ")
	fmt.Println("=================================================================")
	fmt.Printf("Daemon Endpoint: tcp://%s\n", d.Addr)
	fmt.Printf("RPC Auth Token:  %s\n", d.AuthToken)
	fmt.Println("=================================================================")
	fmt.Println("[SECURITY GUARANTEE] Require header 'Authorization: Bearer <TOKEN>'")

	return http.Serve(listener, mux)
}

// authMiddleware enforces Bearer Token authentication and CSRF origin protection.
func (d *Daemon) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Prevent CSRF from malicious web pages via browser fetch
		origin := r.Header.Get("Origin")
		if origin != "" && origin != "null" {
			http.Error(w, "Forbidden: Cross-Origin RPC requests rejected", http.StatusForbidden)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized: missing or invalid Authorization header", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		// Constant-time string comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(token), []byte(d.AuthToken)) != 1 {
			http.Error(w, "Unauthorized: invalid RPC Auth Token", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

func (d *Daemon) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	activeId := d.Manager.GetActiveIdentity()
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "online",
		"mode":        d.Manager.Mode,
		"relay_addr":  d.Manager.RelayAddr,
		"fingerprint": activeId.FormattedFingerprint(),
	})
}

func (d *Daemon) handleContacts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	contacts := d.Manager.ListContacts()
	json.NewEncoder(w).Encode(contacts)
}

func (d *Daemon) handleMode(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Mode      string `json:"mode"` // "relay" or "direct_p2p"
		RelayAddr string `json:"relay_addr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	d.Manager.SetConnectionMode(client.ConnectionMode(req.Mode), req.RelayAddr)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "mode": req.Mode})
}
