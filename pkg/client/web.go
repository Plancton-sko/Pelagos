package client

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"palagos/pkg/identity"
)

// WebServer handles the local UI HTTP server and REST API for the Palagos Client.
type WebServer struct {
	Manager *Manager
	Addr    string
	mu      sync.Mutex
}

// NewWebServer creates a new WebServer instance.
func NewWebServer(mgr *Manager, addr string) *WebServer {
	return &WebServer{
		Manager: mgr,
		Addr:    addr,
	}
}

// Start launches the local HTTP server.
func (ws *WebServer) Start() error {
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/identity", ws.handleIdentity)
	mux.HandleFunc("/api/contacts", ws.handleContacts)
	mux.HandleFunc("/api/messages", ws.handleMessages)
	mux.HandleFunc("/api/pair/create", ws.handlePairCreate)
	mux.HandleFunc("/api/pair/open", ws.handlePairOpen)

	// Single Page Application (UI)
	mux.HandleFunc("/", ws.handleIndex)

	fmt.Printf("[+] Pelagos Web UI running at http://%s\n", ws.Addr)
	return http.ListenAndServe(ws.Addr, mux)
}

func (ws *WebServer) handleIdentity(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		activeId := ws.Manager.GetActiveIdentity()
		pubHex := hex.EncodeToString(activeId.PublicKey)
		privHex := hex.EncodeToString(activeId.PrivateKey)
		fp := activeId.FormattedFingerprint()

		json.NewEncoder(w).Encode(map[string]interface{}{
			"active_profile": ws.Manager.ActiveProfile,
			"public_key_hex": pubHex,
			"private_key_hex": privHex,
			"fingerprint":    fp,
			"profiles":       ws.getProfileNames(),
		})

	case "POST":
		var req struct {
			Action      string `json:"action"` // "create" or "switch"
			ProfileName string `json:"profile_name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if req.Action == "create" {
			newId, err := identity.GenerateIdentity()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			ws.Manager.AddIdentityProfile(req.ProfileName, newId)
			ws.Manager.SwitchProfile(req.ProfileName)
		} else if req.Action == "switch" {
			if err := ws.Manager.SwitchProfile(req.ProfileName); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}

		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}

func (ws *WebServer) getProfileNames() []string {
	ws.Manager.mu.RLock()
	defer ws.Manager.mu.RUnlock()
	var names []string
	for name := range ws.Manager.Identities {
		names = append(names, name)
	}
	return names
}

func (ws *WebServer) handleContacts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		contacts := ws.Manager.ListContacts()
		json.NewEncoder(w).Encode(contacts)

	case "POST":
		var req struct {
			PublicKeyHex string `json:"public_key_hex"`
			CustomAlias  string `json:"custom_alias"`
			OnionAddress string `json:"onion_address"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		pubBytes, err := hex.DecodeString(req.PublicKeyHex)
		if err != nil {
			http.Error(w, "invalid public key hex", http.StatusBadRequest)
			return
		}

		c, err := ws.Manager.SaveContact(pubBytes, req.CustomAlias, req.OnionAddress)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		json.NewEncoder(w).Encode(c)
	}
}

func (ws *WebServer) resolveFingerprint(fpHex string) ([32]byte, error) {
	bytes, err := hex.DecodeString(fpHex)
	if err != nil || len(bytes) != 32 {
		return [32]byte{}, fmt.Errorf("invalid hex string length")
	}
	var arr [32]byte
	copy(arr[:], bytes)

	// Check if arr is directly a known contact fingerprint
	if _, ok := ws.Manager.GetContactByFP(arr); ok {
		return arr, nil
	}

	// Check if arr is a public key whose SHA-256 is a known contact fingerprint
	hashed := sha256.Sum256(bytes)
	if _, ok := ws.Manager.GetContactByFP(hashed); ok {
		return hashed, nil
	}

	return arr, nil
}

func (ws *WebServer) handleMessages(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		fpHex := r.URL.Query().Get("peer_fp")
		if fpHex == "" {
			http.Error(w, "missing peer_fp param", http.StatusBadRequest)
			return
		}

		peerFP, err := ws.resolveFingerprint(fpHex)
		if err != nil {
			http.Error(w, "invalid peer_fp", http.StatusBadRequest)
			return
		}

		msgs := ws.Manager.GetMessages(peerFP)
		json.NewEncoder(w).Encode(msgs)

	case "POST":
		var req struct {
			PeerFPHex string `json:"peer_fp"`
			Content   string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		peerFP, err := ws.resolveFingerprint(req.PeerFPHex)
		if err != nil {
			http.Error(w, "invalid peer_fp", http.StatusBadRequest)
			return
		}

		// Record sent message locally
		msg := ws.Manager.AddMessage(peerFP, req.Content, true, 0)
		json.NewEncoder(w).Encode(msg)
	}
}

func (ws *WebServer) handlePairCreate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req struct {
		PIN   string `json:"pin"`
		Alias string `json:"alias"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	activeId := ws.Manager.GetActiveIdentity()
	payload, err := identity.CreatePairingPayload(activeId, req.Alias, req.PIN)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	rawBytes := payload.Marshal()
	payloadHex := hex.EncodeToString(rawBytes)

	json.NewEncoder(w).Encode(map[string]string{
		"payload_hex": payloadHex,
		"fingerprint": activeId.FormattedFingerprint(),
	})
}

func (ws *WebServer) handlePairOpen(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var req struct {
		PIN        string `json:"pin"`
		PayloadHex string `json:"payload_hex"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	rawBytes, err := hex.DecodeString(req.PayloadHex)
	if err != nil {
		http.Error(w, "invalid payload hex", http.StatusBadRequest)
		return
	}

	payload, err := identity.UnmarshalPairingPayload(rawBytes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	activeId := ws.Manager.GetActiveIdentity()
	peerId, sasCode, err := identity.OpenPairingPayload(payload, activeId, req.PIN)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Save contact automatically
	contact, err := ws.Manager.SaveContact(peerId.PublicKey, peerId.Alias, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "paired",
		"sas_code":     sasCode,
		"contact":      contact,
		"peer_alias":   peerId.Alias,
		"fingerprint":  peerId.FormattedFingerprint(),
	})
}

func (ws *WebServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(htmlUI))
}

const htmlUI = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pelagos — Privacy-First Messenger</title>
    <style>
        :root {
            --bg-dark: #0B0E14;
            --panel-bg: #121824;
            --panel-border: #1F293D;
            --accent-blue: #2563EB;
            --accent-glow: #60A5FA;
            --msg-received: #1A2332;
            --msg-sent: #1E3A8A;
            --text-main: #F3F4F6;
            --text-muted: #9CA3AF;
            --badge-green: #10B981;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; }
        body { background-color: var(--bg-dark); color: var(--text-main); height: 100vh; display: flex; overflow: hidden; }

        /* Sidebar 1: Profile & Navigation */
        .nav-sidebar { width: 72px; background: #07090D; border-right: 1px solid var(--panel-border); display: flex; flex-direction: column; align-items: center; padding: 16px 0; gap: 20px; }
        .nav-icon { width: 48px; height: 48px; border-radius: 16px; background: var(--panel-bg); display: flex; align-items: center; justify-content: center; cursor: pointer; transition: all 0.2s; font-weight: bold; color: var(--accent-glow); border: 1px solid var(--panel-border); }
        .nav-icon:hover, .nav-icon.active { background: var(--accent-blue); color: white; border-color: var(--accent-glow); box-shadow: 0 0 12px rgba(37,99,235,0.4); }

        /* Sidebar 2: Contacts List (Telegram Style) */
        .contacts-sidebar { width: 320px; background: var(--panel-bg); border-right: 1px solid var(--panel-border); display: flex; flex-direction: column; }
        .header { padding: 20px; border-bottom: 1px solid var(--panel-border); display: flex; justify-content: space-between; align-items: center; }
        .header h2 { font-size: 1.1rem; color: var(--text-main); }
        .btn-add { background: var(--accent-blue); color: white; border: none; padding: 8px 14px; border-radius: 8px; cursor: pointer; font-size: 0.85rem; font-weight: 600; }
        .btn-add:hover { background: #1D4ED8; }

        .contact-list { flex: 1; overflow-y: auto; }
        .contact-item { padding: 14px 20px; border-bottom: 1px solid rgba(255,255,255,0.03); cursor: pointer; display: flex; align-items: center; gap: 12px; transition: background 0.15s; }
        .contact-item:hover, .contact-item.active { background: #192233; }
        .avatar { width: 42px; height: 42px; border-radius: 50%; background: linear-gradient(135deg, #2563EB, #1D4ED8); display: flex; align-items: center; justify-content: center; font-weight: bold; color: white; }
        .contact-info { flex: 1; overflow: hidden; }
        .contact-name { font-weight: 600; font-size: 0.95rem; margin-bottom: 4px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .contact-fp { font-size: 0.75rem; color: var(--text-muted); font-family: monospace; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

        /* Main Chat Area */
        .chat-area { flex: 1; display: flex; flex-direction: column; background: var(--bg-dark); }
        .chat-header { padding: 16px 24px; background: var(--panel-bg); border-bottom: 1px solid var(--panel-border); display: flex; align-items: center; justify-content: space-between; }
        .chat-title { display: flex; align-items: center; gap: 12px; }
        .badge-tor { background: rgba(16,185,129,0.15); color: var(--badge-green); padding: 4px 10px; border-radius: 12px; font-size: 0.75rem; border: 1px solid rgba(16,185,129,0.3); }

        .messages-container { flex: 1; padding: 24px; overflow-y: auto; display: flex; flex-direction: column; gap: 12px; }
        .msg-bubble { max-width: 60%; padding: 12px 16px; border-radius: 14px; font-size: 0.95rem; line-height: 1.4; word-break: break-word; }
        .msg-received { background: var(--msg-received); align-self: flex-start; border-bottom-left-radius: 4px; border: 1px solid var(--panel-border); }
        .msg-sent { background: var(--msg-sent); align-self: flex-end; border-bottom-right-radius: 4px; border: 1px solid rgba(96,165,250,0.3); }

        .input-area { padding: 16px 24px; background: var(--panel-bg); border-top: 1px solid var(--panel-border); display: flex; gap: 12px; }
        .input-field { flex: 1; background: var(--bg-dark); border: 1px solid var(--panel-border); border-radius: 10px; padding: 12px 16px; color: white; font-size: 0.95rem; outline: none; }
        .input-field:focus { border-color: var(--accent-glow); }
        .btn-send { background: var(--accent-blue); color: white; border: none; width: 46px; height: 46px; border-radius: 10px; cursor: pointer; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; }

        /* Modal Overlay */
        .modal { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7); backdrop-filter: blur(8px); align-items: center; justify-content: center; z-index: 100; }
        .modal-body { background: var(--panel-bg); border: 1px solid var(--panel-border); border-radius: 16px; width: 420px; padding: 24px; display: flex; flex-direction: column; gap: 16px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
        .modal-body h3 { color: var(--accent-glow); font-size: 1.2rem; }
        .modal-input { background: var(--bg-dark); border: 1px solid var(--panel-border); padding: 10px 14px; border-radius: 8px; color: white; width: 100%; }
        .sas-box { background: rgba(37,99,235,0.15); border: 1px dashed var(--accent-glow); padding: 16px; text-align: center; border-radius: 12px; font-size: 1.6rem; font-weight: bold; letter-spacing: 4px; color: var(--accent-glow); }
    </style>
</head>
<body>
    <div class="nav-sidebar">
        <div class="nav-icon active" title="Conversas">💬</div>
        <div class="nav-icon" onclick="openPairModal()" title="Emparelhar por PIN (Sem Câmera)">🔑</div>
        <div class="nav-icon" onclick="showIdentity()" title="Sua Identidade">👤</div>
    </div>

    <div class="contacts-sidebar">
        <div class="header">
            <h2>Pelagos Chat</h2>
            <button class="btn-add" onclick="openAddModal()">+ Contato</button>
        </div>
        <div class="contact-list" id="contactList"></div>
    </div>

    <div class="chat-area">
        <div class="chat-header">
            <div class="chat-title">
                <div class="avatar" id="activeAvatar">?</div>
                <div>
                    <h3 id="activeName">Selecione uma conversa</h3>
                    <span style="font-size:0.75rem; color: var(--text-muted);" id="activeFP"></span>
                </div>
            </div>
            <div class="badge-tor">🟢 Tor Double Ratchet Active</div>
        </div>

        <div class="messages-container" id="msgContainer"></div>

        <div class="input-area">
            <input type="text" class="input-field" id="msgInput" placeholder="Digite uma mensagem criptografada (E2EE)..." onkeydown="if(event.key==='Enter') sendMsg()">
            <button class="btn-send" onclick="sendMsg()">➔</button>
        </div>
    </div>

    <!-- Modal Adicionar Contato -->
    <div class="modal" id="addModal">
        <div class="modal-body">
            <h3>Adicionar Novo Contato</h3>
            <label>Nome / Apelido Personalizado:</label>
            <input type="text" id="newAlias" class="modal-input" placeholder="Ex: Bob (Trabalho)">
            <label>Public Key Hex do Peer:</label>
            <input type="text" id="newPubKey" class="modal-input" placeholder="Chave Pública Hex (64 caracteres)">
            <label>Endereço .onion (Opcional):</label>
            <input type="text" id="newOnion" class="modal-input" placeholder="xxxx.onion:9090">
            <button class="btn-add" onclick="saveContact()">Salvar Contato</button>
            <button class="btn-add" style="background:#374151;" onclick="closeModals()">Cancelar</button>
        </div>
    </div>

    <!-- Modal Emparelhar por PIN -->
    <div class="modal" id="pairModal">
        <div class="modal-body">
            <h3>🔑 Emparelhamento por PIN (Sem Câmera)</h3>
            <label>PIN de 6 dígitos combinado presencialmente:</label>
            <input type="text" id="pairPIN" class="modal-input" placeholder="Ex: 482901">
            <label>Payload Hex Recebido via Bluetooth (se for abrir):</label>
            <input type="text" id="pairPayload" class="modal-input" placeholder="Cole o payload recebido ou deixe vazio para gerar">
            
            <div id="sasResult" style="display:none;">
                <label>Código de Confirmação SAS:</label>
                <div class="sas-box" id="sasCodeDisplay">--- ---</div>
            </div>

            <button class="btn-add" onclick="processPairing()">Processar Emparelhamento</button>
            <button class="btn-add" style="background:#374151;" onclick="closeModals()">Fechar</button>
        </div>
    </div>

    <script>
        let currentContactFP = null;
        let contactsMap = {};

        async function loadContacts() {
            const res = await fetch('/api/contacts');
            const data = await res.json() || [];
            const listEl = document.getElementById('contactList');
            listEl.innerHTML = '';
            data.forEach(c => {
                contactsMap[c.formatted_fingerprint] = c;
                const div = document.createElement('div');
                div.className = 'contact-item ' + (currentContactFP === c.fingerprint ? 'active' : '');
                div.onclick = () => selectContact(c);
                div.innerHTML = '<div class="avatar">' + c.custom_alias.charAt(0).toUpperCase() + '</div>' +
                    '<div class="contact-info">' +
                        '<div class="contact-name">' + c.custom_alias + '</div>' +
                        '<div class="contact-fp">' + c.formatted_fingerprint.substring(0, 16) + '...</div>' +
                    '</div>';
                listEl.appendChild(div);
            });
        }

        function selectContact(c) {
            currentContactFP = c.public_key_hex; // Using hex string
            document.getElementById('activeName').innerText = c.custom_alias;
            document.getElementById('activeFP').innerText = 'Fingerprint: ' + c.formatted_fingerprint;
            document.getElementById('activeAvatar').innerText = c.custom_alias.charAt(0).toUpperCase();
            loadMessages(c.public_key_hex);
        }

        async function loadMessages(fpHex) {
            const res = await fetch('/api/messages?peer_fp=' + fpHex);
            const msgs = await res.json() || [];
            const box = document.getElementById('msgContainer');
            box.innerHTML = '';
            msgs.forEach(m => {
                const bubble = document.createElement('div');
                bubble.className = 'msg-bubble ' + (m.sender_is_me ? 'msg-sent' : 'msg-received');
                bubble.innerText = m.content;
                box.appendChild(bubble);
            });
            box.scrollTop = box.scrollHeight;
        }

        async function sendMsg() {
            const input = document.getElementById('msgInput');
            const text = input.value.trim();
            if (!text || !currentContactFP) return;
            
            await fetch('/api/messages', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ peer_fp: currentContactFP, content: text })
            });
            input.value = '';
            loadMessages(currentContactFP);
        }

        function openAddModal() { document.getElementById('addModal').style.display = 'flex'; }
        function openPairModal() { document.getElementById('pairModal').style.display = 'flex'; }
        function closeModals() { 
            document.getElementById('addModal').style.display = 'none'; 
            document.getElementById('pairModal').style.display = 'none'; 
        }

        async function saveContact() {
            const alias = document.getElementById('newAlias').value;
            const pubKey = document.getElementById('newPubKey').value;
            const onion = document.getElementById('newOnion').value;
            if (!alias || !pubKey) return alert('Preencha o Nome e a Public Key!');
            
            await fetch('/api/contacts', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ custom_alias: alias, public_key_hex: pubKey, onion_address: onion })
            });
            closeModals();
            loadContacts();
        }

        async function processPairing() {
            const pin = document.getElementById('pairPIN').value;
            const payload = document.getElementById('pairPayload').value;
            if (!pin) return alert('Digite o PIN!');

            if (payload) {
                // Open Payload
                const res = await fetch('/api/pair/open', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ pin: pin, payload_hex: payload })
                });
                const data = await res.json();
                if (data.sas_code) {
                    document.getElementById('sasResult').style.display = 'block';
                    document.getElementById('sasCodeDisplay').innerText = data.sas_code;
                    alert('Contato "' + data.peer_alias + '" emparelhado e salvo!');
                    loadContacts();
                } else {
                    alert('Erro ao emparelhar. Verifique o PIN!');
                }
            } else {
                // Create Payload
                const res = await fetch('/api/pair/create', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ pin: pin, alias: 'MeuDispositivo' })
                });
                const data = await res.json();
                prompt('Transmita este Payload Hex para o seu amigo:', data.payload_hex);
            }
        }

        async function showIdentity() {
            const res = await fetch('/api/identity');
            const data = await res.json();
            alert('Sua Chave Pública Hex:\n' + data.public_key_hex + '\n\nSeu Fingerprint:\n' + data.fingerprint);
        }

        loadContacts();
    </script>
</body>
</html>`;
