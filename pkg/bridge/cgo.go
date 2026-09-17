package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"context"
	"encoding/hex"
	"encoding/json"
	"time"
	"unsafe"

	"palagos/pkg/client"
	"palagos/pkg/identity"
)

var globalManager *client.Manager

//export Palagos_InitManager
func Palagos_InitManager(socksAddr *C.char) *C.char {
	sAddr := C.GoString(socksAddr)
	mgr, err := client.NewManager(sAddr)
	if err != nil {
		return C.CString(err.Error())
	}
	globalManager = mgr
	return C.CString("OK")
}

//export Palagos_SetMode
func Palagos_SetMode(mode *C.char, relayAddr *C.char) *C.char {
	if globalManager == nil {
		return C.CString("Error: Manager not initialized")
	}
	mStr := C.GoString(mode)
	rAddr := C.GoString(relayAddr)
	globalManager.SetConnectionMode(client.ConnectionMode(mStr), rAddr)
	return C.CString("OK")
}

//export Palagos_GenerateIdentity
func Palagos_GenerateIdentity() *C.char {
	id, err := identity.GenerateIdentity()
	if err != nil {
		return C.CString(err.Error())
	}

	pubHex := hex.EncodeToString(id.PublicKey)
	privHex := hex.EncodeToString(id.PrivateKey)
	fp := id.FormattedFingerprint()

	res := map[string]string{
		"public_key_hex":  pubHex,
		"private_key_hex": privHex,
		"fingerprint":     fp,
	}
	bytes, _ := json.Marshal(res)
	return C.CString(string(bytes))
}

//export Palagos_SaveContact
func Palagos_SaveContact(pubKeyHex *C.char, customAlias *C.char, onionAddr *C.char) *C.char {
	if globalManager == nil {
		return C.CString("Error: Manager not initialized")
	}
	pHex := C.GoString(pubKeyHex)
	alias := C.GoString(customAlias)
	oAddr := C.GoString(onionAddr)

	pubBytes, err := hex.DecodeString(pHex)
	if err != nil {
		return C.CString("Error: Invalid public key hex")
	}

	c, err := globalManager.SaveContact(pubBytes, alias, oAddr)
	if err != nil {
		return C.CString(err.Error())
	}

	bytes, _ := json.Marshal(c)
	return C.CString(string(bytes))
}

//export Palagos_PairCreate
func Palagos_PairCreate(pin *C.char, alias *C.char) *C.char {
	if globalManager == nil {
		return C.CString("Error: Manager not initialized")
	}
	pPin := C.GoString(pin)
	pAlias := C.GoString(alias)

	activeId := globalManager.GetActiveIdentity()
	payload, err := identity.CreatePairingPayload(activeId, pAlias, pPin)
	if err != nil {
		return C.CString(err.Error())
	}

	rawBytes := payload.Marshal()
	payloadHex := hex.EncodeToString(rawBytes)

	res := map[string]string{
		"payload_hex": payloadHex,
		"fingerprint": activeId.FormattedFingerprint(),
	}
	bytes, _ := json.Marshal(res)
	return C.CString(string(bytes))
}

//export Palagos_PairOpen
func Palagos_PairOpen(pin *C.char, payloadHex *C.char) *C.char {
	if globalManager == nil {
		return C.CString("Error: Manager not initialized")
	}
	pPin := C.GoString(pin)
	pHex := C.GoString(payloadHex)

	rawBytes, err := hex.DecodeString(pHex)
	if err != nil {
		return C.CString("Error: Invalid payload hex")
	}

	payload, err := identity.UnmarshalPairingPayload(rawBytes)
	if err != nil {
		return C.CString(err.Error())
	}

	activeId := globalManager.GetActiveIdentity()
	peerId, sasCode, err := identity.OpenPairingPayload(payload, activeId, pPin)
	if err != nil {
		return C.CString(err.Error())
	}

	c, err := globalManager.SaveContact(peerId.PublicKey, peerId.Alias, "")
	if err != nil {
		return C.CString(err.Error())
	}

	res := map[string]interface{}{
		"status":      "paired",
		"sas_code":    sasCode,
		"peer_alias":  peerId.Alias,
		"fingerprint": peerId.FormattedFingerprint(),
		"contact":     c,
	}
	bytes, _ := json.Marshal(res)
	return C.CString(string(bytes))
}

//export Palagos_SendMessage
func Palagos_SendMessage(peerFPHex *C.char, text *C.char) *C.char {
	if globalManager == nil {
		return C.CString("Error: Manager not initialized")
	}
	fpHex := C.GoString(peerFPHex)
	msgText := C.GoString(text)

	fpBytes, err := hex.DecodeString(fpHex)
	if err != nil || len(fpBytes) != 32 {
		return C.CString("Error: Invalid peer fingerprint hex")
	}

	var peerFP [32]byte
	copy(peerFP[:], fpBytes)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	msg, err := globalManager.SendTextMessage(ctx, peerFP, msgText)
	if err != nil {
		return C.CString(err.Error())
	}

	bytes, _ := json.Marshal(msg)
	return C.CString(string(bytes))
}

//export Palagos_FreeString
func Palagos_FreeString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

func main() {}
