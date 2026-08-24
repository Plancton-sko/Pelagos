package transport

import (
	"context"
	"fmt"
)

// BluetoothTransport defines an abstract local peer-to-peer transport over Bluetooth RFCOMM / BLE.
//
// Protocol Independence Rationale:
// Because Palagos session cryptographic state (Double Ratchet, AEAD, Ed25519 signatures, replay window)
// is self-contained within the binary packet payload, transporting a packet over Bluetooth requires zero changes
// to the key management or cryptographic code.
type BluetoothTransport struct {
	DeviceMAC string
}

// NewBluetoothTransport creates a new Bluetooth transport instance for a given MAC address.
func NewBluetoothTransport(mac string) *BluetoothTransport {
	return &BluetoothTransport{DeviceMAC: mac}
}

func (bt *BluetoothTransport) Listen(ctx context.Context, address string) error {
	return fmt.Errorf("bluetooth_transport: platform RFCOMM listener stub (requires platform CGO / DBus socket)")
}

func (bt *BluetoothTransport) Dial(ctx context.Context, address string) (Conn, error) {
	return nil, fmt.Errorf("bluetooth_transport: platform RFCOMM dial stub (requires platform CGO / DBus socket)")
}

func (bt *BluetoothTransport) Accept(ctx context.Context) (Conn, error) {
	return nil, fmt.Errorf("bluetooth_transport: platform RFCOMM accept stub")
}

func (bt *BluetoothTransport) Close() error {
	return nil
}

func (bt *BluetoothTransport) Addr() string {
	return bt.DeviceMAC
}
