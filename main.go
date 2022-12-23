package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/crypto/cryptobyte"

	"github.com/elecmir/dpib/windivert"
)

func main() {
	filter := "outbound and tcp.DstPort == 443 and tcp.PayloadLength > 150 and tcp.Payload[0] == 22 and tcp.Payload[5] == 1"
	handle, err := windivert.Open(filter, 23, 0, 0)
	if err != nil {
		log.Println("Call WinDivertOpen", err)
		return
	}
	defer handle.Colse()

	for {
		packet, err := handle.ReadPacketData()
		if err != nil {
			log.Println(err)
			continue
		}
		packetHandler(packet, handle)
	}
}

func packetHandler(packet []byte, handle *windivert.Handle) {
	var ipv4 layers.IPv4
	var tcp layers.TCP
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeIPv4,
		&ipv4,
		&tcp,
	)

	decoded := []gopacket.LayerType{}
	if err := parser.DecodeLayers(packet, &decoded); err != nil {
		log.Printf("Warning: Could not decode layers: %v\n", err)
	}

	var tls = tcp.Payload
	// tlsLayerFisrtHalf := tls[:1]
	// tlsLayerSecondHalf := tls[1:]

	// if tls == nil {
	// 	handle.WritePacketData(packet)
	// 	return
	// }

	// if tls[0] != byte(0x16) || tls[5] != byte(0x01) {
	// 	handle.WritePacketData(packet)
	// }

	offset, _ := extractSNI(tls)
	var tlsLayerFisrtHalf, tlsLayerSecondHalf []byte
	switch {
	// Check "www."
	case compare(tls[offset:offset+4], []byte{119, 119, 119, 46}):
		tlsLayerFisrtHalf = tls[:offset+7]
		tlsLayerSecondHalf = tls[offset+7:]
	// Check "api."
	case compare(tls[offset:offset+4], []byte{97, 112, 105, 46}):
		tlsLayerFisrtHalf = tls[:offset+7]
		tlsLayerSecondHalf = tls[offset+7:]
	default:
		tlsLayerFisrtHalf = tls[:offset+4]
		tlsLayerSecondHalf = tls[offset+4:]
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	tcp.SetNetworkLayerForChecksum(&ipv4)

	err := gopacket.SerializeLayers(buf, opts,
		&ipv4,
		&tcp,
		gopacket.Payload(tlsLayerFisrtHalf))

	if err != nil {
		log.Println("Error: ", err)
	}

	err = handle.WritePacketData(buf.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hex.Dump(tlsLayerFisrtHalf))

	tcp.Seq += uint32(len(tlsLayerFisrtHalf))
	tcp.SetNetworkLayerForChecksum(&ipv4)

	err = gopacket.SerializeLayers(buf, opts,
		&ipv4,
		&tcp,
		gopacket.Payload(tlsLayerSecondHalf))

	if err != nil {
		log.Println("Error: ", err)
	}

	err = handle.WritePacketData(buf.Bytes())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hex.Dump(tlsLayerSecondHalf))
}

func compare(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func extractSNI(handshakeBytes []byte) (int, int) {
	handshakeMessage := cryptobyte.String(handshakeBytes)
	var offset int

	// Skip TLS record layer (5 byte)
	// Skip handshake type (1 byte)
	// Skip "length" (a 24-bit integer specifying the number of bytes remaining in the message)
	// Skip TLS protocol version (2 byte)
	// Skip random (32 byte)
	if !handshakeMessage.Skip(43) {
		return 0, 0
	}
	offset += 43

	// Skip sessionID
	if length, ok := skipLengthPrefixed(&handshakeMessage, 1); ok {
		offset += length + 1
	} else {
		return 0, 0
	}

	// Skip cipherSuites
	if length, ok := skipLengthPrefixed(&handshakeMessage, 2); ok {
		offset += length + 2
	} else {
		return 0, 0
	}

	// Skip compressionMethods
	if length, ok := skipLengthPrefixed(&handshakeMessage, 1); ok {
		offset += length + 1
	} else {
		return 0, 0
	}

	// Skip extensions length
	if !handshakeMessage.Skip(2) {
		return 0, 0
	}
	offset += 2

	for {
		var extType uint16
		if !handshakeMessage.ReadUint16(&extType) {
			return 0, 0
		}
		offset += 2

		if extType != 0 {
			if length, ok := skipLengthPrefixed(&handshakeMessage, 2); ok {
				offset += length + 2
			} else {
				return 0, 0
			}
			continue
		}

		// Skip extention length (2 byte)
		// Skip server name list length (2 byte)
		if !handshakeMessage.Skip(4) {
			return 0, 0
		}
		offset += 4

		var serverNametype uint8
		if !handshakeMessage.ReadUint8(&serverNametype) {
			return 0, 0
		}
		// Check serverNameType=host_name
		if serverNametype != 0 {
			return 0, 0
		}
		offset += 1

		var length uint16
		if handshakeMessage.ReadUint16(&length) {
			offset += 2
			return offset, int(length)
		} else {
			return 0, 0
		}
	}
}

func skipLengthPrefixed(s *cryptobyte.String, n int) (int, bool) {
	var lenBytes []byte
	if !s.ReadBytes(&lenBytes, n) {
		return 0, false
	}
	var length uint32
	for _, b := range lenBytes {
		length = length << 8
		length = length | uint32(b)
	}
	if int(length) < 0 {
		// This currently cannot overflow because we read uint24 at most, but check
		// anyway in case that changes in the future.
		return 0, false
	}

	if !s.Skip(int(length)) {
		return 0, false
	}
	return int(length), true
}
