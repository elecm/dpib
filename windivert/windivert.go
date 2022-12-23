package windivert

import (
	"errors"
	"log"
	"sync"
	"syscall"
	"unsafe"
)

var (
	winDivert     = syscall.NewLazyDLL("./x64/WinDivert.dll")
	winDivertOpen = winDivert.NewProc("WinDivertOpen")
	winDivertRecv = winDivert.NewProc("WinDivertRecv")
	winDivertSend = winDivert.NewProc("WinDivertSend")
)

const (
	NetworkLayer = 0

	/* WinDivert flags */
	SniffFlag     uint64 = 0x0001
	DropFlag      uint64 = 0x0002
	RecvOnlyFlag  uint64 = 0x0004
	SendOnlyFlag  uint64 = 0x0008
	NoInstallFlag uint64 = 0x0010
	FragmentsFlag uint64 = 0x0020

	/* Settings bits */
	Sniffed     uint8 = 1 << 0 // Packet was sniffed?
	Outbound    uint8 = 1 << 1 // Packet is outound?
	Loopback    uint8 = 1 << 2 // Packet is loopback?
	Impostor    uint8 = 1 << 3 // Packet is impostor?
	IPv6        uint8 = 1 << 4 // Packet is IPv6?
	IPChecksum  uint8 = 1 << 5 // Packet has valid IPv4 checksum?
	TCPChecksum uint8 = 1 << 6 // Packet has valid TCP checksum?
	UDPChecksum uint8 = 1 << 7 // Packet has valid UDP checksum?
)

type Handle struct {
	cptr  uintptr
	mu    sync.Mutex
	IfIdx uint32

	// Since pointers to these objects are passed into a C function, if
	// they're declared locally then the Go compiler thinks they may have
	// escaped into C-land, so it allocates them on the heap.  This causes a
	// huge memory hit, so to handle that we store them here instead.
	pktAddr *WinDivertAddress
	bufptr  [1500]uint8
}

type WinDivertAddress struct {
	Timestamp int64
	Layer     uint8
	Event     uint8
	Settings  uint8
	Reserved1 uint8
	Reserved2 uint32
	IfIdx     uint32 // Packet's interface index.
	SubIfIdx  uint32 // Packet's sub-interface index.
}

func Open(filter string, interfaceIndex uint32, priority int16, flags uint64) (*Handle, error) {
	fil, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return nil, err
	}
	cptr, _, callErr := winDivertOpen.Call(uintptr(unsafe.Pointer(fil)), uintptr(NetworkLayer), uintptr(priority), uintptr(flags))
	if int(cptr) == -1 {
		return nil, callErr
	}
	log.Println("Call WinDivertOpen", callErr)
	return &Handle{cptr: cptr, IfIdx: interfaceIndex}, nil
}

func (handle *Handle) ReadPacketData() (data []byte, err error) {
	var bytesRecvLen uint
	handle.mu.Lock()
	res, _, callErr := winDivertRecv.Call(handle.cptr,
		uintptr(unsafe.Pointer(&handle.bufptr)),
		uintptr(1500),
		uintptr(unsafe.Pointer((&bytesRecvLen))),
		uintptr(unsafe.Pointer(handle.pktAddr)))
	if res == 0 {
		handle.mu.Unlock()
		return nil, callErr
	}
	data = make([]byte, bytesRecvLen)
	copy(data, handle.bufptr[:bytesRecvLen])
	handle.mu.Unlock()
	// log.Println("Call WinDivertRecv", callErr)
	return data, nil
}

func (handle *Handle) WritePacketData(data []byte) error {
	var settings uint8
	switch data[0] >> 4 {
	case 4:
		settings = 0b11100010
	case 6:
		settings = 0b11110010
	default:
		return errors.New("IP version is not valid")
	}
	pktAddr := WinDivertAddress{Layer: NetworkLayer, Settings: settings, IfIdx: handle.IfIdx}
	status, _, callErr := winDivertSend.Call(handle.cptr,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(0),
		uintptr(unsafe.Pointer(&pktAddr)))
	if status == 0 {
		return callErr
	}
	// log.Println("Call WinDivertSend", callErr)
	return nil
}

func (handle *Handle) Colse() {
	handle.mu.Lock()
	syscall.FreeLibrary(syscall.Handle(winDivert.Handle()))
	handle.mu.Unlock()
}
