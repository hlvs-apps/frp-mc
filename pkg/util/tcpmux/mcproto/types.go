package mcproto

import "fmt"

//copied from https://github.com/itzg/mc-router/blob/b09659dea62317ac70eb79bec984e21f5b9ec187/mcproto/types.go

type Frame struct {
	Length  int
	Payload []byte
}

var trimLimit = 64

func trimBytes(data []byte) ([]byte, string) {
	if len(data) < trimLimit {
		return data, ""
	} else {
		return data[:trimLimit], "..."
	}
}

func (f *Frame) String() string {
	trimmed, cont := trimBytes(f.Payload)
	return fmt.Sprintf("Frame:[len=%d, payload=%#X%s]", f.Length, trimmed, cont)
}

type Packet struct {
	Length   int
	PacketID int
	// Data is either a byte slice of raw content or a parsed message
	Data interface{}
}

func (p *Packet) String() string {
	if dataBytes, ok := p.Data.([]byte); ok {
		trimmed, cont := trimBytes(dataBytes)
		return fmt.Sprintf("Frame:[len=%d, packetId=%d, data=%#X%s]", p.Length, p.PacketID, trimmed, cont)
	} else {
		return fmt.Sprintf("Frame:[len=%d, packetId=%d, data=%+v]", p.Length, p.PacketID, p.Data)
	}
}

const (
	PacketIdHandshake            = 0x00
	PacketIdLegacyServerListPing = 0xFE
)

type Handshake struct {
	ProtocolVersion int
	ServerAddress   string
	ServerPort      uint16
	NextState       int
}

type LegacyServerListPing struct {
	ProtocolVersion int
	ServerAddress   string
	ServerPort      uint16
}

type ByteReader interface {
	ReadByte() (byte, error)
}
