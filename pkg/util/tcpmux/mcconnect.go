package tcpmux

import (
	"bytes"
	"github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/pkg/util/tcpmux/mcproto"
	"github.com/fatedier/frp/pkg/util/vhost"
	libnet "github.com/fatedier/golib/net"
	"io"
	"net"
	"time"
)

type MCConnectTCPMuxer struct {
	*vhost.Muxer
}

func NewMCConnectTCPMuxer(listener net.Listener, timeout time.Duration) (*MCConnectTCPMuxer, error) {
	ret := &MCConnectTCPMuxer{}
	mux, err := vhost.NewMuxer(listener, ret.getHostFromMCConnect, timeout)
	if err != nil {
		return nil, err
	}
	mux.SetCheckAuthFunc(ret.auth).
		SetSuccessHookFunc(ret.sendConnectResponse).
		SetFailHookFunc(mcVhostFailed)
	ret.Muxer = mux
	return ret, err
}

func mcVhostFailed(c net.Conn) {
	log.Debugf("MC Vhost failed, closing connection")
	if c != nil {
		_ = c.Close()
	}
}

func (muxer *MCConnectTCPMuxer) sendConnectResponse(_ net.Conn, _ map[string]string) error {
	return nil
}

func (muxer *MCConnectTCPMuxer) auth(_ net.Conn, _, _ string, _ map[string]string) (bool, error) {
	return true, nil
}

func (muxer *MCConnectTCPMuxer) getHostFromMCConnect(c net.Conn) (net.Conn, map[string]string, error) {
	reqInfoMap := make(map[string]string, 2)
	sc, rd := libnet.NewSharedConn(c)

	clientAddr := c.RemoteAddr()

	if _, ok := clientAddr.(*net.TCPAddr); !ok {
		log.Errorf("Remote address %v is not a TCP address, skipping filtering\n", clientAddr)
		return nil, reqInfoMap, nil
	}

	inspectionBuffer := new(bytes.Buffer)

	inspectionReader := io.TeeReader(rd, inspectionBuffer)

	packet, err := mcproto.ReadPacket(inspectionReader, clientAddr)
	if err != nil {
		log.Errorf("Failed to read packet from client %v: %v", clientAddr, err)
		return sc, reqInfoMap, err
	}

	if packet.PacketID == mcproto.PacketIdHandshake {
		handshake, err := mcproto.ReadHandshake(packet.Data)
		if err != nil {
			log.Errorf("Failed to read handshake from client %v: %v", clientAddr, err)
			return sc, reqInfoMap, err
		}
		log.Debugf("MC Handshake from client %v, server address %v", clientAddr, handshake.ServerAddress)
		reqInfoMap["Host"] = handshake.ServerAddress
		reqInfoMap["Scheme"] = "tcp"
	} else if packet.PacketID == mcproto.PacketIdLegacyServerListPing {
		handshake, ok := packet.Data.(*mcproto.LegacyServerListPing)
		if !ok {
			return nil, reqInfoMap, nil
		}
		log.Debugf("MC LegacyServerListPing from client %v, server address %v", clientAddr, handshake.ServerAddress)
		reqInfoMap["Host"] = handshake.ServerAddress
		reqInfoMap["Scheme"] = "tcp"
	} else {
		log.Errorf("Unexpected packetID, expected handshake\n")
		return sc, reqInfoMap, nil
	}

	return sc, reqInfoMap, nil
}
