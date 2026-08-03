// Copyright 2021 Thorben Krüger (thorben.krueger@ovgu.de)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package rpc

import (
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
)

// The gob serializable structs are necessary to replace the protocol.* types
type SerializableTransportParameters struct {
	InitialMaxStreamDataBidiLocal   uint64
	InitialMaxStreamDataBidiRemote  uint64
	InitialMaxStreamDataUni         uint64
	InitialMaxData                  uint64
	MaxAckDelay                     time.Duration
	AckDelayExponent                uint8
	DisableActiveMigration          bool
	MaxUDPPayloadSize               uint64
	MaxUniStreamNum                 uint64
	MaxBidiStreamNum                uint64
	MaxIdleTimeout                  time.Duration
	PreferredAddress                string
	OriginalDestinationConnectionID []byte
	InitialSourceConnectionID       []byte
	RetrySourceConnectionID         []byte
	StatelessResetToken             []byte
	ActiveConnectionIDLimit         uint64
	MaxDatagramFrameSize            uint64
}

func toSerializableTP(p *logging.TransportParameters) *SerializableTransportParameters {
	if p == nil {
		return nil
	}
	s := &SerializableTransportParameters{
		InitialMaxStreamDataBidiLocal:  uint64(p.InitialMaxStreamDataBidiLocal),
		InitialMaxStreamDataBidiRemote: uint64(p.InitialMaxStreamDataBidiRemote),
		InitialMaxStreamDataUni:        uint64(p.InitialMaxStreamDataUni),
		InitialMaxData:                 uint64(p.InitialMaxData),
		MaxAckDelay:                    p.MaxAckDelay,
		AckDelayExponent:               p.AckDelayExponent,
		DisableActiveMigration:         p.DisableActiveMigration,
		MaxUDPPayloadSize:              uint64(p.MaxUDPPayloadSize),
		MaxUniStreamNum:                uint64(p.MaxUniStreamNum),
		MaxBidiStreamNum:               uint64(p.MaxBidiStreamNum),
		MaxIdleTimeout:                 p.MaxIdleTimeout,
		ActiveConnectionIDLimit:        p.ActiveConnectionIDLimit,
		MaxDatagramFrameSize:           uint64(p.MaxDatagramFrameSize),
		// StatelessResetToken:            append([]byte(nil), p.StatelessResetToken...),
	}

	if p.StatelessResetToken != nil {
		s.StatelessResetToken = append([]byte(nil), p.StatelessResetToken[:]...)
	}
	s.OriginalDestinationConnectionID = p.OriginalDestinationConnectionID.Bytes()
	s.InitialSourceConnectionID = p.InitialSourceConnectionID.Bytes()

	if p.RetrySourceConnectionID != nil {
		s.RetrySourceConnectionID = p.RetrySourceConnectionID.Bytes()
	}

	if p.PreferredAddress != nil {
		s.PreferredAddress = fmt.Sprintf("IPv4:%s,IPv6:%s,ConnID:%s,Token:%x",
			p.PreferredAddress.IPv4, p.PreferredAddress.IPv6,
			p.PreferredAddress.ConnectionID, p.PreferredAddress.StatelessResetToken)
	}
	return s
}

func fromSerializableTP(s *SerializableTransportParameters) *logging.TransportParameters {
	if s == nil {
		return nil
	}
	p := &logging.TransportParameters{
		InitialMaxStreamDataBidiLocal:  logging.ByteCount(s.InitialMaxStreamDataBidiLocal),
		InitialMaxStreamDataBidiRemote: logging.ByteCount(s.InitialMaxStreamDataBidiRemote),
		InitialMaxStreamDataUni:        logging.ByteCount(s.InitialMaxStreamDataUni),
		InitialMaxData:                 logging.ByteCount(s.InitialMaxData),
		MaxAckDelay:                    s.MaxAckDelay,
		AckDelayExponent:               s.AckDelayExponent,
		DisableActiveMigration:         s.DisableActiveMigration,
		MaxUDPPayloadSize:             	logging.ByteCount(s.MaxUDPPayloadSize),
		MaxUniStreamNum: 				logging.StreamNum(s.MaxUniStreamNum),
		MaxBidiStreamNum:              	logging.StreamNum(s.MaxBidiStreamNum),
		MaxIdleTimeout:                 s.MaxIdleTimeout,
		ActiveConnectionIDLimit:        s.ActiveConnectionIDLimit,
		MaxDatagramFrameSize:           logging.ByteCount(s.MaxDatagramFrameSize),
		// StatelessResetToken:            append([]byte(nil), s.StatelessResetToken...),
	}

	if len(s.OriginalDestinationConnectionID) > 0 {
		id := bytesToConnID(s.OriginalDestinationConnectionID)
		p.OriginalDestinationConnectionID = id
	}
	if len(s.InitialSourceConnectionID) > 0 {
		id := bytesToConnID(s.InitialSourceConnectionID)
		p.InitialSourceConnectionID = id
	}
	if len(s.RetrySourceConnectionID) > 0 {
		id := bytesToConnID(s.RetrySourceConnectionID)
		p.RetrySourceConnectionID = &id
	}
	return p
}

type SerializableHeader struct {
	Type             uint8
	Version          logging.Version
	SrcConnectionID  []byte
	DestConnectionID []byte
	Length           logging.ByteCount
	Token            []byte
}

func toSerializableHeader(h *logging.Header) *SerializableHeader {
	if h == nil {
		return nil
	}
	return &SerializableHeader{
		Type:             uint8(h.Type),
		Version:          h.Version,
		SrcConnectionID:  h.SrcConnectionID.Bytes(),
		DestConnectionID: h.DestConnectionID.Bytes(),
		Length:           h.Length,
		Token:            append([]byte(nil), h.Token...),
	}
}

func fromSerializableHeader(s *SerializableHeader) *logging.Header {
	if s == nil {
		return nil
	}

	return &logging.Header{
		Version:          s.Version,
		SrcConnectionID:  bytesToConnID(s.SrcConnectionID),
		DestConnectionID: bytesToConnID(s.DestConnectionID),
		Length:           s.Length,
		Token:            append([]byte(nil), s.Token...),
	}
}

type SerializableExtendedHeader struct {
	Type             uint8
	Version          logging.Version
	SrcConnectionID  []byte
	DestConnectionID []byte
	Length           logging.ByteCount
	Token            []byte
	PacketNumber     logging.PacketNumber
	PacketNumberLen  uint8
	KeyPhase         logging.KeyPhaseBit
}

func toSerializableExtendedHeader(h *logging.ExtendedHeader) *SerializableExtendedHeader {
	if h == nil {
		return nil
	}
	return &SerializableExtendedHeader{
		Type:             uint8(h.Type),
		Version:          h.Version,
		SrcConnectionID:  h.SrcConnectionID.Bytes(),
		DestConnectionID: h.DestConnectionID.Bytes(),
		Length:           h.Length,
		Token:            append([]byte(nil), h.Token...),
		PacketNumber:     h.PacketNumber,
		PacketNumberLen:  uint8(h.PacketNumberLen),
		KeyPhase:         h.KeyPhase,
	}
}

func fromSerializableExtendedHeader(s *SerializableExtendedHeader) *logging.ExtendedHeader {
	if s == nil {
		return nil
	}
	h:= &logging.ExtendedHeader{
		Header: logging.Header{
			Version:          s.Version,
			SrcConnectionID:  bytesToConnID(s.SrcConnectionID),
			DestConnectionID: bytesToConnID(s.DestConnectionID),
			Length:           s.Length,
			Token:            append([]byte(nil), s.Token...),
		},
		PacketNumber:    s.PacketNumber,
		KeyPhase:        s.KeyPhase,
	}
	return h
}

type ServerConnectionTracer interface {
	TracerForConnection(id uint64, p logging.Perspective, odcid logging.ConnectionID) error
	StartedConnection(local, remote *pan.UDPAddr, srcConnID, destConnID logging.ConnectionID) error
	NegotiatedVersion(local, remote *pan.UDPAddr, chosen logging.Version, clientVersions, serverVersions []logging.Version) error
	ClosedConnection(local, remote *pan.UDPAddr, err error) error
	SentTransportParameters(*pan.UDPAddr, *pan.UDPAddr, *logging.TransportParameters) error
	ReceivedTransportParameters(*pan.UDPAddr, *pan.UDPAddr, *logging.TransportParameters) error
	RestoredTransportParameters(local, remote *pan.UDPAddr, parameters *logging.TransportParameters) error
	SentPacket(local, remote *pan.UDPAddr, hdr *logging.ExtendedHeader, size logging.ByteCount, ack *logging.AckFrame, frames []logging.Frame) error
	ReceivedVersionNegotiationPacket(*pan.UDPAddr, *pan.UDPAddr, *logging.Header, []logging.Version) error
	ReceivedRetry(*pan.UDPAddr, *pan.UDPAddr, *logging.Header) error
	ReceivedPacket(local, remote *pan.UDPAddr, hdr *logging.ExtendedHeader, size logging.ByteCount, frames []logging.Frame) error
	BufferedPacket(*pan.UDPAddr, *pan.UDPAddr, logging.PacketType) error
	DroppedPacket(*pan.UDPAddr, *pan.UDPAddr, logging.PacketType, logging.ByteCount, logging.PacketDropReason) error
	UpdatedMetrics(local, remote *pan.UDPAddr, rttStats *RTTStats, cwnd, bytesInFlight logging.ByteCount, packetsInFlight int) error
	AcknowledgedPacket(*pan.UDPAddr, *pan.UDPAddr, logging.EncryptionLevel, logging.PacketNumber) error
	LostPacket(*pan.UDPAddr, *pan.UDPAddr, logging.EncryptionLevel, logging.PacketNumber, logging.PacketLossReason) error
	UpdatedCongestionState(*pan.UDPAddr, *pan.UDPAddr, logging.CongestionState) error
	UpdatedPTOCount(local, remote *pan.UDPAddr, value uint32) error
	UpdatedKeyFromTLS(*pan.UDPAddr, *pan.UDPAddr, logging.EncryptionLevel, logging.Perspective) error
	UpdatedKey(local, remote *pan.UDPAddr, generation logging.KeyPhase, rem bool) error
	DroppedEncryptionLevel(*pan.UDPAddr, *pan.UDPAddr, logging.EncryptionLevel) error
	DroppedKey(local, remote *pan.UDPAddr, generation logging.KeyPhase) error
	SetLossTimer(*pan.UDPAddr, *pan.UDPAddr, logging.TimerType, logging.EncryptionLevel, time.Time) error
	LossTimerExpired(*pan.UDPAddr, *pan.UDPAddr, logging.TimerType, logging.EncryptionLevel) error
	LossTimerCanceled(local, remote *pan.UDPAddr) error
	Close(local, remote *pan.UDPAddr) error
	Debug(local, remote *pan.UDPAddr, name, msg string) error
}

type RTTStats struct {
	LatestRTT, MaxAckDelay, MeanDeviation, MinRTT, PTO, SmoothedRTT time.Duration
}

func NewRTTStats(stats *logging.RTTStats) *RTTStats {
	return &RTTStats{
		LatestRTT:     stats.LatestRTT(),
		MaxAckDelay:   stats.MaxAckDelay(),
		MeanDeviation: stats.MeanDeviation(),
		MinRTT:        stats.MinRTT(),
		PTO:           stats.PTO(false),
		SmoothedRTT:   stats.SmoothedRTT(),
	}
}

type ConnectionTracerMsg struct {
	Local, Remote                            *pan.UDPAddr
	OdcID, SrcConnID, DestConnID             []byte
	Chosen                                   logging.Version
	Versions, ClientVersions, ServerVersions []logging.Version
	ErrorMsg, Key, Value                     *string
	Parameters                               *SerializableTransportParameters
	ByteCount, Cwnd                          logging.ByteCount
	Packets, ID                              int
	Header                                   *SerializableHeader
	ExtendedHeader                           *SerializableExtendedHeader
	Frames                                   []logging.Frame
	AckFrame                                 *logging.AckFrame
	PacketType                               logging.PacketType
	DropReason                               logging.PacketDropReason
	LossReason                               logging.PacketLossReason
	EncryptionLevel                          logging.EncryptionLevel
	PacketNumber                             logging.PacketNumber
	CongestionState                          logging.CongestionState
	PTOCount                                 uint32
	TracingID                                uint64
	Perspective                              logging.Perspective
	Bool                                     bool
	Generation                               logging.KeyPhase
	TimerType                                logging.TimerType
	Time                                     *time.Time
	RTTStats                                 *RTTStats
}

func non_nil_string(name string, i interface{}) string {
	if i != nil {
		return fmt.Sprintf("%s: %+v\n", name, i)
	}
	return ""
}

func (m *ConnectionTracerMsg) String() string {
	s := ""
	s += non_nil_string("OdcID", m.OdcID)
	s += non_nil_string("Perspective", m.Perspective)
	s += non_nil_string("ID", m.ID)
	s += non_nil_string("TracingID", m.TracingID)
	s += non_nil_string("Local", m.Local)
	s += non_nil_string("Remote", m.Remote)
	s += non_nil_string("Chosen", m.Chosen)
	s += non_nil_string("Versions", m.Versions)
	s += non_nil_string("ClientVersions", m.ClientVersions)
	s += non_nil_string("ServerVersions", m.ServerVersions)
	s += non_nil_string("ErrorMsg", m.ErrorMsg)
	s += non_nil_string("Parameters", m.Parameters)
	s += non_nil_string("ByteCount", m.ByteCount)
	s += non_nil_string("Cwnd", m.Cwnd)
	s += non_nil_string("Packets", m.Packets)
	s += non_nil_string("Header", m.Header)
	s += non_nil_string("ExtendedHeader", m.ExtendedHeader)
	s += non_nil_string("Frames", m.Frames)
	s += non_nil_string("AckFrame", m.AckFrame)
	s += non_nil_string("PacketType", m.PacketType)
	s += non_nil_string("DropReason", m.DropReason)
	s += non_nil_string("TimerType", m.TimerType)
	s += non_nil_string("CongestionState", m.CongestionState)
	return s
}

type ConnectionTracerClient struct {
	rpc           *Client
	l             *log.Logger
	p             logging.Perspective
	odcid         logging.ConnectionID
	tracing_id    uint64
	local, remote *pan.UDPAddr
}

func (c *ConnectionTracerClient) new_msg() *ConnectionTracerMsg {
	return &ConnectionTracerMsg{
		Perspective: c.p,
		OdcID:       connIDToBytes(c.odcid),
		ID:          c.rpc.id,
		TracingID:   c.tracing_id,
		Local:       c.local,
		Remote:      c.remote,
	}
}

func NewConnectionTracerClient(client *Client, id uint64, p logging.Perspective, odcid logging.ConnectionID) logging.ConnectionTracer {
	// client.l.Printf("NewConnectionTracerClient %v", odcid)
	err := client.Call("ConnectionTracerServer.NewTracerForConnection",
		&ConnectionTracerMsg{
			Perspective: p,
			OdcID:       connIDToBytes(odcid),
			ID:          client.id,
			TracingID:   id,
		},
		&NilMsg{},
	)
	if err != nil {
		client.l.Fatalln(err)
	}

	c := &ConnectionTracerClient{client, client.l, p, odcid, id, nil, nil}
	return logging.ConnectionTracer{
		StartedConnection:                c.StartedConnection,
		NegotiatedVersion:                c.NegotiatedVersion,
		ClosedConnection:                 c.ClosedConnection,
		SentTransportParameters:          c.SentTransportParameters,
		ReceivedTransportParameters:      c.ReceivedTransportParameters,
		RestoredTransportParameters:      c.RestoredTransportParameters,
		SentLongHeaderPacket:             c.SentLongHeaderPacket,
		SentShortHeaderPacket:            nil,
		ReceivedVersionNegotiationPacket: c.ReceivedVersionNegotiationPacket,
		ReceivedRetry:                    c.ReceivedRetry,
		ReceivedLongHeaderPacket:         c.ReceivedLongHeaderPacket,
		ReceivedShortHeaderPacket:        nil,
		BufferedPacket:                   c.BufferedPacket,
		DroppedPacket:                    c.DroppedPacket,
		UpdatedMetrics:                   c.UpdatedMetrics,
		AcknowledgedPacket:               c.AcknowledgedPacket,
		LostPacket:                       c.LostPacket,
		UpdatedMTU:                       nil,
		UpdatedCongestionState:           c.UpdatedCongestionState,
		UpdatedPTOCount:                  c.UpdatedPTOCount,
		UpdatedKeyFromTLS:                c.UpdatedKeyFromTLS,
		UpdatedKey:                       c.UpdatedKey,
		DroppedEncryptionLevel:           c.DroppedEncryptionLevel,
		DroppedKey:                       c.DroppedKey,
		SetLossTimer:                     c.SetLossTimer,
		LossTimerExpired:                 c.LossTimerExpired,
		LossTimerCanceled:                c.LossTimerCanceled,
		ECNStateUpdated:                  nil,
		ChoseALPN:                        nil,
		Close:                            c.Close,
		Debug:                            c.Debug,
	}
}

func (c *ConnectionTracerClient) StartedConnection(local, remote net.Addr, srcConnID, destConnID logging.ConnectionID) {
	//c.l.Printf("StartedConnection")
	msg := c.new_msg()
	l, ok := local.(pan.UDPAddr)
	if !ok {
		c.l.Printf("unexpected local type %T", local)
		return
	}
	r := remote.(pan.UDPAddr)
	c.local = &l
	c.remote = &r

	msg.Local = &l
	msg.Remote = &r
	msg.SrcConnID = connIDToBytes(srcConnID)
	msg.DestConnID = connIDToBytes(destConnID)

	err := c.rpc.Call("ConnectionTracerServer.StartedConnection",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) NegotiatedVersion(chosen logging.Version, clientVersions, serverVersions []logging.Version) {
	//c.l.Printf("NegotiatedVersion")
	msg := c.new_msg()
	msg.Chosen = chosen
	msg.ClientVersions = clientVersions
	msg.ServerVersions = serverVersions

	err := c.rpc.Call("ConnectionTracerServer.NegotiatedVersion",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) ClosedConnection(e error) {
	//c.l.Printf("ClosedConnection")
	s := e.Error()
	msg := c.new_msg()
	msg.ErrorMsg = &s
	err := c.rpc.Call("ConnectionTracerServer.ClosedConnection",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) SentTransportParameters(parameters *logging.TransportParameters) {
	//c.l.Printf("SentTransportParameters")
	msg := c.new_msg()
	msg.Parameters = toSerializableTP(parameters)
	err := c.rpc.Call("ConnectionTracerServer.SentTransportParameters",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) ReceivedTransportParameters(parameters *logging.TransportParameters) {
	//c.l.Printf("ReceivedTransportParameters")
	msg := c.new_msg()
	msg.Parameters = toSerializableTP(parameters)
	err := c.rpc.Call("ConnectionTracerServer.ReceivedTransportParameters",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) RestoredTransportParameters(parameters *logging.TransportParameters) {
	//c.l.Printf("RestoredTransportParameters")
	msg := c.new_msg()
	msg.Parameters = toSerializableTP(parameters)
	err := c.rpc.Call("ConnectionTracerServer.RestoredTransportParameters",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) SentLongHeaderPacket(hdr *logging.ExtendedHeader, size logging.ByteCount, ecn logging.ECN, ack *logging.AckFrame, frames []logging.Frame) {
	//c.l.Printf("SentPacket")
	msg := c.new_msg()
	msg.ExtendedHeader = toSerializableExtendedHeader(hdr)
	msg.ByteCount = size
	msg.AckFrame = ack
	//msg.Frames = frames
	err := c.rpc.Call("ConnectionTracerServer.SentPacket",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) ReceivedVersionNegotiationPacket(dest, src logging.ArbitraryLenConnectionID, versions []logging.Version) {
	//c.l.Printf("ReceivedVersionNegotiationPacket")
	msg := c.new_msg()
	msg.Versions = versions

	err := c.rpc.Call("ConnectionTracerServer.ReceivedVersionNegotiationPacket",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) ReceivedRetry(hdr *logging.Header) {
	//c.l.Printf("ReceivedRetry")
	msg := c.new_msg()
	msg.Header = toSerializableHeader(hdr)
	err := c.rpc.Call("ConnectionTracerServer.ReceivedRetry",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) ReceivedLongHeaderPacket(hdr *logging.ExtendedHeader, size logging.ByteCount, ecn logging.ECN, frames []logging.Frame) {
	//c.l.Printf("ReceivedPacket")
	msg := c.new_msg()
	msg.ExtendedHeader = toSerializableExtendedHeader(hdr)
	msg.ByteCount = size
	//msg.Frames = frames
	err := c.rpc.Call("ConnectionTracerServer.ReceivedPacket",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) BufferedPacket(ptype logging.PacketType, size logging.ByteCount) {
	//c.l.Printf("BufferedPacket")
	msg := c.new_msg()
	msg.PacketType = ptype
	err := c.rpc.Call("ConnectionTracerServer.BufferedPacket",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) DroppedPacket(ptype logging.PacketType, pn logging.PacketNumber, size logging.ByteCount, reason logging.PacketDropReason) {
	//c.l.Printf("DroppedPacket")
	msg := c.new_msg()
	msg.PacketType = ptype
	msg.ByteCount = size
	msg.DropReason = reason
	err := c.rpc.Call("ConnectionTracerServer.DroppedPacket",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) UpdatedMetrics(rttStats *logging.RTTStats, cwnd, bytesInFlight logging.ByteCount, packetsInFlight int) {
	//c.l.Printf("UpdatedMetrics")
	msg := c.new_msg()
	msg.Cwnd = cwnd
	msg.ByteCount = bytesInFlight
	msg.Packets = packetsInFlight
	msg.RTTStats = NewRTTStats(rttStats)
	err := c.rpc.Call("ConnectionTracerServer.UpdatedMetrics",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) AcknowledgedPacket(level logging.EncryptionLevel, pnum logging.PacketNumber) {
	//c.l.Printf("AcknowledgedPacket")
	msg := c.new_msg()
	msg.EncryptionLevel = level
	msg.PacketNumber = pnum
	err := c.rpc.Call("ConnectionTracerServer.AcknowledgedPacket",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) LostPacket(level logging.EncryptionLevel, pnum logging.PacketNumber, reason logging.PacketLossReason) {
	//c.l.Printf("LostPacket")
	msg := c.new_msg()
	msg.EncryptionLevel = level
	msg.PacketNumber = pnum
	msg.LossReason = reason
	err := c.rpc.Call("ConnectionTracerServer.LostPacket",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) UpdatedCongestionState(state logging.CongestionState) {
	msg := c.new_msg()
	msg.CongestionState = state
	//c.l.Printf("UpdatedCongestionState")
	err := c.rpc.Call("ConnectionTracerServer.UpdatedCongestionState",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) UpdatedPTOCount(value uint32) {
	//c.l.Printf("UpdatedPTOCount")
	msg := c.new_msg()
	msg.PTOCount = value
	err := c.rpc.Call("ConnectionTracerServer.UpdatedPTOCount",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) UpdatedKeyFromTLS(level logging.EncryptionLevel, p logging.Perspective) {
	//c.l.Printf("UpdatedKeyFromTLS")
	msg := c.new_msg()
	msg.EncryptionLevel = level
	msg.Perspective = p
	err := c.rpc.Call("ConnectionTracerServer.UpdatedKeyFromTLS",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) UpdatedKey(generation logging.KeyPhase, remote bool) {
	//c.l.Printf("UpdatedKey")
	msg := c.new_msg()
	msg.Generation = generation
	msg.Bool = remote
	err := c.rpc.Call("ConnectionTracerServer.UpdatedKey",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) DroppedEncryptionLevel(level logging.EncryptionLevel) {
	//c.l.Printf("DroppedEncryptionLevel")
	msg := c.new_msg()
	msg.EncryptionLevel = level
	err := c.rpc.Call("ConnectionTracerServer.DroppedEncryptionLevel",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) DroppedKey(generation logging.KeyPhase) {
	//c.l.Printf("DroppedKey")
	msg := c.new_msg()
	msg.Generation = generation
	err := c.rpc.Call("ConnectionTracerServer.DroppedKey",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) SetLossTimer(ttype logging.TimerType, level logging.EncryptionLevel, t time.Time) {
	//c.l.Printf("SetLossTimer")
	msg := c.new_msg()
	msg.TimerType = ttype
	msg.EncryptionLevel = level
	msg.Time = &t
	err := c.rpc.Call("ConnectionTracerServer.SetLossTimer",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) LossTimerExpired(ttype logging.TimerType, level logging.EncryptionLevel) {
	//c.l.Printf("LossTimerExpired")
	msg := c.new_msg()
	msg.TimerType = ttype
	msg.EncryptionLevel = level
	err := c.rpc.Call("ConnectionTracerServer.LossTimerExpired",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) LossTimerCanceled() {
	//c.l.Printf("LossTimerCanceled")
	msg := c.new_msg()
	err := c.rpc.Call("ConnectionTracerServer.LossTimerCanceled",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) Close() {
	//c.l.Printf("Close")
	msg := c.new_msg()
	err := c.rpc.Call("ConnectionTracerServer.Close",
		msg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}
func (c *ConnectionTracerClient) Debug(name, msg string) {
	//c.l.Printf("Debug")
	mesg := c.new_msg()
	mesg.Key = &name
	mesg.Value = &msg
	err := c.rpc.Call("ConnectionTracerServer.Debug",
		mesg,
		&NilMsg{},
	)
	if err != nil {
		c.l.Fatalln(err)
	}
}

type NilMsg struct{}

type ConnectionTracerServer struct {
	l  *log.Logger
	ct ServerConnectionTracer
}

func NewConnectionTracerServer(ct ServerConnectionTracer) *ConnectionTracerServer {
	return &ConnectionTracerServer{log.Default(), ct}
}

func (c *ConnectionTracerServer) NewTracerForConnection(args *ConnectionTracerMsg, resp *NilMsg) error {
	if args.OdcID == nil {
		return ErrDeref
	}
	tracing_id := args.TracingID
	return c.ct.TracerForConnection(tracing_id, args.Perspective, bytesToConnID(args.OdcID))

}

func (c *ConnectionTracerServer) StartedConnection(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Printf("StartedConnection called: %+v", args)
	if args.Local == nil || args.Remote == nil {
		return ErrDeref
	}
	return c.ct.StartedConnection(args.Local, args.Remote, bytesToConnID(args.SrcConnID), bytesToConnID(args.DestConnID))
}

func (c *ConnectionTracerServer) NegotiatedVersion(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("NegotiatedVersion called")
	return c.ct.NegotiatedVersion(args.Local, args.Remote, args.Chosen, args.ClientVersions, args.ServerVersions)
}

func (c *ConnectionTracerServer) ClosedConnection(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("ClosedConnection called")
	if args.ErrorMsg == nil {
		return c.ct.ClosedConnection(args.Local, args.Remote, nil)
	} else {
		return c.ct.ClosedConnection(args.Local, args.Remote, errors.New(*args.ErrorMsg))
	}
}

func (c *ConnectionTracerServer) SentTransportParameters(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("SentTransportParameters called")
	return c.ct.SentTransportParameters(args.Local, args.Remote, fromSerializableTP(args.Parameters))
}

func (c *ConnectionTracerServer) ReceivedTransportParameters(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("ReceivedTransportParameters called")
	return c.ct.ReceivedTransportParameters(args.Local, args.Remote, fromSerializableTP(args.Parameters))
}

func (c *ConnectionTracerServer) RestoredTransportParameters(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("RestoredTransportParameters called")
	return c.ct.RestoredTransportParameters(args.Local, args.Remote, fromSerializableTP(args.Parameters))
}

func (c *ConnectionTracerServer) SentPacket(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("SentPacket called")
	return c.ct.SentPacket(args.Local, args.Remote, fromSerializableExtendedHeader(args.ExtendedHeader), args.ByteCount, args.AckFrame, nil)
}

func (c *ConnectionTracerServer) ReceivedVersionNegotiationPacket(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("ReceivedVersionNegotiationPacket called")
	return c.ct.ReceivedVersionNegotiationPacket(args.Local, args.Remote, fromSerializableHeader(args.Header), args.Versions)
}

func (c *ConnectionTracerServer) ReceivedRetry(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("ReceivedRetry called")
	return c.ct.ReceivedRetry(args.Local, args.Remote, fromSerializableHeader(args.Header))
}

func (c *ConnectionTracerServer) ReceivedPacket(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("ReceivedPacket called")
	return c.ct.ReceivedPacket(args.Local, args.Remote, fromSerializableExtendedHeader(args.ExtendedHeader), args.ByteCount, nil)
}

func (c *ConnectionTracerServer) BufferedPacket(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("BufferedPacket called")
	return c.ct.BufferedPacket(args.Local, args.Remote, args.PacketType)
}

func (c *ConnectionTracerServer) DroppedPacket(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("DroppedPacket called")
	return c.ct.DroppedPacket(args.Local, args.Remote, args.PacketType, args.ByteCount, args.DropReason)
}

func (c *ConnectionTracerServer) UpdatedMetrics(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("UpdatedMetrics called")
	return c.ct.UpdatedMetrics(args.Local, args.Remote, args.RTTStats, args.Cwnd, args.ByteCount, args.Packets)
}

func (c *ConnectionTracerServer) AcknowledgedPacket(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("AcknowledgedPacket called")
	return c.ct.AcknowledgedPacket(args.Local, args.Remote, args.EncryptionLevel, args.PacketNumber)
}

func (c *ConnectionTracerServer) LostPacket(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("LostPacket called")
	return c.ct.LostPacket(args.Local, args.Remote, args.EncryptionLevel, args.PacketNumber, args.LossReason)
}

func (c *ConnectionTracerServer) UpdatedCongestionState(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Printf("UpdatedCongestionState called")
	return c.ct.UpdatedCongestionState(args.Local, args.Remote, args.CongestionState)
}

func (c *ConnectionTracerServer) UpdatedPTOCount(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("UpdatedPTOCount called")
	return c.ct.UpdatedPTOCount(args.Local, args.Remote, args.PTOCount)
}

func (c *ConnectionTracerServer) UpdatedKeyFromTLS(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("UpdatedKeyFromTLS called")
	return c.ct.UpdatedKeyFromTLS(args.Local, args.Remote, args.EncryptionLevel, args.Perspective)
}

func (c *ConnectionTracerServer) UpdatedKey(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("UpdatedKey called")
	return c.ct.UpdatedKey(args.Local, args.Remote, args.Generation, args.Bool)
}

func (c *ConnectionTracerServer) DroppedEncryptionLevel(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("DroppedEncryptionLevel called")
	return c.ct.DroppedEncryptionLevel(args.Local, args.Remote, args.EncryptionLevel)
}

func (c *ConnectionTracerServer) DroppedKey(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("DroppedKey called")
	return c.ct.DroppedKey(args.Local, args.Remote, args.Generation)
}

func (c *ConnectionTracerServer) SetLossTimer(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("SetLossTimer called")
	if args.Time == nil {
		return ErrDeref
	}
	return c.ct.SetLossTimer(args.Local, args.Remote, args.TimerType, args.EncryptionLevel, *args.Time)
}

func (c *ConnectionTracerServer) LossTimerExpired(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("LossTimerExpired called")
	return c.ct.LossTimerExpired(args.Local, args.Remote, args.TimerType, args.EncryptionLevel)
}

func (c *ConnectionTracerServer) LossTimerCanceled(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("LossTimerCanceled called")
	return c.ct.LossTimerCanceled(args.Local, args.Remote)
}

func (c *ConnectionTracerServer) Close(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("Close called")
	return c.ct.Close(args.Local, args.Remote)
}

func (c *ConnectionTracerServer) Debug(args *ConnectionTracerMsg, resp *NilMsg) error {
	//c.l.Println("Debug called")
	if args.Key == nil || args.Value == nil {
		return ErrDeref
	}
	return c.ct.Debug(args.Local, args.Remote, *args.Key, *args.Value)
}

func connIDToBytes(id logging.ConnectionID) []byte {
    b := id.Bytes()
    if b == nil {
        return []byte{}
    }
    return b
}

func bytesToConnID(b []byte) logging.ConnectionID {
	return quic.ConnectionIDFromBytes(b)
}
