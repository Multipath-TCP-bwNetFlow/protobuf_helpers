package protobuf_helpers

import (
	flow "github.com/bwNetFlow/protobuf/go"
	"math"
	"strings"
)

var (
	FlowDirectionMap = map[uint32]string{
		0: "Incoming",
		1: "Outgoing"}
	EtypeMap = map[uint32]string{
		0x0800: "IPv4",
		0x0806: "ARP",
		0x0842: "Wake-on-LAN",
		0x86DD: "IPv6",
		0x8809: "Ethernet Slow Protocols (LACP)",
		0x8847: "MPLS unicast",
		0x8848: "MPLS multicast",
		0x8863: "PPPoE Discovery Stage",
		0x8864: "PPPoE Session Stage",
		0x889A: "HyperSCSI (SCSI over Ethernet)",
		0x88A2: "ATA over Ethernet",
		0x88A4: "EtherCAT Protocol",
		0x88CC: "LLDP",
		0x88E5: "MAC Security",
		0x8906: "Fibre Channel over Ethernet (FCoE)",
		0x8914: "FCoE Initialization Protocol",
		0x9000: "Ethernet Configuration Testing Protocol"}
	ForwardingStatusMap = map[uint32]string{
		0:   "Unknown",
		64:  "Forwarded (Unknown)",
		65:  "Forwarded (Fragmented)",
		66:  "Forwarded (Not Fragmented)",
		128: "Dropped (Unknown)",
		129: "Dropped (ACL Deny)",
		130: "Dropped (ACL Drop)",
		131: "Dropped (Unroutable)",
		132: "Dropped (Adjacency)",
		133: "Dropped (Fragmented and DF set)",
		134: "Dropped (Bad Header Checksum)",
		135: "Dropped (Bad Total Length)",
		136: "Dropped (Bad Header Length)",
		137: "Dropped (Bad TTL)",
		138: "Dropped (Policer)",
		139: "Dropped (WRED)",
		140: "Dropped (RPF)",
		141: "Dropped (For Us)",
		142: "Dropped (Bad Output Interface)",
		143: "Dropped (Hardware)",
		192: "Consumed (Unknown)",
		193: "Consumed (Terminate Punt Adjacency)",
		194: "Consumed (Terminate Incomplete Adjacency)",
		195: "Consumed (Terminate For Us)"}
	IPv6ExtensionHeadersMap = map[uint32]string{
		uint32(math.Pow(2, 0)):  "Res",
		uint32(math.Pow(2, 1)):  "FRAx",
		uint32(math.Pow(2, 2)):  "RH",
		uint32(math.Pow(2, 3)):  "FRA0",
		uint32(math.Pow(2, 4)):  "UNK",
		uint32(math.Pow(2, 5)):  "Res",
		uint32(math.Pow(2, 6)):  "HOP",
		uint32(math.Pow(2, 7)):  "DST",
		uint32(math.Pow(2, 8)):  "PAY",
		uint32(math.Pow(2, 9)):  "AH",
		uint32(math.Pow(2, 10)): "ESP",
		uint32(math.Pow(2, 11)): "MOB", // Res on Cisco Routers
		uint32(math.Pow(2, 12)): "Res", uint32(math.Pow(2, 13)): "Res",
		uint32(math.Pow(2, 14)): "Res", uint32(math.Pow(2, 15)): "Res",
		uint32(math.Pow(2, 16)): "Res", uint32(math.Pow(2, 17)): "Res",
		uint32(math.Pow(2, 17)): "Res", uint32(math.Pow(2, 18)): "Res",
		uint32(math.Pow(2, 19)): "Res", uint32(math.Pow(2, 20)): "Res",
		uint32(math.Pow(2, 21)): "Res", uint32(math.Pow(2, 22)): "Res",
		uint32(math.Pow(2, 23)): "Res", uint32(math.Pow(2, 24)): "Res",
		uint32(math.Pow(2, 25)): "Res", uint32(math.Pow(2, 26)): "Res",
		uint32(math.Pow(2, 27)): "Res", uint32(math.Pow(2, 28)): "Res",
		uint32(math.Pow(2, 29)): "Res", uint32(math.Pow(2, 30)): "Res",
		uint32(math.Pow(2, 31)): "Res"}
	IPv6ExtensionHeadersLongMap = map[uint32]string{
		uint32(math.Pow(2, 0)):  "Reserved",
		uint32(math.Pow(2, 1)):  "Fragment header - not first fragment",
		uint32(math.Pow(2, 2)):  "Routing Header (any type)",
		uint32(math.Pow(2, 3)):  "Fragment header - first fragment",
		uint32(math.Pow(2, 4)):  "Unknown Layer 4 header (compressed, encrypted, not supported)",
		uint32(math.Pow(2, 5)):  "Reserved",
		uint32(math.Pow(2, 6)):  "Hop-by-Hop",
		uint32(math.Pow(2, 7)):  "Destination Options",
		uint32(math.Pow(2, 8)):  "Payload compression",
		uint32(math.Pow(2, 9)):  "Authentication Header",
		uint32(math.Pow(2, 10)): "Encapsulating Security Payload",
		uint32(math.Pow(2, 11)): "IPv6 mobility [RFC3775]", // Reserved on Cisco Routers
		uint32(math.Pow(2, 12)): "Reserved", uint32(math.Pow(2, 13)): "Reserved",
		uint32(math.Pow(2, 14)): "Reserved", uint32(math.Pow(2, 15)): "Reserved",
		uint32(math.Pow(2, 16)): "Reserved", uint32(math.Pow(2, 17)): "Reserved",
		uint32(math.Pow(2, 17)): "Reserved", uint32(math.Pow(2, 18)): "Reserved",
		uint32(math.Pow(2, 19)): "Reserved", uint32(math.Pow(2, 20)): "Reserved",
		uint32(math.Pow(2, 21)): "Reserved", uint32(math.Pow(2, 22)): "Reserved",
		uint32(math.Pow(2, 23)): "Reserved", uint32(math.Pow(2, 24)): "Reserved",
		uint32(math.Pow(2, 25)): "Reserved", uint32(math.Pow(2, 26)): "Reserved",
		uint32(math.Pow(2, 27)): "Reserved", uint32(math.Pow(2, 28)): "Reserved",
		uint32(math.Pow(2, 29)): "Reserved", uint32(math.Pow(2, 30)): "Reserved",
		uint32(math.Pow(2, 31)): "Reserved"}
)

type FlowHelper struct {
	*flow.FlowMessage
}

func NewFlowHelper(flow *flow.FlowMessage) FlowHelper {
	return FlowHelper{flow}
}

func (flow *FlowHelper) FlowDirectionString() string {
	return FlowDirectionMap[flow.GetFlowDirection()]
}

func (flow *FlowHelper) IsIncoming() bool {
	return flow.GetFlowDirection() == 0
}

func (flow *FlowHelper) IsOutgoing() bool {
	return flow.GetFlowDirection() == 1
}

func (flow *FlowHelper) Peer() string {
	switch flow.GetFlowDirection() {
	case 0:
		return flow.GetSrcIfDesc()
	case 1:
		return flow.GetDstIfDesc()
	default:
		return ""
	}
}

func (flow *FlowHelper) EtypeString() string {
	return EtypeMap[flow.GetEtype()]
}

func (flow *FlowHelper) IPVersion() uint8 {
	switch flow.GetEtype() {
	case 0x0800:
		return 4
	case 0x86dd:
		return 6
	default:
		return 0
	}
}

func (flow *FlowHelper) IPVersionString() string {
	if flow.GetEtype() == 0x800 || flow.GetEtype() == 0x86dd {
		return EtypeMap[flow.GetEtype()]
	} else {
		return ""
	}
}

func (flow *FlowHelper) IsIPv4() bool {
	return flow.GetEtype() == 0x0800
}

func (flow *FlowHelper) IsIPv6() bool {
	return flow.GetEtype() == 0x86dd
}

func (flow *FlowHelper) ForwardingStatusString() string {
	return ForwardingStatusMap[flow.GetForwardingStatus()]
}

func (flow *FlowHelper) IsConsumed() bool {
	return 192 <= flow.GetForwardingStatus() // && < 256
}

func (flow *FlowHelper) IsDropped() bool {
	return 128 <= flow.GetForwardingStatus() && flow.GetForwardingStatus() < 192
}

func (flow *FlowHelper) IsForwarded() bool {
	return 64 <= flow.GetForwardingStatus() && flow.GetForwardingStatus() < 128
}

func (flow *FlowHelper) IsUnknownForwardingStatus() bool {
	return flow.GetForwardingStatus() < 64
}

func (flow *FlowHelper) IPv6ExtensionHeadersString() string {
	var flagnames []string
	for val, name := range IPv6ExtensionHeadersMap {
		if flow.IPv6ExtensionHeaders&val == 1 {
			flagnames = append(flagnames, name)
		}
	}
	return strings.Join(flagnames, " - ")
}

func (flow *FlowHelper) IPv6ExtensionHeadersLongString() string {
	var flagnames []string
	for val, name := range IPv6ExtensionHeadersLongMap {
		if flow.IPv6ExtensionHeaders&val == 1 {
			flagnames = append(flagnames, name)
		}
	}
	return strings.Join(flagnames, ", ")
}
