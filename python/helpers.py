#!/usr/bin/env python3
import flow_messages_enriched_pb2 as api # this needs to be in the local path

flow_direction = {
        0: "Incoming",
        1: "Outgoing"
        }
etype = {
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
        0x9000: "Ethernet Configuration Testing Protocol"
        }
forwarding_status = {
        0 : 'Unknown',
        64 : 'Forwarded (Unknown)',
        65 : 'Forwarded (Fragmented)',
        66 : 'Forwarded (Not Fragmented)',
        128 : 'Dropped (Unknown)',
        129 : 'Dropped (ACL Deny)',
        130 : 'Dropped (ACL Drop)',
        131 : 'Dropped (Unroutable)',
        132 : 'Dropped (Adjacency)',
        133 : 'Dropped (Fragmented and DF set)',
        134 : 'Dropped (Bad Header Checksum)',
        135 : 'Dropped (Bad Total Length)',
        136 : 'Dropped (Bad Header Length)',
        137 : 'Dropped (Bad TTL)',
        138 : 'Dropped (Policer)',
        139 : 'Dropped (WRED)',
        140 : 'Dropped (RPF)',
        141 : 'Dropped (For Us)',
        142 : 'Dropped (Bad Output Interface)',
        143 : 'Dropped (Hardware)',
        192 : 'Consumed (Unknown)',
        193 : 'Consumed (Terminate Punt Adjacency)',
        194 : 'Consumed (Terminate Incomplete Adjacency)',
        195 : 'Consumed (Terminate For Us)'
        }
ipv6_extension_headers = {
        2**0:  "DST",
        2**1:  "HOP",
        2**2:  "Res",
        2**3:  "UNK",
        2**4:  "FRA0",
        2**5:  "RH",
        2**6:  "FRA1",
        2**7:  "Res", 2**8:  "Res", 2**9:  "Res", 2**10: "Res", 2**11: "Res",
        2**12: "MOB",
        2**13: "ESP",
        2**14: "AH",
        2**15: "PAY",
        2**16: "Res", 2**17: "Res", 2**18: "Res", 2**19: "Res", 2**20: "Res",
        2**21: "Res", 2**22: "Res", 2**23: "Res", 2**24: "Res", 2**25: "Res",
        2**26: "Res", 2**27: "Res", 2**28: "Res", 2**29: "Res", 2**30: "Res",
        2**31: "Res", 2**32: "Res"}

class FlowHelper():
    def __init__(self, flowmsg):
        self.flowmsg = flowmsg

    def direction_str(self):
        return flow_direction[self.flowmsg.FlowDirection]

    def is_incoming(self):
        return self.flowmsg.FlowDirection == 0

    def is_outgoing(self):
        return self.flowmsg.FlowDirection == 1

    def peer(self):
        if self.is_incoming():
            return self.flowmsg.SrcIfDesc
        elif self.is_outgoing():
            return self.flowmsg.DstIfDesc
        else:
            return ""

    def etype_str(self):
        return etype[self.flowmsg.Etype]

    def ipversion(self):
        if self.flowmsg.Etype == 0x0800:
            return 4
        elif self.flowmsg.Etype == 0x86dd:
            return 6
        else:
            return 0

    def ipversion_str(self):
        if self.flowmsg.Etype == 0x0800 or self.flowmsg.Etype == 0x86dd:
            return self.etype_str()
        else:
            return ""

    def is_ipv4(self):
        return flow.Etype == 0x0800

    def is_ipv6(self):
        return flow.Etype == 0x86dd

    def forwardingstatus_str(self):
        return forwarding_status[self.flowmsg.ForwardingStatus]

    def is_consumed(self):
        return 192 <= self.flowmsg.ForwardingStatus # and < 256

    def is_dropped(self):
        return 128 <= self.flowmsg.ForwardingStatus and self.flowmsg.ForwardingStatus < 192

    def is_forwarded(self):
        return 64 <= self.flowmsg.ForwardingStatus and self.flowmsg.ForwardingStatus < 128

    def is_unknown_forwardingstatus(self):
        return self.flowmsg.ForwardingStatus < 64

    def ipv6_extensionheaders_str(self):
        flags = [flag for val, flag in ipv6_extension_headers if self.flowmsg.IPv6ExtensionHeaders & val]
        return " - ".join(flags)
