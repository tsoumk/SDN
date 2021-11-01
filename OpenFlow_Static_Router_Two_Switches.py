# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An OpenFlow 1.0 L3 Static Router and two OpenFlow 1.0 L2 learning switches.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types

H1_ip = '192.168.1.2'
H1_mac = '00:00:00:00:01:02'

H3_ip = '192.168.2.2'
H3_mac = '00:00:00:00:02:02'

ROUTER_1A_ip = '192.168.1.1'
ROUTER_1B_ip = '192.168.2.1'
ROUTER_1A_l_mac = '00:00:00:00:01:01'
ROUTER_1A_r_mac = '00:00:00:00:03:01'
ROUTER_1B_l_mac = '00:00:00:00:03:02'
ROUTER_1B_r_mac = '00:00:00:00:02:01'

class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src

        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        if dpid == 0x1A:
            if eth.ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                arp_header = pkt.get_protocol(arp.arp)
                if arp_header.opcode == 1:
                    if arp_header.dst_ip == ROUTER_1A_ip:
                        self.send_arp_reply(datapath, ROUTER_1A_l_mac, ROUTER_1A_ip, src, arp_header.src_ip,
                                            msg.in_port)
                    return
                return
            elif eth.ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                ip_datag = pkt.get_protocol(ipv4.ipv4)
                src_add = ip_datag.src
                dst_add = ip_datag.dst
                match = datapath.ofproto_parser.OFPMatch(dl_type=0x0800, nw_dst=dst_add, dl_dst=dst)

                if ((H1_ip == ip_datag.src) and (
                        H3_ip == ip_datag.dst) and dst == ROUTER_1A_l_mac):
                    actions = [datapath.ofproto_parser.OFPActionSetDlDst(ROUTER_1B_l_mac),
                               datapath.ofproto_parser.OFPActionSetDlSrc(ROUTER_1A_r_mac),
                               datapath.ofproto_parser.OFPActionOutput(1)]
                    self.add_flow(datapath, match, actions)

                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                        actions=actions, data=msg.data)
                    datapath.send_msg(out)

                elif ((H3_ip == ip_datag.src) and (
                        H1_ip == ip_datag.dst) and src == ROUTER_1A_r_mac):
                    actions = [datapath.ofproto_parser.OFPActionSetDlDst(H1_mac),
                               datapath.ofproto_parser.OFPActionSetDlSrc(ROUTER_1A_mac_l),
                               datapath.ofproto_parser.OFPActionOutput(2)]
                    self.add_flow(datapath, match, actions)

                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                        actions=actions, data=msg.data)
                    datapath.send_msg(out)

                else:
                    actions[] #keno opws to eida sto internet

                    self.add_flow(datapath, match, actions) #flow gia ta dropped packets

                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                        actions=actions, data=msg.data)
                    datapath.send_msg(out)

                return
            return
        if dpid == 0x1B:
            if eth.ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                arp_header = pkt.get_protocol(arp.arp)
                if arp_header.opcode == 1:
                    if arp_header.dst_ip == ROUTER_1B_ip:
                        self.send_arp_reply(datapath, ROUTER_1B_mac_r, ROUTER_1B_ip, src, arp_header.src_ip,
                                        msg.in_port)
                    return
                return

            elif eth.ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                ip_datag = pkt.get_protocol(ipv4.ipv4)
                src_add = ip_datag.src
                dst_add = ip_datag.dst
                match = datapath.ofproto_parser.OFPMatch(dl_type=0x0800, nw_dst=dst_add, dl_dst=dst)

                if ((H3_ip == ip_datag.src) and (
                        H1_ip == ip_datag.dst) and dst == ROUTER_1B_r_mac):
                    actions = [datapath.ofproto_parser.OFPActionSetDlDst(ROUTER_1A_r_mac),
                               datapath.ofproto_parser.OFPActionSetDlSrc(ROUTER_1B_l_mac),
                               datapath.ofproto_parser.OFPActionOutput(1)]
                    self.add_flow(datapath, match, actions)

                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                        actions=actions, data=msg.data)
                    datapath.send_msg(out)

                elif ((H1_ip == ip_datag.src) and (
                        H3_ip == ip_datag.dst) and src == ROUTER_1B_l_mac):
                    actions = [datapath.ofproto_parser.OFPActionSetDlDst(H3_mac),
                               datapath.ofproto_parser.OFPActionSetDlSrc(ROUTER_1B_r_mac),
                               datapath.ofproto_parser.OFPActionOutput(2)]
                    self.add_flow(datapath, match, actions)

                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                        actions=actions, data=msg.data)
                    datapath.send_msg(out)

                else:
                    actions[] #keno opws to eida sto internet

                    self.add_flow(datapath, match, actions) #flow gia ta dropped packets

                    out = datapath.ofproto_parser.OFPPacketOut(
                        datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                        actions=actions, data=msg.data)
                    datapath.send_msg(out)

                return
            return

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        match = datapath.ofproto_parser.OFPMatch(
            in_port=msg.in_port, dl_dst=haddr_to_bin(dst))

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    def send_arp_reply(self, datapath, srcMac, srcIp, dstMac, dstIp, outPort):
        e = ethernet.ethernet(dstMac, srcMac, ether_types.ETH_TYPE_ARP)
        a = arp.arp(1, 0x0800, 6, 4, 2, srcMac, srcIp, dstMac, dstIp)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(outPort, 0)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=0xffffffff,
            in_port=datapath.ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=p.data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
