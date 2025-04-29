from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, arp, ethernet
from ryu.lib import hub
from ryu.topology import event
import asyncio
import threading
import json, time, collections

class GlobalViewAgent(app_manager.RyuApp):
    """
    GlobalViewAgent (Ryu SDN Controller) listens for flow reports from TrafficAgent,
    decides to allow or drop flows, installs OpenFlow rules accordingly,
    and also performs periodic DDoS monitoring using flow/port stats.
    Additionally installs host-to-host paths on ARP learning to enable ping.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # DDoS detection parameters
    FLOW_LOW_THRESHOLD = 2     # pps lower than this are suspicious
    FLOW_HIGH_THRESHOLD = 5    # pps higher are legitimate
    PACKET_COUNT_THRESHOLD = 100  # packets per flow to flag
    FLOW_COUNT_THRESHOLD = 20     # number of flagged flows to trigger mitigation
    DETECTION_WINDOW = 10         # seconds for detection interval

    def __init__(self, *args, **kwargs):
        super(GlobalViewAgent, self).__init__(*args, **kwargs)
        # --- state ---
        self.datapaths = {}
        self.agent_ports = {}
        self.ip_to_port = {}
        self.arp_table = {}
        self.f_low = self.FLOW_LOW_THRESHOLD
        self.f_high = self.FLOW_HIGH_THRESHOLD
       
        # --- TA comms ---
        self.ta_host = '0.0.0.0'; self.ta_port = 9000; self.ta_writer = None

        # --- DDoS monitor ---
        self.flow_stats = {}
        self.port_stats = {}
        self.suspicious_ips = collections.defaultdict(int)
        self.last_detection = time.time()
        self.monitor_thread = hub.spawn(self._monitor)

        # --- start TCP server thread ---
        self.loop = asyncio.new_event_loop()
        self.server_thread = threading.Thread(target=self._start_tcp_server, daemon=True)
        self.server_thread.start()
        self.logger.info("GlobalViewAgent started (TCP & monitor threads)")

    # --------------------- Switch feature handler ---------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath; dpid = dp.id
        ofproto = dp.ofproto; parser = dp.ofproto_parser
        # register
        self.datapaths[dpid] = dp
        self.agent_ports[dpid] = 3  # ensure matches Mininet topology
        self.ip_to_port.setdefault(dpid, {})

        # install ARP -> controller
        m_arp = parser.OFPMatch(eth_type=0x0806)
        inst_arp = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                       [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)])]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=10, match=m_arp, instructions=inst_arp))

        # install IP -> TrafficAgent
        port_ta = self.agent_ports[dpid]
        m_ip = parser.OFPMatch(eth_type=0x0800)
        inst_ip = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                       [parser.OFPActionOutput(port_ta)])]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=0, match=m_ip, instructions=inst_ip))

        self.logger.info(f"Switch {dpid}: ARP->CTRL (prio10), IP->TA port {port_ta} (prio0)")

    # ------------- PacketIn for ARP learning & path install -------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg; dp = msg.datapath; dpid = dp.id
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)

        # only handle ARP for learning
        if eth.ethertype == 0x0806 and arp_pkt:
            src_ip = arp_pkt.src_ip; dst_ip = arp_pkt.dst_ip
            # learn
            self.ip_to_port.setdefault(dpid, {})[src_ip] = in_port
            self.arp_table[src_ip] = (dpid, in_port)
            self.logger.info(f"Learned host {src_ip}@{dpid}/{in_port}")
            # if destination known, install bidirectional paths
            if src_ip in self.arp_table and dst_ip in self.arp_table:
                self._install_path(src_ip, dst_ip)
                self._install_path(dst_ip, src_ip)
                self.logger.info(f"Added paths {src_ip}={dst_ip} for {dpid}")
            # flood ARP
            parser = dp.ofproto_parser; ofp = dp.ofproto
            out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                      in_port=in_port,
                                      actions=[parser.OFPActionOutput(ofp.OFPP_FLOOD)],
                                      data=msg.data)
            dp.send_msg(out)

    def _install_path(self, src_ip, dst_ip):
        # installs flow rules in both directions for IP traffic between two hosts
        dpid, port = self.arp_table[src_ip]
        dp = self.datapaths.get(dpid)
        if not dp: return
        parser, ofp = dp.ofproto_parser, dp.ofproto
        # match IPv4 between src and dst
        match = parser.OFPMatch(eth_type=0x0800,
                                ipv4_src=src_ip, ipv4_dst=dst_ip)
        # action: output to port of dst_ip
        out_port = self.arp_table.get(dst_ip, (None,None))[1]
        actions = [parser.OFPActionOutput(out_port)] if out_port else [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=50, match=match, instructions=inst))
        self.logger.info(f"Installed path {src_ip}->{dst_ip} on switch {dpid} outport {out_port}")

    # --------------------- BTCP server & TA comms ---------------------
    def _start_tcp_server(self):
        asyncio.set_event_loop(self.loop)
        server = self.loop.run_until_complete(
            asyncio.start_server(self._handle_ta_connection, self.ta_host, self.ta_port)
        )
        self.logger.info(f"TCP server listening on {self.ta_host}:{self.ta_port}")
        try:
            self.loop.run_forever()
        finally:
            server.close(); self.loop.run_until_complete(server.wait_closed())

    async def _handle_ta_connection(self, reader, writer):
        addr = writer.get_extra_info('peername'); self.logger.info(f"TA connected from {addr}")
        self.ta_writer = writer
        # once connected, no need to reinstall default IP->TA (already done)
        try:
            while True:
                length = int.from_bytes(await reader.readexactly(4), 'big')
                data = await reader.readexactly(length)
                msg = json.loads(data.decode()); self.logger.info(f"Recv TA: {msg}")
                await self._handle_ta_message(msg)
        except Exception as e:
            self.logger.warning(f"TA disconnected: {e}")
        finally:
            writer.close(); await writer.wait_closed(); self.ta_writer = None

    async def _handle_ta_message(self, msg):
        if msg.get('type') != 'flow_report': return
        dpid = msg['dpid']; flow = tuple(msg['flow']); cnt = msg['features'].get('packet_count', 0)
        state = msg.get('state', 'p')
        if state == 'p': # PENDING
            # apply same thresholds
            if cnt >= self.f_high:
                decision = 'allow'
            elif cnt <= self.f_low:
                decision = 'drop'
            else:
                decision = 'drop'
            self._install_flow_rule(dpid, flow, decision)
            # reply
            resp = {'type':'decision','flow':list(flow),'decision':decision}
            if self.ta_writer:
                data = json.dumps(resp).encode()
                self.ta_writer.write(len(data).to_bytes(4,'big')+data)
                await self.ta_writer.drain()
        # FORWARD
        elif state == 'd': self._install_flow_rule(dpid, flow, 'drop')
        elif state == 'a': self._install_flow_rule(dpid, flow, 'allow')
        else: self.logger.warning(f"unknown flow state")

    # --------------------- Flow rule installation ---------------------
    def _install_flow_rule(self, dpid, flow, decision):
        dp = self.datapaths.get(dpid)
        if not dp: return
        parser, ofp = dp.ofproto_parser, dp.ofproto
        ip_src, ip_dst, src_p, dst_p, proto = flow
        # match
        if proto == 'TCP': match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src, ipv4_dst=ip_dst, ip_proto=6, tcp_src=src_p, tcp_dst=dst_p)
        elif proto == 'UDP': match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src, ipv4_dst=ip_dst, ip_proto=17, udp_src=src_p, udp_dst=dst_p)
        elif proto == 'ICMP' or proto == 1: match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_src, ipv4_dst=ip_dst, ip_proto=1) # icmp
        # actions
        if decision == 'drop': actions = []
        else:
            out_port = self.ip_to_port.get(dpid,{}).get(ip_dst)
            if out_port: actions = [parser.OFPActionOutput(out_port)]
            else:        actions = [parser.OFPActionOutput(ofp.OFPP_FLOOD)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=100, match=match, instructions=inst))
        self.logger.info(f"{decision.upper()} flow {flow} on switch {dpid} -> {actions}")

    # --------------------- DDoS monitoring ---------------------
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
                dp.send_msg(dp.ofproto_parser.OFPPortStatsRequest(dp, 0, dp.ofproto.OFPP_ANY))
            if time.time() - self.last_detection > self.DETECTION_WINDOW:
                for dpid, stats in self.flow_stats.items(): self._detect(dpid=dpid, stats=stats)
                self.suspicious_ips.clear(); self.last_detection = time.time()
            hub.sleep(5)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply(self, ev):
        self.flow_stats[ev.msg.datapath.id] = ev.msg.body

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply(self, ev):
        self.port_stats[ev.msg.datapath.id] = ev.msg.body

    def _detect(self, dpid, stats):
        cnts = collections.Counter()
        for s in stats:
            if 'ipv4_src' in s.match:
                src_ip = s.match['ipv4_src']; cnts[src_ip] += 1
                if s.packet_count > self.PACKET_COUNT_THRESHOLD:
                    self.suspicious_ips[src_ip] += 1
        for ip, c in cnts.items():
            if self.suspicious_ips[ip] > self.FLOW_COUNT_THRESHOLD:
                self.logger.warning(f"DDoS detected from {ip} on {dpid}")
                self._mitigate(dpid, ip)

    def _mitigate(self, dpid, src_ip):
        dp = self.datapaths.get(dpid); parser=dp.ofproto_parser; ofp=dp.ofproto
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=200, match=match, instructions=[]))
        self.logger.info(f"Blocked traffic from {src_ip} on switch {dpid}")
