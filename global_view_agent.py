from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, arp, ethernet
import asyncio
import threading
import json, time

class GlobalViewAgent(app_manager.RyuApp):
    """
    GlobalViewAgent (Ryu SDN Controller) listens for flow reports from TrafficAgent,
    decides to allow or drop flows, and installs OpenFlow rules accordingly.
    It runs an asyncio TCP server (in a separate thread) for flow report messages.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(GlobalViewAgent, self).__init__(*args, **kwargs)
        # Switch datapaths by DPID
        self.datapaths = {}
        # Switch agent ports (for TrafficAgent connection)
        self.agent_ports = {}
        # Mapping of IP to switch port for each switch (learned via ARP)
        self.ip_to_port = {}
        # Mapping ARP
        self.arp_table = {}
        # Threshold parameters (shared across all switches/flows)
        self.f_low = 2
        self.f_high = 5
        # TCP server settings for TrafficAgent communication
        self.ta_host = '0.0.0.0'
        self.ta_port = 9000
        self.ta_writer = None

        # Start the asyncio TCP server in a separate thread
        self.loop = asyncio.new_event_loop()
        self.server_thread = threading.Thread(target=self._start_tcp_server, daemon=True)
        self.server_thread.start()
        self.logger.info("Started GlobalViewAgent TCP server thread")

    def _start_tcp_server(self):
        """Start asyncio TCP server to accept TrafficAgent connections."""
        asyncio.set_event_loop(self.loop)
        # Create TCP server coroutine
        server_coro = asyncio.start_server(self._handle_ta_connection,
                                           host=self.ta_host, port=self.ta_port)
        server = self.loop.run_until_complete(server_coro)
        self.logger.info(f"TCP server listening on {self.ta_host}:{self.ta_port}")
        try:
            self.loop.run_forever()
        except Exception as e:
            self.logger.error(f"Asyncio loop stopped: {e}")
        server.close()
        self.loop.run_until_complete(server.wait_closed())

    async def _handle_ta_connection(self, reader, writer):
        """Handle a new TrafficAgent connection."""
        addr = writer.get_extra_info('peername')
        self.logger.info(f"TrafficAgent connected from {addr}")
        
        # Save writer to send decisions back to TrafficAgent
        self.ta_writer = writer

        # Install IP→TA rules on all known switches
        for dpid, datapath in self.datapaths.items():
            agent_port = self.agent_ports.get(dpid)
            if agent_port is None:
                self.logger.warning(f"No TrafficAgent port for switch {dpid}")
                continue

            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto

            match_ip = parser.OFPMatch(eth_type=0x0800)
            actions = [parser.OFPActionOutput(agent_port)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

            mod = parser.OFPFlowMod(
                datapath=datapath,
                priority=0,  # table-miss default for IP
                match=match_ip,
                instructions=inst
            )
            datapath.send_msg(mod)
            self.logger.info(f"Installed IP→TA rule on switch {dpid} (port {agent_port})")

        try:
            while True:
                # Read a length-prefixed JSON message
                length_bytes = await reader.readexactly(4)
                length = int.from_bytes(length_bytes, 'big')
                data = await reader.readexactly(length)
                msg = json.loads(data.decode())
                self.logger.info(f"[GlobalViewAgent] Received: {msg}")
                await self._handle_ta_message(msg)
        except (asyncio.IncompleteReadError, ConnectionResetError) as e:
            self.logger.warning(f"TrafficAgent connection lost: {e}")
        finally:
            # Clean up IP→TA rules on disconnect
            for dpid, datapath in self.datapaths.items():
                parser = datapath.ofproto_parser
                ofproto = datapath.ofproto

                match_ip = parser.OFPMatch(eth_type=0x0800)
                mod = parser.OFPFlowMod(
                    datapath=datapath,
                    command=ofproto.OFPFC_DELETE,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    priority=0,
                    match=match_ip
                )
                datapath.send_msg(mod)
                self.logger.info(f"Removed IP→TA rule on switch {dpid}")

            writer.close()
            await writer.wait_closed()
            self.logger.info(f"TrafficAgent connection from {addr} closed")
            self.ta_writer = None


    async def _handle_ta_message(self, msg):
        """Handle messages received from the TrafficAgent."""
        msg_type = msg.get("type")
        if msg_type == "flow_report":
            # Extract flow information
            dpid = msg['dpid']
            flow = tuple(msg["flow"])
            count = msg["features"].get("packet_count", 0)
            # Simple decision logic: allow flows above mid-threshold
            if count > (self.f_low + self.f_high) / 2:
                decision = "allow"
            else:
                decision = "drop"
            # Install OpenFlow rule on switch             
            self._install_flow_rule(dpid, flow, decision)
            # Send the decision back to the TrafficAgent
            response = {
                "type": "decision",
                "flow": list(flow),
                "decision": decision
            }
            await self._send_to_ta(response)
        else:
            self.logger.info(f"[GlobalViewAgent] Unknown message type: {msg_type}")

    async def _send_to_ta(self, message):
        """Send a JSON message to the connected TrafficAgent."""
        if self.ta_writer:
            data = json.dumps(message).encode()
            try:
                self.ta_writer.write(len(data).to_bytes(4, 'big') + data)
                await self.ta_writer.drain()
                self.logger.info(f"[GlobalViewAgent] Sent: {message}")
            except Exception as e:
                self.logger.warning(f"Failed to send to TrafficAgent: {e}")
        else:
            self.logger.warning("No TrafficAgent connected; cannot send message")

    def _install_flow_rule(self, dpid, flow, decision):
        """Install an OpenFlow rule to drop or allow the given flow."""
        datapath = self.datapaths.get(dpid)
        if datapath is None:
            self.logger.error(f"No datapath found for switch {dpid}")
            return
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        ip_src, ip_dst, src_port, dst_port, proto = flow
        # Determine IP protocol number
        ip_proto = 6 if proto == 'TCP' else 17
        # Build match for the flow
        if proto == "TCP":
            match = parser.OFPMatch(eth_type=0x0800,
                                    ipv4_src=ip_src, ipv4_dst=ip_dst,
                                    ip_proto=ip_proto,
                                    tcp_src=src_port, tcp_dst=dst_port)
        else:  # UDP
            match = parser.OFPMatch(eth_type=0x0800,
                                    ipv4_src=ip_src, ipv4_dst=ip_dst,
                                    ip_proto=ip_proto,
                                    udp_src=src_port, udp_dst=dst_port)
        # Decide actions based on decision
        if decision == "drop":
            actions = []
            self.logger.info(f"Installing DROP rule for flow {flow}")
        else:  # allow
            out_port = self._get_output_port(datapath, ip_dst)
            if out_port:
                actions = [parser.OFPActionOutput(out_port)]
                self.logger.info(f"Installing ALLOW rule for flow {flow} to port {out_port}")
            else:
                # If destination unknown, flood as fallback
                actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                self.logger.info(f"Installing ALLOW rule for flow {flow} as FLOOD")
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        # Use higher priority than default table-miss
        mod = parser.OFPFlowMod(datapath=datapath, priority=100,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def _get_output_port(self, datapath, dst_ip):
        """Look up the output port for the given destination IP (learned via ARP)."""
        ports = self.ip_to_port.get(datapath.id, {})
        return ports.get(dst_ip)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch feature reply to install default flow rules."""
        datapath = ev.msg.datapath
        dpid = datapath.id
        self.datapaths[dpid] = datapath
        self.ip_to_port.setdefault(dpid, {})
        self.logger.info(f"Switch {dpid} connected.")
        # specify agent port 
        self.agent_ports[dpid] = 3 # forward table miss packets to port 3 for now as both swicthes are linked to TA by p3

        self.logger.info(f"TrafficAgent port for switch {dpid} set to {self.agent_ports[dpid]}")
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        # Default: send ARP packets to controller for learning
        match_arp = parser.OFPMatch(eth_type=0x0806)
        actions_ctrl = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self._add_flow(datapath, match_arp, actions_ctrl, priority=10)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle PacketIn events to learn host locations and install paths."""
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)

        if eth.ethertype == 0x0806 and arp_pkt:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip

            # Learn source IP location (just like before)
            self.ip_to_port.setdefault(dpid, {})[src_ip] = in_port
            self.arp_table[src_ip] = (dpid, in_port)  # for path install
            self.logger.info(f"Learned {src_ip} is at switch {dpid} port {in_port}")

            # If destination is known, install forward/reverse paths
            if dst_ip in self.arp_table:
                self._install_path(src_ip, dst_ip)
                self._install_path(dst_ip, src_ip)

            # Flood ARP so other side learns
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data
            )
            datapath.send_msg(out)
    
    def _install_path(self, src_ip, dst_ip):
        # Find the DPIDs and ports where each host lives
        dpid_src, port_src = self.arp_table[src_ip]
        dpid_dst, port_dst = self.arp_table[dst_ip]

        # Install flow on source switch
        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip,
            ip_proto=1  # ICMP
        )
        actions = [parser.OFPActionOutput(port_dst)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=self.datapaths[dpid_src],
            priority=200,
            match=match,
            instructions=inst,
            idle_timeout=30,
            hard_timeout=60
        )
        self.datapaths[dpid_src].send_msg(mod)



    def _add_flow(self, datapath, match, actions, priority=0):
        """Helper to add a flow entry to the switch."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)
