from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, in_proto, ipv4, icmp, tcp, udp
import logging
from ryu.lib import hub
from typing import Dict, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict
import time
from threading import Lock

# Global constants for flow, meter and stats configuration
DEFAULT_FLOW_IDLE_TIMEOUT = 60  # Time before inactive flow is removed: 1 minute
DEFAULT_FLOW_HARD_TIMEOUT = 300  # Time before flow is removed: 5 minutes
STATS_INTERVAL = 5  # seconds between stats collection
WINDOW_SIZE = 5  # Number of intervals to keep for rate calculations

@dataclass
class FlowStats:
    """Class to track flow stats."""
    packet_count: int = 0 # Number of packets in flow
    byte_count: int = 0 # Number of bytes in flow
    duration_sec: int = 0 # Duration(lifespan) of flow in seconds
    start_time: float = field(default_factory=time.time) # Time when flow started
    last_update: float = field(default_factory=time.time) # Last updated time
    is_active: bool = True # Flow status 

    def update(self, pkt_count: int, byte_count: int, duration: int) -> None:
        """Update flow stats."""
        self.packet_count = pkt_count
        self.byte_count = byte_count
        self.duration_sec = duration
        self.last_update = time.time()
        self.is_active = True

# Ryu application class for SDN DDoS prevention
class SimpleSwitch13(app_manager.RyuApp):
    """
    Main controller class
    
    Features:
    - MAC learning and forwarding
    - Rate limiting using OpenFlow meters
    - Flow stats tracking
    - Thread handling on exclusive access to shared resources (datapaths, flow stats) (in progress)
    - Flow stats collection and analysis (in progress 50%)
    - Adaptive Random Forest (ARF) for DDoS detection (in progress)
    - Dynamic meter rate adjustment for mitigation (in progress)
    """
    # OpenFlow version supported
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize controller with default configurations."""
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        
        # Data structures
        self.mac_to_port: Dict[int, Dict[str, int]] = {} # MAC address to port mapping {dpid: {mac: port}}
        self.mac_to_port_lock = Lock() # lock for thread safety
        self.flow_stats: Dict[int, Dict[tuple, FlowStats]] = defaultdict(dict) # Stores flow stats per datapath {dpid: {flow_key: FlowStats}}
        self.flow_stats_lock = Lock() # lock for thread safety
        self.datapaths: Dict[int, Any] = {} # Track connected switches {dpid: datapath}
        self.datapaths_lock = Lock()  # lock for thread safety
        
        # Logging
        self.logger = logging.getLogger('sdn_controller')
        self.logger.setLevel(logging.INFO)
        
        # Console logging
        if not self.logger.handlers:
            ch = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s') # Log format: timestamp - logger name - log level - message
            ch.setFormatter(formatter)
            self.logger.addHandler(ch)
        
        # Openflow pipeline configuration
        self.METER_TABLE_ID = 0  # Table 0: Apply rate limiting meter
        self.FORWARDING_TABLE_ID = 1  # Table 1: MAC learning and forwarding
        
        # Meter configuration
        self.METER_ID = 1
        self.DEFAULT_RATE = 1000000000  # 1Gbps
        self.current_rate = self.DEFAULT_RATE
        
        self.logger.info("Controller initialized with default rate %d bytes/sec", self.DEFAULT_RATE)

        # Start monitoring thread for flow stats collection
        self.is_active = True
        self.monitor_thread = hub.spawn(self._monitor_loop)

    def _monitor_loop(self) -> None:
        """Background thread to periodically request flow statistics."""
        while self.is_active:
            for dp in list(self.datapaths.values()):
                try:
                    self.logger.debug(f"Requesting stats for datapath {dp.id}")
                    self._request_flow_stats(dp)
                except Exception as e:
                    self.logger.error(f"Error requesting stats for datapath {dp.id}: {e}")
            hub.sleep(STATS_INTERVAL)

    def _request_flow_stats(self, datapath) -> None:
        """Send flow statistics request to the switch."""
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        
        req = ofp_parser.OFPFlowStatsRequest(
            datapath=datapath,
            table_id=ofp.OFPTT_ALL,
            out_port=ofp.OFPP_ANY,
            out_group=ofp.OFPG_ANY,
            cookie=0,
            cookie_mask=0,
            match=ofp_parser.OFPMatch()
        )
        datapath.send_msg(req)

    def stop(self):
        """Ensure clean shutdown of the monitor thread."""
        self.is_active = False
        hub.joinall([self.monitor_thread])
        super(SimpleSwitch13, self).stop()


    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev) -> None:
        """Handle flow statistics reply from switch."""
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        
        with self.flow_stats_lock: # Acquire lock
            for stat in body:
                # Extract flow key: tuple of (eth_src, eth_dst, ip_proto, src_port, dst_port)
                flow_key = self._get_flow_key_from_stats(stat)
                if not flow_key:
                    continue
                    
                # Update flow statistics
                if dpid not in self.flow_stats:
                    self.flow_stats[dpid] = {}
                    
                if flow_key not in self.flow_stats[dpid]:
                    self.flow_stats[dpid][flow_key] = FlowStats()
                    
                flow_stat = self.flow_stats[dpid][flow_key]
                flow_stat.update(
                    stat.packet_count,
                    stat.byte_count,
                    stat.duration_sec
                )

    def _get_flow_key_from_stats(self, stat) -> Optional[tuple]:
        """Extract flow key from flow stats."""
        try:
            eth_src = stat.match.get('eth_src', '00:00:00:00:00:00')
            eth_dst = stat.match.get('eth_dst', '00:00:00:00:00:00')
            ip_proto = stat.match.get('ip_proto', 0)
            src_port = stat.match.get('tcp_src', 0) or stat.match.get('udp_src', 0)
            dst_port = stat.match.get('tcp_dst', 0) or stat.match.get('udp_dst', 0)
            
            return (eth_src, eth_dst, ip_proto, src_port, dst_port)
        except Exception as e:
            self.logger.error(f"Error extracting flow key: {e}")
            return None 
    
    def _detect_ddos(self, dpid: int, port_no: int) -> None:
        pass

    def _mitigate_attack(self, dpid: int, port_no: int) -> None:
        pass

    # Handle switch connection and initialize flow tables
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection and initialize flow tables."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Store datapath
        with self.datapaths_lock:
            self.datapaths[datapath.id] = datapath

        # Configure initial meter with default rate
        # Example:
        burst_size = max(15000, int(self.DEFAULT_RATE * 0.01)) # at least 10 MTUs, or 1% of rate
        if self.DEFAULT_RATE == 0: # If rate is zero, burst should also be zero
            burst_size = 0
        bands = [parser.OFPMeterBandDrop(type_=ofproto.OFPMBT_DROP, rate=self.DEFAULT_RATE, burst_size=burst_size)]
        req = parser.OFPMeterMod(datapath, command=ofproto.OFPMC_ADD, meter_id=self.METER_ID, bands=bands)
        datapath.send_msg(req)
        self.logger.debug(f"Initialized meter {self.METER_ID} with default rate {self.DEFAULT_RATE} bytes/sec")

        # Install general flow in Table 0: apply meter to all traffic
        match = parser.OFPMatch()
        instructions = [
            parser.OFPInstructionMeter(self.METER_ID),
            parser.OFPInstructionGotoTable(self.FORWARDING_TABLE_ID)
        ]
        mod = parser.OFPFlowMod(datapath, table_id=self.METER_TABLE_ID, priority=0, match=match, instructions=instructions)
        datapath.send_msg(mod)
        self.logger.debug("Installed general flow in Table 0 with meter")

        # Install table-miss flow in Table 1: send to controller for MAC learning
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath, table_id=self.FORWARDING_TABLE_ID, priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)
        self.logger.debug("Installed table-miss flow in Table 1")
    
    def update_meter_rate(self, datapath: Any, rate: int) -> bool:
        """
        Dynamically adjust the meter rate.
        
        Args:
            datapath: The switch datapath object
            rate: New rate in bytes per second
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            burst_size = max(15000, int(rate * 0.01)) # at least 10 MTUs, or 1% of rate
            if rate == 0: # If rate is zero, burst should also be zero
                burst_size = 0

            rate_kbps = int((rate * 8) / 1000) # Convert bytes/sec to kbps
            burst_kbps = int((burst_size * 8) / 1000) # Convert burst bytes to kbits

            # Modify existing meter with new rate
            bands = [parser.OFPMeterBandDrop(
                type_=ofproto.OFPMBT_DROP, 
                rate=rate_kbps, 
                burst_size=burst_kbps
            )]
            
            req = parser.OFPMeterMod(
                datapath=datapath,
                command=ofproto.OFPMC_MODIFY,
                flags=ofproto.OFPMF_KBPS,
                meter_id=self.METER_ID,
                bands=bands
            )
            
            datapath.send_msg(req)
            self.current_rate = rate
            self.logger.info(
                "Adjusted meter %d rate to %d bytes/sec (burst: %d) on switch %s",
                self.METER_ID, rate, burst_size, datapath.id
            )
            return True
            
        except Exception as e:
            self.logger.error(
                "Failed to update meter rate to %d: %s", 
                rate, str(e), exc_info=True
            )
            return False

    # Helper method to add flow entries to a switch
    def _add_flow(self, 
                 datapath: Any, 
                 table_id: int, 
                 priority: int, 
                 match: Any, 
                 actions: list, 
                 buffer_id: Optional[int] = None, 
                 instructions: Optional[list] = None) -> bool:
        """
        Add a flow entry to the specified table with given match and actions.
        
        Args:
            datapath: The switch datapath object
            table_id: Table ID to install the flow
            priority: Flow priority
            match: Flow match conditions
            actions: List of actions to apply
            buffer_id: Optional buffer ID for buffered packets
            instructions: Optional list of instructions
            
        Returns:
            bool: True if flow was added successfully, False otherwise
        """
        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            inst = []
            if instructions:
                inst.extend(instructions)
            if actions:
                inst.append(parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, 
                    actions
                ))
            
            if buffer_id is None:
                buffer_id = ofproto.OFP_NO_BUFFER

            mod = parser.OFPFlowMod(
                datapath=datapath,
                table_id=table_id,
                priority=priority,
                match=match,
                instructions=inst,
                hard_timeout=DEFAULT_FLOW_HARD_TIMEOUT,
                idle_timeout=DEFAULT_FLOW_IDLE_TIMEOUT,
                buffer_id=buffer_id
            )
            
            datapath.send_msg(mod)
            self.logger.debug(
                "Added flow: table=%d, priority=%d, match=%s, actions=%s",
                table_id, priority, str(match), str(actions)
            )
            return True
            
        except Exception as e:
            self.logger.error(
                "Failed to add flow: %s", 
                str(e), exc_info=True
            )
            return False

    # Handle switch connection events
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """Handle switch connection and disconnection events."""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            with self.datapaths_lock:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            with self.datapaths_lock:
                self.datapaths.pop(datapath.id, None)
            with self.mac_to_port_lock:
                if datapath.id in self.mac_to_port:
                    del self.mac_to_port[datapath.id]

    # Handle packets sent to the controller (MAC learning)
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev: ofp_event.EventOFPPacketIn) -> None:
        """
        Process packets sent to the controller, learn MACs, and forward.
        
        Args:
            ev: The packet-in event
        """
        try:
            msg = ev.msg
            datapath = msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            in_port = msg.match['in_port']

            # Parse the packet
            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocols(ethernet.ethernet)
            
            if not eth or len(eth) == 0:
                self.logger.warning("Received non-Ethernet packet")
                return
                
            eth = eth[0]
            dst = eth.dst
            src = eth.src
            dpid = datapath.id
            
            # Skip LLDP and other non-IP traffic
            if eth.ethertype == ether_types.ETH_TYPE_LLDP:
                return

            # Initialize MAC table for this switch
            with self.mac_to_port_lock:
                self.mac_to_port.setdefault(dpid, {})

            self.logger.debug(
                "Packet in: switch=%s src=%s dst=%s in_port=%s", 
                dpid, src, dst, in_port
            )

            # Learn source MAC address
            with self.mac_to_port_lock:
               self.mac_to_port[dpid][src] = in_port

            # --- Create granular match for installing flow rules ---
            # Start with a default L2 match, and add more details if available
            match_fields = {'in_port': in_port, 'eth_src': src, 'eth_dst': dst}

            if eth.ethertype == ether_types.ETH_TYPE_IP:
                match_fields['eth_type'] = eth.ethertype
                ip_pkt = pkt.get_protocol(ipv4.ipv4)
                if ip_pkt:
                    match_fields['ipv4_src'] = ip_pkt.src
                    match_fields['ipv4_dst'] = ip_pkt.dst
                    match_fields['ip_proto'] = ip_pkt.proto

                    if ip_pkt.proto == in_proto.IPPROTO_ICMP:
                        icmp_pkt_proto = pkt.get_protocol(icmp.icmp)
                        if icmp_pkt_proto:
                            match_fields['icmpv4_type'] = icmp_pkt_proto.type
                            match_fields['icmpv4_code'] = icmp_pkt_proto.code
                    elif ip_pkt.proto == in_proto.IPPROTO_TCP:
                        tcp_pkt_proto = pkt.get_protocol(tcp.tcp)
                        if tcp_pkt_proto:
                            match_fields['tcp_src'] = tcp_pkt_proto.src_port
                            match_fields['tcp_dst'] = tcp_pkt_proto.dst_port
                    elif ip_pkt.proto == in_proto.IPPROTO_UDP:
                        udp_pkt_proto = pkt.get_protocol(udp.udp)
                        if udp_pkt_proto:
                            match_fields['udp_src'] = udp_pkt_proto.src_port
                            match_fields['udp_dst'] = udp_pkt_proto.dst_port
                else:
                    self.logger.debug(f"DPID {dpid}: eth_type IP but no ipv4_protocol found in packet")
            
            elif eth.ethertype == ether_types.ETH_TYPE_ARP:
                match_fields['eth_type'] = eth.ethertype
                arp_pkt_proto = pkt.get_protocol(arp.arp)
                if arp_pkt_proto:
                    match_fields['arp_op'] = arp_pkt_proto.opcode
                    match_fields['arp_spa'] = arp_pkt_proto.src_ip
                    match_fields['arp_tpa'] = arp_pkt_proto.dst_ip
                    match_fields['arp_sha'] = arp_pkt_proto.src_mac
                    match_fields['arp_tha'] = arp_pkt_proto.dst_mac
                else:
                    self.logger.debug(f"DPID {dpid}: eth_type ARP but no arp_protocol found in packet")
            # else: for other eth_types, match_fields remains L2 with in_port

            match = parser.OFPMatch(**match_fields)
            # --- End of granular match creation ---

            # Determine output port
            with self.mac_to_port_lock:
               out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)

            # Install flow for known destinations in Table 1
            if out_port != ofproto.OFPP_FLOOD:
                actions = [parser.OFPActionOutput(out_port)]
                if self._add_flow(datapath, self.FORWARDING_TABLE_ID, 1, match, actions):
                    self.logger.debug(
                        "Installed forwarding flow for dst=%s to port=%d", 
                        dst, out_port
                    )

            # Prepare packet out
            actions = [parser.OFPActionOutput(out_port)]
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
                
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=data
            )
            datapath.send_msg(out)
            self.logger.debug("Sent packet out on port=%d", out_port)
            
        except Exception as e:
            self.logger.error("Error in packet_in handler: %s", str(e), exc_info=True)

    # Placeholder for future AI integration (Layer 3)
    def _ai_integration_placeholder(self):
        """Placeholder for integrating Adaptive Random Forest and RL for DDoS detection/mitigation."""
        # TODO: Collect flow stats (Flow-Pkts/s, Flow-Dur) via OFPFlowStatsRequest
        # TODO: Optimize flow stats collection _flow_stats_reply_handler
        # TODO: Feed stats into ARF model for attack classification
        # TODO: Call adjust_meter_rate with appropriate rate when attack detected
        # TODO: Call adjust_meter_rate with DEFAULT_RATE when attack mitigated
        
        pass

    # Note: eBPF filtering (Layer 1) will be implemented at the OVS kernel level 
