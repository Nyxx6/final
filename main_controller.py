from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
import logging
from typing import Dict, Optional, Tuple, Any
from dataclasses import dataclass

# Constants for flow and meter configuration
DEFAULT_FLOW_IDLE_TIMEOUT = 60  # 1 minute
DEFAULT_FLOW_HARD_TIMEOUT = 300  # 5 minutes
MAX_MAC_PER_PORT = 1000  # Maximum MAC addresses per port
STATS_INTERVAL = 5  # seconds between stats collection
WINDOW_SIZE = 5  # Number of intervals to keep for rate calculations

@dataclass
class FlowStats:
    """Class to track flow statistics."""
    packet_count: int = 0
    byte_count: int = 0
    duration_sec: int = 0
    start_time: float = field(default_factory=time.time)
    last_update: float = field(default_factory=time.time)
    is_active: bool = True

    def update(self, pkt_count: int, byte_count: int, duration: int) -> None:
        """Update flow statistics."""
        self.packet_count = pkt_count
        self.byte_count = byte_count
        self.duration_sec = duration
        self.last_update = time.time()
        self.is_active = True

@dataclass
class PortStats:
    """Class to track port statistics and MAC learning."""
    mac_count: int = 0
    last_seen: float = field(default_factory=time.time)
    rx_packets: int = 0
    tx_packets: int = 0
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_dropped: int = 0
    tx_dropped: int = 0
    rx_errors: int = 0
    tx_errors: int = 0
    rx_frame_err: int = 0
    rx_over_err: int = 0
    rx_crc_err: int = 0
    collisions: int = 0
    duration_sec: int = 0
    duration_nsec: int = 0
    rx_rate: float = 0.0
    tx_rate: float = 0.0
    packet_in_rate: float = 0.0
    last_rx_bytes: int = 0
    last_tx_bytes: int = 0
    last_rx_packets: int = 0
    last_update: float = 0.0
    flow_stats: Dict[tuple, FlowStats] = field(default_factory=dict)
    history: Deque[Tuple[float, dict]] = field(default_factory=lambda: deque(maxlen=WINDOW_SIZE))

    def update_rates(self, current_time: float) -> None:
        """Update rate calculations."""
        time_elapsed = current_time - self.last_update
        if time_elapsed > 0:
            self.rx_rate = (self.rx_bytes - self.last_rx_bytes) * 8 / time_elapsed  # bits per second
            self.tx_rate = (self.tx_bytes - self.last_tx_bytes) * 8 / time_elapsed
            self.packet_in_rate = (self.rx_packets - self.last_rx_packets) / time_elapsed

# Ryu application class for SDN DDoS prevention
class SimpleSwitch13(app_manager.RyuApp):
    """
    A Ryu application implementing l2 switch with DDoS detection and mitigation
    
    Features:
    - MAC learning and forwarding
    - Rate limiting using OpenFlow meters
    - Protection against MAC flooding
    - Dynamic meter rate adjustment
    - Flow statistics tracking
    - Port statistics tracking
    - Adaptive Random Forest (ARF) for DDoS detection
    """
    # OpenFlow version supported
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the controller with default configurations."""
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        
        # Initialize data structures
        self.mac_to_port: Dict[int, Dict[str, int]] = {}
        self.port_stats: Dict[Tuple[int, int], PortStats] = defaultdict(PortStats)
        self.flow_stats: Dict[int, Dict[tuple, FlowStats]] = defaultdict(dict)
        self.datapaths: Dict[int, Any] = {} 
        
        # Configure logging
        self.logger = logging.getLogger('sdn_controller')
        self.logger.setLevel(logging.INFO)
        
        # Add console handler if not already present
        if not self.logger.handlers:
            ch = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            ch.setFormatter(formatter)
            self.logger.addHandler(ch)
        
        # Table IDs for the pipeline
        self.METER_TABLE_ID = 0  # Table 0: Apply rate limiting meter
        self.FORWARDING_TABLE_ID = 1  # Table 1: MAC learning and forwarding
        
        # Meter configuration
        self.METER_ID = 1
        self.DEFAULT_RATE = 1000000000  # 1Gbps default rate
        self.current_rate = self.DEFAULT_RATE
        
        self.logger.info("Controller initialized with default rate %d bytes/sec", self.DEFAULT_RATE)

        # Start monitoring thread for stats collection
        self.monitor_thread = None
        self.is_active = True
        self.monitor_thread = self.spawn(self._monitor_loop)

    def _monitor_loop(self) -> None:
        """Background thread to periodically request statistics."""
        while self.is_active:
            try:
                for dp in list(self.datapaths.values()):
                    self._request_port_stats(dp)
                    self._request_flow_stats(dp)
                time.sleep(STATS_INTERVAL)
            except Exception as e:
                self.logger.error(f"Error in monitor loop: {e}")

    def _request_port_stats(self, datapath) -> None:
        """Send port statistics request to the switch."""
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        # Request stats for all ports
        req = ofp_parser.OFPPortStatsRequest(datapath, 0, ofp.OFPP_ANY)
        datapath.send_msg(req)

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

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev) -> None:
        """Handle port statistics reply."""
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        current_time = time.time()
        
        for stat in body:
            port_no = stat.port_no
            port_key = (dpid, port_no)

            # Initialize port stats if not exists
            if port_key not in self.port_stats:
                self.port_stats[port_key] = PortStats()
            
            # Update port statistics
            port_stat = self.port_stats[port_key]
            port_stat.rx_packets = stat.rx_packets
            port_stat.tx_packets = stat.tx_packets
            port_stat.rx_bytes = stat.rx_bytes
            port_stat.tx_bytes = stat.tx_bytes
            port_stat.rx_dropped = stat.rx_dropped
            port_stat.tx_dropped = stat.tx_dropped
            port_stat.rx_errors = stat.rx_errors
            port_stat.tx_errors = stat.tx_errors
            port_stat.rx_frame_err = stat.rx_frame_err
            port_stat.rx_over_err = stat.rx_over_err
            port_stat.rx_crc_err = stat.rx_crc_err
            port_stat.collisions = stat.collisions
            port_stat.duration_sec = stat.duration_sec
            port_stat.duration_nsec = stat.duration_nsec
            
            # Update rates
            port_stat.update_rates(current_time)
            
            # Store previous values for rate calculation
            port_stat.last_rx_bytes = stat.rx_bytes
            port_stat.last_tx_bytes = stat.tx_bytes
            port_stat.last_rx_packets = stat.rx_packets
            port_stat.last_update = current_time
            
            # Detect potential DDoS
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev) -> None:
        """Handle flow statistics reply."""
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        
        for stat in body:
            # Extract flow key
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
    
    def _detect_ddos(self, dpid: int, port_no: int, port_stat: PortStats) -> None:
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
        self.datapaths[datapath.id] = datapath

        # Configure initial meter with default rate
        bands = [parser.OFPMeterBandDrop(type_=ofproto.OFPMBT_DROP, rate=self.DEFAULT_RATE, burst_size=0)]
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
            
            # Modify existing meter with new rate
            bands = [parser.OFPMeterBandDrop(
                type_=ofproto.OFPMBT_DROP, 
                rate=rate, 
                burst_size=0
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
                self.METER_ID, rate, 0, datapath.id
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

            mod = parser.OFPFlowMod(
                datapath=datapath,
                table_id=table_id,
                priority=priority,
                match=match,
                instructions=inst,
                hard_timeout=DEFAULT_FLOW_HARD_TIMEOUT,
                idle_timeout=DEFAULT_FLOW_IDLE_TIMEOUT,
                buffer_id=buffer_id if buffer_id != ofproto.OFP_NO_BUFFER else None
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

    # Handle switch disconnection event
    @set_ev_cls(ofp_event.EventOFPSwitchLeave, [MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER])
    def _handle_switch_leave(self, ev: ofp_event.EventOFPSwitchLeave) -> None:
        """Handle switch disconnection event."""
        if ev.datapath:
            self.logger.info("Switch %s disconnected", ev.datapath.id)
            # Clean up switch-specific state
            if ev.datapath.id in self.mac_to_port:
                del self.mac_to_port[ev.datapath.id]

    def _is_mac_flooding_attempt(self, dpid: int, port: int) -> bool:
        """Check if a port is attempting MAC flooding."""
        port_stats = self.port_stats.get((dpid, port))
        if port_stats and port_stats.mac_count > MAX_MAC_PER_PORT:
            self.logger.warning(
                "Possible MAC flooding on switch %s port %d: %d MACs learned",
                dpid, port, port_stats.mac_count
            )
            return True
        return False

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
            self.mac_to_port.setdefault(dpid, {})
            
            # Initialize port statistics
            port_key = (dpid, in_port)
            if port_key not in self.port_stats:
                self.port_stats[port_key] = PortStats()
            
            port_stat = self.port_stats[port_key]
            
            # Check for MAC flooding
            if src not in self.mac_to_port[dpid]:
                port_stat.mac_count += 1
                port_stat.last_seen = time.time()
                
                if self._is_mac_flooding_attempt(dpid, in_port):
                    self.logger.warning("Blocking potential MAC flooding from %s on port %d", src, in_port)
                    return

            self.logger.debug(
                "Packet in: switch=%s src=%s dst=%s in_port=%s", 
                dpid, src, dst, in_port
            )

            # Learn source MAC address
            self.mac_to_port[dpid][src] = in_port

            # Determine output port
            out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)

            # Install flow for known destinations in Table 1
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(eth_dst=dst)
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
        # TODO: Collect port stats (Packet Rate per Port) via OFPPortStatsRequest
        # TODO: Collect flow stats (Flow-Pkts/s, Flow-Dur) via OFPFlowStatsRequest
        # TODO: Feed stats into ARF model for attack classification
        # TODO: Call adjust_meter_rate with appropriate rate when attack detected
        # TODO: Call adjust_meter_rate with DEFAULT_RATE when attack mitigated
        pass

    # Note: eBPF filtering (Layer 1) will be implemented at the OVS kernel level 