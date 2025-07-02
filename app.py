from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, in_proto, ipv4, icmp, tcp, udp
import logging
from ryu.lib import hub
from typing import Dict, Optional, Any, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import time
from threading import Lock

from river.forest import ARFClassifier
from river import metrics, stream, compose
from river.drift import ADWIN
from river.preprocessing import StandardScaler
import pandas as pd


# Global constants
DEFAULT_FLOW_IDLE_TIMEOUT = 60
DEFAULT_FLOW_HARD_TIMEOUT = 300
STATS_INTERVAL = 5
WINDOW_SIZE = 5

@dataclass
class FlowStats:
    """Original flow stats class."""
    packet_count: int = 0
    byte_count: int = 0
    duration_sec: int = 0
    start_time: float = field(default_factory=time.time)
    last_update: float = field(default_factory=time.time)
    is_active: bool = True

    def update(self, pkt_count: int, byte_count: int, duration: int) -> None:
        self.packet_count = pkt_count
        self.byte_count = byte_count
        self.duration_sec = duration
        self.last_update = time.time()
        self.is_active = True

@dataclass
class FlowFeatures:
    """Enhanced flow statistics for AI model features."""
    # Forward direction (A->B)
    fwd_packet_count: int = 0
    fwd_byte_count: int = 0
    
    # Backward direction (B->A) 
    bwd_packet_count: int = 0
    bwd_byte_count: int = 0
    
    # Timing
    start_time: float = field(default_factory=time.time)
    last_update: float = field(default_factory=time.time)
    duration_sec: float = 0.0
    
    # Protocol 
    protocol: int = 0

    # Ports  (optional for now)
    src_port: int = 0
    dst_port: int = 0
    
    # IP addresses (optional for now)
    src_ip: str = ""
    dst_ip: str = ""
    
    def update_forward(self, pkt_count: int, byte_count: int, duration: float) -> None:
        """Update forward direction stats (A->B)."""
        self.fwd_packet_count = pkt_count
        self.fwd_byte_count = byte_count
        self.duration_sec = duration
        self.last_update = time.time()
    
    def update_backward(self, pkt_count: int, byte_count: int, duration: float) -> None:
        """Update backward direction stats (B->A)."""
        self.bwd_packet_count = pkt_count
        self.bwd_byte_count = byte_count
        self.duration_sec = max(self.duration_sec, duration)
        self.last_update = time.time()
    
    @property
    def tot_fwd_pkts(self) -> int:
        return self.fwd_packet_count
    
    @property
    def tot_bwd_pkts(self) -> int:
        return self.bwd_packet_count
    
    @property
    def totlen_fwd_pkts(self) -> int:
        return self.fwd_byte_count
    
    @property
    def totlen_bwd_pkts(self) -> int:
        return self.bwd_byte_count
    
    @property
    def flow_byts_per_sec(self) -> float:
        if self.duration_sec <= 0:
            return 0.0
        total_bytes = self.fwd_byte_count + self.bwd_byte_count
        return total_bytes / self.duration_sec
    
    @property
    def flow_pkts_per_sec(self) -> float:
        if self.duration_sec <= 0:
            return 0.0
        total_packets = self.fwd_packet_count + self.bwd_packet_count
        return total_packets / self.duration_sec
    
    @property
    def flow_duration(self) -> float:
        return self.duration_sec
    
    def get_protocol_name(self) -> str:
        protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        return protocol_map.get(self.protocol, f'PROTO_{self.protocol}')

class FlowFeatureTracker:
    """Tracks bidirectional flow features for AI model."""
    
    def __init__(self):
        self.flow_features: Dict[int, Dict[Tuple, FlowFeatures]] = defaultdict(dict)
        self.logger = logging.getLogger('flow_tracker')
        
    def _get_conversation_key(self, flow_key: Tuple) -> Tuple:
        """Convert flow key to bidirectional conversation key."""
        eth_src, eth_dst, ip_proto, src_port, dst_port = flow_key
        
        # Create normalized conversation key (lexicographically ordered)
        if (eth_src, src_port) < (eth_dst, dst_port):
            return (eth_src, eth_dst, ip_proto, src_port, dst_port)
        else:
            return (eth_dst, eth_src, ip_proto, dst_port, src_port)
    
    def _get_flow_direction(self, flow_key: Tuple, conv_key: Tuple) -> str:
        """Determine if this flow is forward or backward direction."""
        eth_src, eth_dst, _, src_port, dst_port = flow_key
        conv_src, conv_dst, _, conv_src_port, conv_dst_port = conv_key
        
        if (eth_src == conv_src and eth_dst == conv_dst and 
            src_port == conv_src_port and dst_port == conv_dst_port):
            return 'forward'
        else:
            return 'backward'
    
    def update_flow_stats(self, dpid: int, flow_key: Tuple, 
                         pkt_count: int, byte_count: int, duration: float,
                         src_ip: str = "", dst_ip: str = "") -> None:
        """Update flow statistics and calculate features."""
        conv_key = self._get_conversation_key(flow_key)
        direction = self._get_flow_direction(flow_key, conv_key)
        
        # Initialize flow features if not exists
        if conv_key not in self.flow_features[dpid]:
            self.flow_features[dpid][conv_key] = FlowFeatures()
            feature = self.flow_features[dpid][conv_key]
            feature.protocol = flow_key[2]
            feature.src_port = flow_key[3]
            feature.dst_port = flow_key[4]
            feature.src_ip = src_ip
            feature.dst_ip = dst_ip
        
        # Update appropriate direction
        flow_feature = self.flow_features[dpid][conv_key]
        if direction == 'forward':
            flow_feature.update_forward(pkt_count, byte_count, duration)
        else:
            flow_feature.update_backward(pkt_count, byte_count, duration)
    
    def extract_features_for_ai(self, dpid: int, min_duration: float = 1.0) -> list:
        """Extract features in format ready for AI model."""
        features = []
        now = time.time()
        
        for conv_key, flow_feat in self.flow_features.get(dpid, {}).items():
            # Only include flows with sufficient duration and skip very old flows (> 5min)
            if flow_feat.duration_sec < min_duration or now - flow_feat.last_update > 300:
                continue
            
            # Extract features matching the model's expected format
            feature_vector = {
                'Tot Fwd Pkts': float(flow_feat.tot_fwd_pkts),
                'Tot Bwd Pkts': float(flow_feat.tot_bwd_pkts), 
                'TotLen Fwd Pkts': float(flow_feat.totlen_fwd_pkts),
                'Flow Byts/s': float(flow_feat.flow_byts_per_sec),
                'Flow Pkts/s': float(flow_feat.flow_pkts_per_sec),
                'Protocol': float(flow_feat.protocol),
                'Flow Duration': float(flow_feat.flow_duration),
                'conversation_key': conv_key  # Keep this for logging
            }
            features.append(feature_vector)
        
        return features
    
    def cleanup_old_flows(self, max_age: int = 600) -> None:
        """Remove flows older than max_age seconds."""
        now = time.time()
        for dpid in list(self.flow_features.keys()):
            for conv_key in list(self.flow_features[dpid].keys()):
                flow_feat = self.flow_features[dpid][conv_key]
                if now - flow_feat.last_update > max_age:
                    del self.flow_features[dpid][conv_key]

class SimpleSwitch13(app_manager.RyuApp):
    """Enhanced SDN controller with AI-ready flow feature extraction."""
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        
        # Original data structures
        self.mac_to_port: Dict[int, Dict[str, int]] = {} # [dpid][mac] = port
        self.mac_to_port_lock = Lock()
        self.flow_stats: Dict[int, Dict[tuple, FlowStats]] = defaultdict(dict) # [dpid][(src_ip, dst_ip, src_port, dst_port)] = FlowStats
        self.flow_stats_lock = Lock()
        self.datapaths: Dict[int, Any] = {} # [dpid] = datapath object
        self.datapaths_lock = Lock()
        
        # AI feature tracker
        self.feature_tracker = FlowFeatureTracker() # Tracks bidirectional flow features
        # Init ARF River model
        self.ai_model = self.get_pipeline()
        self._warmup_model()  # Pre-train on small dataset
        # Define feature order as in training
        self.model_features = [
            'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts',
            'Flow Byts/s', 'Flow Pkts/s', 'Protocol', 'Flow Duration'
        ]

        # Toggle mitigation
        self.mitigation_enabled = False
        
        # Logging setup
        self.logger = logging.getLogger('sdn_controller')
        self.logger.setLevel(logging.INFO)
        
        if not self.logger.handlers:
            ch = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            ch.setFormatter(formatter)
            self.logger.addHandler(ch)
        
        # OpenFlow pipeline configuration
        self.METER_TABLE_ID = 0
        self.FORWARDING_TABLE_ID = 1
        self.METER_ID = 1
        self.DEFAULT_RATE = 1000000000  # 1Gbps
        self.current_rate = self.DEFAULT_RATE
        
        # Mitigation rate
        self.MITIGATION_RATE = 100000000  # 100Mbps
        
        self.logger.info(f"Controller initialized with default rate {self.DEFAULT_RATE} bytes/sec")

        # Start monitoring threads
        self.is_active = True
        self.monitor_thread = hub.spawn(self._monitor_loop)
        self.ai_thread = hub.spawn(self._ai_detection_loop)

    def _monitor_loop(self) -> None:
        """Background thread to periodically request flow statistics."""
        while self.is_active:
            with self.datapaths_lock:
                datapaths = list(self.datapaths.values())
            
            for dp in datapaths:
                try:
                    self._request_flow_stats(dp)
                except Exception as e:
                    self.logger.error(f"Error requesting stats for datapath {dp.id}: {e}")
            
            # Cleanup old flows every 10 cycles
            if hasattr(self, '_cleanup_counter'):
                self._cleanup_counter += 1
            else:
                self._cleanup_counter = 0
                
            if self._cleanup_counter >= 10:
                self.feature_tracker.cleanup_old_flows()
                self._cleanup_counter = 0
                
            hub.sleep(STATS_INTERVAL)

    def _ai_detection_loop(self) -> None:
        """Background thread for AI-based DDoS detection."""
        while self.is_active:
            try:
                self._run_ai_detection()
            except Exception as e:
                self.logger.error(f"Error in AI detection: {e}")
            hub.sleep(STATS_INTERVAL * 2)  # Run less frequently (10s)

    def _run_ai_detection(self) -> None:
        """Run DDoS detection on all switches."""
        with self.datapaths_lock:
            dpids = list(self.datapaths.keys())
        
        for dpid in dpids:
            features = self.feature_tracker.extract_features_for_ai(dpid)
            
            if not features:  # No flows to analyze
                continue
                
            self.logger.debug(f"Analyzing {len(features)} flows on switch {dpid}")
            
            for feature_dict in features:
                if self._detect_ddos(feature_dict):
                    conv_key = feature_dict.get('conversation_key', 'unknown')
                    self.logger.warning(f"DDoS detected on switch {dpid}: {conv_key}")
                    self._mitigate_attack(dpid)
                    break  # Only mitigate once per detection cycle

    def get_pipeline(self) -> Any:
        # Initialize online pipeline with ARFClassifier
        return compose.Pipeline(
            StandardScaler(),    # online scaling
            ARFClassifier(
            n_models=20, # Reduced for simulation
            drift_detector=ADWIN(0.001),
            warning_detector=ADWIN(0.005),
            metric=metrics.Recall(),
            disable_weighted_vote=False,
            split_criterion="gini",
            leaf_prediction="nb",
            max_depth=10,  
            seed=42
        )
    )
    
    def _warmup_model(self) -> None:
        """Warm up the AI model with a small dataset."""
        try:
            # Load training data
            warmup_data = pd.read_csv('Training data/resampled_dataset1.csv')
            
            # Select only the features that match our model
            feature_columns = [
                'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
                'Flow Byts/s', 'Flow Pkts/s', 'Protocol', 'Flow Duration'
            ]
            
            # Check if columns exist in dataset
            available_columns = [col for col in feature_columns if col in warmup_data.columns]
            if len(available_columns) < len(feature_columns):
                self.logger.warning(f"Missing columns in training data: {set(feature_columns) - set(available_columns)}")
                feature_columns = available_columns
            
            X = warmup_data[feature_columns]
            y = warmup_data['Label']
            
            # Take a smaller sample for warmup (first 1000 rows)
            sample_size = min(1000, len(X))
            X_sample = X.head(sample_size)
            y_sample = y.head(sample_size)
            
            # Initialize metrics
            acc = metrics.Accuracy()
            
            warmup_count = 0
            # Iterate over the dataset
            for xi, yi in stream.iter_pandas(X_sample, y_sample, shuffle=True, seed=1):
                # Convert to float to ensure compatibility
                xi_clean = {k: float(v) for k, v in xi.items()}
                
                # Predict the new sample
                yi_pred = self.ai_model.predict_one(xi_clean)
                if yi_pred is not None:
                    acc.update(yi, yi_pred)
                
                # Learn from the new sample
                self.ai_model.learn_one(xi_clean, yi)
                warmup_count += 1
            
            # Update model features list
            self.model_features = feature_columns
            
            # Log warmup results
            self.logger.info(f"Warmup completed with {warmup_count} samples. Accuracy: {acc.get() * 100:.2f}%")
            
        except Exception as e:
            self.logger.error(f"Error during model warmup: {e}")
            # Create a simple fallback model if warmup fails
            # self.logger.info("Using fallback model initialization")

    def _detect_ddos(self, features: dict) -> bool:
        """AI-based DDoS detection using Adaptive Random Forest."""
        try:
            # Remove non-feature keys
            feature_vector = {k: v for k, v in features.items() if k != 'conversation_key'}
            
            # Ensure all features are present and convert to float
            clean_features = {}
            for feature in self.model_features:
                if feature in feature_vector:
                    clean_features[feature] = float(feature_vector[feature])
                else:
                    clean_features[feature] = 0.0  # Default value for missing features
            
            # Get prediction probabilities
            proba = self.ai_model.predict_proba_one(clean_features)
            
            # Check if probabilities are returned
            if proba is None or len(proba) == 0:
                return False
            
            # Check probability of DDoS class (assuming 0 = DDoS, 1 = Normal)
            ddos_prob = proba.get(0, 0.0)
            normal_prob = proba.get(1, 0.0)
            
            self.logger.debug(f"DDoS probability: {ddos_prob:.3f}, Normal probability: {normal_prob:.3f}")
            
            # Detect DDoS if probability > threshold
            if ddos_prob > 0.6:  # Lowered threshold for simulation
                self.logger.warning(f"DDoS attack detected! DDoS probability: {ddos_prob:.3f}")
                # Online learning - update model with detected attack
                self.ai_model.learn_one(clean_features, 0)  # 0 = DDoS
                return True
            else:
                # Learn from normal traffic
                self.ai_model.learn_one(clean_features, 1)  # 1 = Normal
                return False
                
        except Exception as e:
            self.logger.error(f"Error during DDoS detection: {e}")
            return False
    
    def _mitigate_attack(self, dpid: int) -> None:
        """Mitigate detected DDoS attack."""
        if not self.mitigation_enabled:
            self.logger.info("Mitigation is disabled, DDoS detected but no action taken")
            return
            
        with self.datapaths_lock:
            datapath = self.datapaths.get(dpid)
        
        if datapath and self.current_rate > self.MITIGATION_RATE:
            success = self.update_meter_rate(datapath, self.MITIGATION_RATE)
            if success:
                self.logger.info(f"Applied rate limiting ({self.MITIGATION_RATE} bytes/sec) on switch {dpid}")
                # Optionally restore rate after some time
                hub.spawn_after(30, self._restore_normal_rate, datapath)  # Restore after 30 seconds

    def _restore_normal_rate(self, datapath) -> None:
        """Restore normal rate after mitigation period."""
        success = self.update_meter_rate(datapath, self.DEFAULT_RATE)
        if success:
            self.logger.info(f"Restored normal rate ({self.DEFAULT_RATE} bytes/sec) on switch {datapath.id}")


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


    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev) -> None:
        """Handle flow statistics reply from switch."""
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        
        with self.flow_stats_lock:
            for stat in body:
                flow_key = self._get_flow_key_from_stats(stat)
                if not flow_key:
                    continue
                    
                # Update original flow statistics
                if dpid not in self.flow_stats:
                    self.flow_stats[dpid] = {}
                    
                if flow_key not in self.flow_stats[dpid]:
                    self.flow_stats[dpid][flow_key] = FlowStats()
                    
                flow_stat = self.flow_stats[dpid][flow_key]
                flow_stat.update(stat.packet_count, stat.byte_count, stat.duration_sec)
                
                # Update AI feature tracker
                # Extract IP addresses if available
                src_ip = stat.match.get('ipv4_src', '')
                dst_ip = stat.match.get('ipv4_dst', '')
                self.feature_tracker.update_flow_stats(
                    dpid, flow_key,
                    stat.packet_count,
                    stat.byte_count,
                    float(stat.duration_sec),
                    src_ip, dst_ip
                )

    def _get_flow_key_from_stats(self, stat) -> Optional[tuple]:
        """Extract flow key from flow stats."""
        try:
            eth_src = stat.match.get('eth_src', '00:00:00:00:00:00')
            eth_dst = stat.match.get('eth_dst', '00:00:00:00:00:00')
            ip_proto = stat.match.get('ip_proto', 0)
            src_port = stat.match.get('tcp_src') or stat.match.get('udp_src') or 0
            dst_port = stat.match.get('tcp_dst') or stat.match.get('udp_dst') or 0
            
            return (eth_src, eth_dst, ip_proto, src_port, dst_port)
        except Exception as e:
            self.logger.error(f"Error extracting flow key: {e}")
            return None


    def update_meter_rate(self, datapath: Any, rate: int) -> bool:
        """Dynamically adjust the meter rate."""
        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            # Convert bytes/sec to kbps and ensure minimum values
            rate_kbps = max(1, int((rate * 8) / 1000))
            burst_kbps = max(15, int(rate_kbps * 0.1))  # 10% of rate

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
            self.logger.info(f"Updated meter rate to {rate_kbps} kbps on switch {datapath.id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update meter rate: {e}")
            return False

    def stop(self):
        """Clean shutdown."""
        self.is_active = False
        hub.joinall([self.monitor_thread, self.ai_thread])
        super(SimpleSwitch13, self).stop()
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection and initialize flow tables."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        with self.datapaths_lock:
            self.datapaths[datapath.id] = datapath

        # Configure meter
        burst_size = max(15000, int(self.DEFAULT_RATE * 0.01))
        if self.DEFAULT_RATE == 0:
            burst_size = 0
        bands = [parser.OFPMeterBandDrop(type_=ofproto.OFPMBT_DROP, 
                                        rate=self.DEFAULT_RATE, burst_size=burst_size)]
        req = parser.OFPMeterMod(datapath, command=ofproto.OFPMC_ADD, 
                                meter_id=self.METER_ID, bands=bands)
        datapath.send_msg(req)

        # Install flows
        match = parser.OFPMatch()
        instructions = [
            parser.OFPInstructionMeter(self.METER_ID),
            parser.OFPInstructionGotoTable(self.FORWARDING_TABLE_ID)
        ]
        mod = parser.OFPFlowMod(datapath, table_id=self.METER_TABLE_ID, 
                               priority=0, match=match, instructions=instructions)
        datapath.send_msg(mod)

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath, table_id=self.FORWARDING_TABLE_ID, 
                               priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)

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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev: ofp_event.EventOFPPacketIn) -> None:
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

    def _add_flow(self, datapath, table_id, priority, match, actions, buffer_id=None, instructions=None):
        """Add flow entry to switch."""
        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            inst = []
            if instructions:
                inst.extend(instructions)
            if actions:
                inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions))
            
            if buffer_id is None:
                buffer_id = ofproto.OFP_NO_BUFFER

            mod = parser.OFPFlowMod(
                datapath=datapath, table_id=table_id, priority=priority,
                match=match, instructions=inst,
                hard_timeout=DEFAULT_FLOW_HARD_TIMEOUT,
                idle_timeout=DEFAULT_FLOW_IDLE_TIMEOUT,
                buffer_id=buffer_id
            )
            
            datapath.send_msg(mod)
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add flow: {e}")
            return False
