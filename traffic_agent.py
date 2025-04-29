import asyncio
import time
import json
import argparse
from collections import defaultdict, deque
from typing import Dict, Deque, Tuple, Any, List
from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP

FlowKey = Tuple[str, str, int, int, str]  # (src_ip, dst_ip, src_port, dst_port, protocol)

class TrafficAgent:
    """
    TrafficAgent sniffs packets on multiple switch interfaces,
    tracks flows globally across interfaces using a sliding window,
    and communicates flow reports to the GlobalViewAgent(controller)
    """
    def __init__(self, controller_host: str, controller_port: int, interfaces: List[str], dpids: List[str],  f_low: int = 2, f_high: int = 5, window_size: int = 5):
        self.start_time = time.time()
        self.controller_host = controller_host
        self.controller_port = controller_port
        self.interfaces = interfaces
        self.iface_dpid = dict(zip(interfaces, dpids))
        self.f_low = f_low
        self.f_high = f_high
        self.window_size = window_size
        # Track recent packet timestamps per flow (global across interfaces)
        self.flow_timestamps: Dict[FlowKey, Deque[float]] = defaultdict(deque)
        # Track actions taken for each flow ("allow", "drop", or "pending")
        self.flow_action: Dict[FlowKey, str] = {}
        # Async I/O (connection to GlobalViewAgent)
        self.writer: asyncio.StreamWriter = None
        self.reader: asyncio.StreamReader = None
        self._send_queue: asyncio.Queue = asyncio.Queue()
        # Sniffer flag to ensure we start only once
        self.sniffer_started = False

    async def start(self):
        # Connect (or reconnect) to the GlobalViewAgent via asyncio TCP
        while True:
            try:
                self.reader, self.writer = await asyncio.open_connection(self.controller_host, self.controller_port)
                print(f"[TrafficAgent] Connected to GlobalViewAgent at "
                      f"{self.controller_host}:{self.controller_port}")
                break
            except Exception as e:
                print(f"[TrafficAgent] Connection failed: {e}. Retrying in 5 seconds...")
                await asyncio.sleep(5)

        # Start send/receive loops to controller
        send_task = asyncio.create_task(self._send_loop())
        recv_task = asyncio.create_task(self._receive_loop())

        # Start sniffing on each interface (only once)
        if not self.sniffer_started:
            self.sniffer_started = True
            for iface in self.interfaces:
                print(f"[TrafficAgent] Sniffing on interface: {iface}")
                sniffer = AsyncSniffer(iface=iface, prn=lambda pkt, i=iface: self._packet_handler(pkt, i), store=False, filter="ip")
                sniffer.start()

        # Wait for either loop to exit (e.g., on connection loss)
        done, pending = await asyncio.wait([send_task, recv_task], return_when=asyncio.FIRST_EXCEPTION)
        for task in pending:
            task.cancel()

        # Clean up and attempt to reconnect
        self.writer.close()
        await self.writer.wait_closed()
        print("[TrafficAgent] Connection to GlobalViewAgent lost. Reconnecting...")
        await asyncio.sleep(1)
        await self.start()

    def _packet_handler(self, packet, iface: str):
        """Called for each sniffed packet to update flow statistics."""        
        if IP in packet:
            ip = packet[IP]
            if TCP in packet:
                l4 = packet[TCP]
                proto = "TCP"
                sport, dport = l4.sport, l4.dport
            elif UDP in packet:
                l4 = packet[UDP]
                proto = "UDP"
                sport, dport = l4.sport, l4.dport
            elif ICMP in packet:
                proto = "ICMP"
                sport, dport = 0, 0  # ICMP has no ports
            else:
                return  # Not TCP/UDP/ICMP

            flow = (ip.src, ip.dst, sport, dport, proto)
            dpid = self.iface_dpid.get(iface)
            if dpid is None:
                return  # Unknown interface
            self.process_new_flow(flow, dpid)

    def process_new_flow(self, flow: FlowKey, dpid: int):
        """
        Add the packet timestamp to the flow's sliding window,
        then classify and possibly take action on the flow.
        """
        timestamp = time.time()
        
        timestamps = self.flow_timestamps[flow]  # auto-inits deque via defaultdict
        timestamps.append(timestamp)
        # Remove timestamps older than the sliding window
        while timestamps and (timestamp - timestamps[0] > self.window_size):
            timestamps.popleft()
        count = len(timestamps)

        # Check if flow already has a final decision
        action = self.flow_action.get(flow)
        if action in ("allow", "drop"):
            return

        # Classification logic based on thresholds
        if count >= self.f_high:
            self.flow_action[flow] = "allow"
            self.enforce_decision(flow, "allow")
            self.report_flow_to_controller(flow, count, dpid, 'a')
        elif count <= self.f_low:
            self.flow_action[flow] = "drop"
            self.enforce_decision(flow, "drop")
            self.report_flow_to_controller(flow, count, dpid, 'd')
        else:
            # Flow is in the intermediate range-> report to controller if first time
            if action is None:
                self.flow_action[flow] = "pending"
                self.report_flow_to_controller(flow, count, dpid, 'p')

    def enforce_decision(self, flow: FlowKey, decision: str):
        """
        Enforce the decision locally
        simple log for now
        Add fw rules / iptable
        """
        print(f"[TrafficAgent] {decision.upper()} flow {flow}")

    def report_flow_to_controller(self, flow: FlowKey, count: int, dpid: int, state: int):
        """
        Send a flow report (with packet count) to the GlobalViewAgent.
        """
        if self.writer is None:
            return
        message = {
            "type": "flow_report",
            "dpid" : dpid,
            "flow": flow,
            "features": {"packet_count": count},
            "state": state
        }
        self._send_queue.put_nowait(message)

    async def _send_loop(self):
        """Continuously send messages from queue to GlobalViewAgent."""
        while True:
            message = await self._send_queue.get()
            data = json.dumps(message).encode()
            try:
                self.writer.write(len(data).to_bytes(4, 'big') + data)
                await self.writer.drain()
                print(f"[TrafficAgent] Sent: {message}")
            except Exception as e:
                print(f"[TrafficAgent] Send failed: {e}")
                break
            finally:
                self._send_queue.task_done()

    async def _receive_loop(self):
        """Continuously receive and handle messages from GlobalViewAgent."""
        while True:
            try:
                length_bytes = await self.reader.readexactly(4)
                length = int.from_bytes(length_bytes, 'big')
                data = await self.reader.readexactly(length)
                cmd = json.loads(data.decode())
                await self._handle_controller_message(cmd)
            except (asyncio.IncompleteReadError, ConnectionResetError):
                # Connection closed or reset by peer
                break
            except Exception as e:
                print(f"[TrafficAgent] Receive error: {e}")
                break

    async def _handle_controller_message(self, msg: Dict[str, Any]):
        """Process policies from GlobalViewAgent (allow drop or update thresholds)"""
        msg_type = msg.get("type")
        if msg_type == "decision":
            flow = tuple(msg["flow"])
            decision = msg["decision"]
            self.flow_action[flow] = decision
            self.enforce_decision(flow, decision)
        elif msg_type == "update_thresholds":
            self.f_low = msg.get("f_low", self.f_low)
            self.f_high = msg.get("f_high", self.f_high)
            print(f"[TrafficAgent] Updated thresholds: f_low={self.f_low}, f_high={self.f_high}")
        else:
            print(f"[TrafficAgent] Unknown message: {msg}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Distributed Traffic Agent')
    parser.add_argument('--controller-host', required=True)
    parser.add_argument('--controller-port', type=int, default=9000)
    parser.add_argument('--interfaces', nargs='+', required=True, help='List of switch-connected interfaces to sniff')
    parser.add_argument('--dpids', nargs='+', type=int, required=True, help='List of switch DPIDs corresponding to each interface')
    parser.add_argument('--f-low', type=int, default=2)
    parser.add_argument('--f-high', type=int, default=5)
    parser.add_argument('--window', type=int, default=5)
    args = parser.parse_args()

    if len(args.dpids) != len(args.interfaces):
        raise ValueError("Number of switch-ids must match number of interfaces")

    agent = TrafficAgent(
        controller_host=args.controller_host,
        controller_port=args.controller_port,
        interfaces=args.interfaces,
        dpids=args.dpids,
        f_low=args.f_low,
        f_high=args.f_high,
        window_size=args.window
    )
    asyncio.run(agent.start())
