#!/usr/bin/env python3
"""
Mininet Testing Scripts for SDN Controller with AI DDoS Detection
"""

# 1. Basic Mininet Topology Setup
# File: topology.py
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time

def create_test_topology():
    """Create a simple topology for testing DDoS detection."""
    
    # Create network
    net = Mininet(
        controller=RemoteController,
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=True
    )
    
    info('*** Adding controller\n')
    # Connect to your Ryu controller (default port 6633)
    c0 = net.addController('c0', controller=RemoteController, 
                          ip='127.0.0.1', port=6633)
    
    info('*** Adding switches\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    
    info('*** Adding hosts\n')
    # Legitimate hosts
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')
    h4 = net.addHost('h4', ip='10.0.0.4/24')
    
    # Attacker hosts
    attacker1 = net.addHost('attacker1', ip='10.0.0.10/24')
    attacker2 = net.addHost('attacker2', ip='10.0.0.11/24')
    attacker3 = net.addHost('attacker3', ip='10.0.0.12/24')
    
    # Target server
    server = net.addHost('server', ip='10.0.0.100/24')
    
    info('*** Creating links\n')
    # Connect all hosts to switch
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)
    net.addLink(attacker1, s1)
    net.addLink(attacker2, s1)
    net.addLink(attacker3, s1)
    net.addLink(server, s1)
    
    return net

def start_network():
    """Start the network and run tests."""
    setLogLevel('info')
    
    net = create_test_topology()
    
    info('*** Starting network\n')
    net.start()
    
    info('*** Testing connectivity\n')
    net.pingAll()
    
    info('*** Network ready for testing\n')
    print("Available hosts:")
    for host in net.hosts:
        print(f"  {host.name}: {host.IP()}")
    
    print("\nTo run DDoS tests, use the test scripts in separate terminals")
    print("Controller should be running on port 6633")
    
    info('*** Running CLI\n')
    CLI(net)
    
    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    start_network()

# =================================================================
# 2. Normal Traffic Generator
# File: normal_traffic.py

import subprocess
import time
import random
import threading
from datetime import datetime

class NormalTrafficGenerator:
    """Generate normal network traffic patterns."""
    
    def __init__(self):
        self.running = False
        self.threads = []
    
    def generate_web_traffic(self, src_host, dst_host, duration=60):
        """Generate HTTP-like traffic."""
        print(f"[{datetime.now()}] Starting web traffic: {src_host} -> {dst_host}")
        
        start_time = time.time()
        while self.running and (time.time() - start_time) < duration:
            try:
                # Simulate HTTP requests with varying sizes
                size = random.randint(100, 1500)  # Typical web request sizes
                cmd = f"mininet> {src_host} ping -c 1 -s {size} {dst_host} > /dev/null 2>&1"
                subprocess.run(cmd, shell=True, timeout=5)
                
                # Random intervals between requests (0.5-3 seconds)
                time.sleep(random.uniform(0.5, 3.0))
                
            except Exception as e:
                print(f"Error in web traffic: {e}")
                break
    
    def generate_file_transfer(self, src_host, dst_host, duration=30):
        """Generate file transfer-like traffic."""
        print(f"[{datetime.now()}] Starting file transfer: {src_host} -> {dst_host}")
        
        start_time = time.time()
        while self.running and (time.time() - start_time) < duration:
            try:
                # Simulate larger file transfers
                size = random.randint(1000, 8000)
                cmd = f"mininet> {src_host} ping -c 5 -s {size} {dst_host} > /dev/null 2>&1"
                subprocess.run(cmd, shell=True, timeout=10)
                
                # Longer intervals for file transfers
                time.sleep(random.uniform(2.0, 5.0))
                
            except Exception as e:
                print(f"Error in file transfer: {e}")
                break
    
    def start_normal_traffic(self, duration=300):
        """Start generating normal traffic patterns."""
        self.running = True
        
        # Define normal traffic patterns
        traffic_patterns = [
            ('h1', '10.0.0.100', 'web'),      # h1 -> server
            ('h2', '10.0.0.100', 'web'),      # h2 -> server  
            ('h3', '10.0.0.4', 'web'),        # h3 -> h4
            ('h4', '10.0.0.1', 'file'),       # h4 -> h1
            ('h1', '10.0.0.2', 'web'),        # h1 -> h2
        ]
        
        print(f"Starting normal traffic for {duration} seconds...")
        
        for src, dst, traffic_type in traffic_patterns:
            if traffic_type == 'web':
                thread = threading.Thread(
                    target=self.generate_web_traffic,
                    args=(src, dst, duration)
                )
            else:
                thread = threading.Thread(
                    target=self.generate_file_transfer,
                    args=(src, dst, duration)
                )
            
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
            time.sleep(1)  # Stagger start times
        
        # Wait for completion
        time.sleep(duration)
        self.stop_traffic()
    
    def stop_traffic(self):
        """Stop all traffic generation."""
        self.running = False
        print("Stopping normal traffic...")
        
        for thread in self.threads:
            thread.join(timeout=5)
        
        self.threads.clear()
        print("Normal traffic stopped.")

# =================================================================
# 3. DDoS Attack Simulator
# File: ddos_simulator.py

import subprocess
import threading
import time
import random
from datetime import datetime

class DDoSSimulator:
    """Simulate various types of DDoS attacks."""
    
    def __init__(self):
        self.running = False
        self.attack_threads = []
    
    def icmp_flood(self, attacker_host, target_ip, intensity='medium'):
        """Generate ICMP flood attack."""
        intensities = {
            'low': (0.01, 0.05),      # 0.01-0.05 second intervals
            'medium': (0.001, 0.01),   # 0.001-0.01 second intervals  
            'high': (0.0001, 0.001)    # Very fast
        }
        
        min_interval, max_interval = intensities.get(intensity, intensities['medium'])
        
        print(f"[{datetime.now()}] Starting ICMP flood: {attacker_host} -> {target_ip} ({intensity})")
        
        while self.running:
            try:
                # Send ICMP packets with random sizes
                size = random.randint(64, 1472)  # Standard ICMP payload sizes
                cmd = f"mininet> {attacker_host} ping -c 1 -s {size} -W 1 {target_ip} > /dev/null 2>&1"
                subprocess.run(cmd, shell=True, timeout=2)
                
                # Random interval based on intensity
                time.sleep(random.uniform(min_interval, max_interval))
                
            except Exception as e:
                if self.running:
                    print(f"Error in ICMP flood from {attacker_host}: {e}")
                break
    
    def tcp_syn_flood(self, attacker_host, target_ip, target_port=80, intensity='medium'):
        """Simulate TCP SYN flood using hping3 (if available)."""
        intensities = {
            'low': 10,
            'medium': 50, 
            'high': 200
        }
        
        rate = intensities.get(intensity, 50)
        
        print(f"[{datetime.now()}] Starting TCP SYN flood: {attacker_host} -> {target_ip}:{target_port}")
        
        while self.running:
            try:
                # Try using hping3 if available, otherwise fallback to ping flood
                cmd = f"mininet> {attacker_host} hping3 -S -p {target_port} -i u1000 -c {rate} {target_ip} > /dev/null 2>&1"
                result = subprocess.run(cmd, shell=True, timeout=5)
                
                if result.returncode != 0:
                    # Fallback to high-rate ping if hping3 not available
                    for _ in range(rate):
                        if not self.running:
                            break
                        cmd = f"mininet> {attacker_host} ping -c 1 -W 1 {target_ip} > /dev/null 2>&1"
                        subprocess.run(cmd, shell=True, timeout=1)
                        time.sleep(0.001)
                
            except Exception as e:
                if self.running:
                    print(f"Error in TCP SYN flood from {attacker_host}: {e}")
                break
            
            time.sleep(1)  # Brief pause between bursts
    
    def udp_flood(self, attacker_host, target_ip, intensity='medium'):
        """Generate UDP flood attack."""
        intensities = {
            'low': (0.01, 0.05),
            'medium': (0.001, 0.01),
            'high': (0.0001, 0.001)
        }
        
        min_interval, max_interval = intensities.get(intensity, intensities['medium'])
        
        print(f"[{datetime.now()}] Starting UDP flood: {attacker_host} -> {target_ip}")
        
        port = 53  # DNS port for UDP flood
        while self.running:
            try:
                # Use netcat for UDP flood if available
                cmd = f"mininet> {attacker_host} echo 'flood' | nc -u -w1 {target_ip} {port} > /dev/null 2>&1"
                subprocess.run(cmd, shell=True, timeout=2)
                
                time.sleep(random.uniform(min_interval, max_interval))
                
            except Exception as e:
                if self.running:
                    print(f"Error in UDP flood from {attacker_host}: {e}")
                break
    
    def start_coordinated_attack(self, attack_type='icmp', target_ip='10.0.0.100', 
                               duration=60, intensity='medium'):
        """Start coordinated DDoS attack from multiple attackers."""
        self.running = True
        
        attackers = ['attacker1', 'attacker2', 'attacker3']
        
        print(f"\n{'='*50}")
        print(f"Starting {attack_type.upper()} DDoS Attack")
        print(f"Target: {target_ip}")
        print(f"Duration: {duration} seconds")
        print(f"Intensity: {intensity}")
        print(f"Attackers: {attackers}")
        print(f"{'='*50}\n")
        
        for attacker in attackers:
            if attack_type == 'icmp':
                thread = threading.Thread(
                    target=self.icmp_flood,
                    args=(attacker, target_ip, intensity)
                )
            elif attack_type == 'tcp':
                thread = threading.Thread(
                    target=self.tcp_syn_flood,
                    args=(attacker, target_ip, 80, intensity)
                )
            elif attack_type == 'udp':
                thread = threading.Thread(
                    target=self.udp_flood,
                    args=(attacker, target_ip, intensity)
                )
            else:
                print(f"Unknown attack type: {attack_type}")
                continue
            
            thread.daemon = True
            thread.start()
            self.attack_threads.append(thread)
            time.sleep(0.5)  # Stagger attacker start times
        
        # Let attack run for specified duration
        time.sleep(duration)
        self.stop_attack()
    
    def stop_attack(self):
        """Stop all attack traffic."""
        self.running = False
        print("\nStopping DDoS attack...")
        
        for thread in self.attack_threads:
            thread.join(timeout=5)
        
        self.attack_threads.clear()
        print("DDoS attack stopped.\n")

# =================================================================
# 4. Main Test Controller
# File: test_controller.py

import time
import sys
from datetime import datetime

def main():
    """Main test controller for DDoS detection simulation."""
    
    print("SDN DDoS Detection Test Controller")
    print("=" * 40)
    
    if len(sys.argv) < 2:
        print("Usage: python test_controller.py <test_type>")
        print("\nAvailable tests:")
        print("  normal     - Generate normal traffic only")
        print("  ddos       - Generate DDoS attack")
        print("  mixed      - Generate normal traffic + DDoS attack")
        print("  sequence   - Run complete test sequence")
        return
    
    test_type = sys.argv[1].lower()
    
    # Initialize generators
    normal_gen = NormalTrafficGenerator()
    ddos_sim = DDoSSimulator()
    
    try:
        if test_type == 'normal':
            print("Generating normal traffic for 5 minutes...")
            normal_gen.start_normal_traffic(duration=300)
        
        elif test_type == 'ddos':
            attack_type = input("Attack type (icmp/tcp/udp) [icmp]: ").strip() or 'icmp'
            intensity = input("Intensity (low/medium/high) [medium]: ").strip() or 'medium'
            duration = int(input("Duration in seconds [60]: ").strip() or 60)
            
            ddos_sim.start_coordinated_attack(
                attack_type=attack_type,
                target_ip='10.0.0.100',
                duration=duration,
                intensity=intensity
            )
        
        elif test_type == 'mixed':
            print("Starting mixed traffic simulation...")
            
            # Start normal traffic in background
            import threading
            normal_thread = threading.Thread(
                target=normal_gen.start_normal_traffic,
                args=(180,)  # 3 minutes
            )
            normal_thread.daemon = True
            normal_thread.start()
            
            time.sleep(30)  # Let normal traffic establish
            
            # Start DDoS attack
            ddos_sim.start_coordinated_attack(
                attack_type='icmp',
                target_ip='10.0.0.100',
                duration=60,
                intensity='medium'
            )
            
            # Wait for normal traffic to finish
            normal_thread.join()
        
        elif test_type == 'sequence':
            run_full_test_sequence(normal_gen, ddos_sim)
        
        else:
            print(f"Unknown test type: {test_type}")
    
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
        normal_gen.stop_traffic()
        ddos_sim.stop_attack()
    
    except Exception as e:
        print(f"Error during test: {e}")

def run_full_test_sequence(normal_gen, ddos_sim):
    """Run complete test sequence to validate AI detection."""
    
    print("\n" + "="*60)
    print("FULL TEST SEQUENCE - AI DDoS DETECTION VALIDATION")
    print("="*60)
    
    # Phase 1: Normal traffic baseline (2 minutes)
    print(f"\n[{datetime.now()}] Phase 1: Establishing normal traffic baseline...")
    import threading
    normal_thread = threading.Thread(
        target=normal_gen.start_normal_traffic,
        args=(120,)
    )
    normal_thread.daemon = True
    normal_thread.start()
    time.sleep(120)
    
    # Phase 2: Low intensity attack (30 seconds)
    print(f"\n[{datetime.now()}] Phase 2: Low intensity ICMP flood...")
    ddos_sim.start_coordinated_attack('icmp', '10.0.0.100', 30, 'low')
    time.sleep(10)  # Recovery time
    
    # Phase 3: Medium intensity attack (45 seconds)
    print(f"\n[{datetime.now()}] Phase 3: Medium intensity ICMP flood...")
    ddos_sim.start_coordinated_attack('icmp', '10.0.0.100', 45, 'medium')
    time.sleep(10)  # Recovery time
    
    # Phase 4: High intensity attack (30 seconds)
    print(f"\n[{datetime.now()}] Phase 4: High intensity ICMP flood...")
    ddos_sim.start_coordinated_attack('icmp', '10.0.0.100', 30, 'high')
    time.sleep(10)  # Recovery time
    
    # Phase 5: TCP SYN flood (60 seconds)
    print(f"\n[{datetime.now()}] Phase 5: TCP SYN flood attack...")
    ddos_sim.start_coordinated_attack('tcp', '10.0.0.100', 60, 'medium')
    time.sleep(10)  # Recovery time
    
    # Phase 6: Mixed attack types (60 seconds)
    print(f"\n[{datetime.now()}] Phase 6: Mixed attack types...")
    # Start ICMP flood
    icmp_thread = threading.Thread(
        target=ddos_sim.start_coordinated_attack,
        args=('icmp', '10.0.0.100', 60, 'medium')
    )
    icmp_thread.daemon = True
    icmp_thread.start()
    
    time.sleep(20)  # Let ICMP establish
    
    # Add UDP flood
    ddos_sim.start_coordinated_attack('udp', '10.0.0.100', 40, 'medium')
    
    icmp_thread.join()
    
    print(f"\n[{datetime.now()}] Test sequence completed!")
    print("Check controller logs for AI detection results.")

if __name__ == '__main__':
    main()