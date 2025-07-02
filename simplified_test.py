#!/usr/bin/env python3
"""
Simplified Test Script for Quick DDoS Detection Validation
Run this after starting Mininet topology
"""

import subprocess
import time
import threading
import sys
from datetime import datetime

def run_command(cmd, timeout=5):
    """Run shell command with timeout."""
    try:
        result = subprocess.run(cmd, shell=True, timeout=timeout, 
                              capture_output=True, text=True)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False

def generate_normal_traffic(duration=30):
    """Generate light normal traffic."""
    print(f"[{datetime.now()}] Generating normal traffic...")
    
    start_time = time.time()
    while time.time() - start_time < duration:
        # Light ping traffic between hosts
        run_command("sudo mn -c > /dev/null 2>&1")  # Clean first
        run_command("echo 'h1 ping -c 1 10.0.0.100' | sudo mn --topo single,4 --controller remote")
        time.sleep(2)
        run_command("echo 'h2 ping -c 1 10.0.0.100' | sudo mn --topo single,4 --controller remote")
        time.sleep(2)

def generate_ddos_traffic(duration=60, intensity='high'):
    """Generate DDoS traffic using mininet."""
    print(f"[{datetime.now()}] Starting DDoS attack (intensity: {intensity})...")
    
    if intensity == 'high':
        interval = 0.1  # Very fast
        count = 10
    elif intensity == 'medium':
        interval = 0.5
        count = 5
    else:  # low
        interval = 1.0
        count = 2
    
    start_time = time.time()
    attack_commands = []
    
    # Prepare attack commands for multiple hosts
    for i in range(1, 4):  # h1, h2, h3 as attackers
        cmd = f"h{i} ping -f -c {count} 10.0.0.100 &"
        attack_commands.append(cmd)
    
    while time.time() - start_time < duration:
        for cmd in attack_commands:
            # Execute in mininet
            full_cmd = f"echo '{cmd}' | sudo mn --topo single,8 --controller remote,ip=127.0.0.1,port=6633"
            run_command(full_cmd, timeout=2)
        time.sleep(interval)
    
    print(f"[{datetime.now()}] DDoS attack completed")

def quick_validation_test():
    """Run quick validation test sequence."""
    print("="*60)
    print("QUICK DDoS DETECTION VALIDATION TEST")
    print("="*60)
    print("Make sure your Ryu controller is running on port 6633!")
    print()
    
    input("Press Enter when controller is ready...")
    
    try:
        # Phase 1: Baseline normal traffic (30 seconds)
        print("\nPhase 1: Normal traffic baseline (30 seconds)")
        generate_normal_traffic(30)
        
        print("\nWaiting 10 seconds...")
        time.sleep(10)
        
        # Phase 2: Medium DDoS attack (45 seconds)
        print("\nPhase 2: Medium intensity DDoS (45 seconds)")
        generate_ddos_traffic(45, 'medium')
        
        print("\nWaiting 15 seconds for recovery...")
        time.sleep(15)
        
        # Phase 3: High intensity DDoS (30 seconds)
        print("\nPhase 3: High intensity DDoS (30 seconds)")
        generate_ddos_traffic(30, 'high')
        
        print("\n" + "="*60)
        print("TEST COMPLETED!")
        print("Check your controller logs for:")
        print("1. DDoS detection messages")
        print("2. Rate limiting activation")
        print("3. AI model learning updates")
        print("="*60)
        
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
    except Exception as e:
        print(f"Test error: {e}")

def continuous_attack_test():
    """Continuous attack for extended testing."""
    print("Starting continuous DDoS attack...")
    print("Press Ctrl+C to stop")
    
    try:
        while True:
            generate_ddos_traffic(10, 'high')
            time.sleep(5)  # Brief pause
    except KeyboardInterrupt:
        print("Continuous attack stopped")

def main():
    if len(sys.argv) < 2:
        print("Usage: python simplified_test.py <mode>")
        print("Modes:")
        print("  quick     - Quick validation test")
        print("  normal    - Generate normal traffic only")
        print("  ddos      - Generate DDoS attack only")
        print("  continuous - Continuous DDoS for extended testing")
        return
    
    mode = sys.argv[1].lower()
    
    if mode == 'quick':
        quick_validation_test()
    elif mode == 'normal':
        duration = int(input("Duration in seconds [60]: ") or 60)
        generate_normal_traffic(duration)
    elif mode == 'ddos':
        intensity = input("Intensity (low/medium/high) [medium]: ").strip() or 'medium'
        duration = int(input("Duration in seconds [60]: ") or 60)
        generate_ddos_traffic(duration, intensity)
    elif mode == 'continuous':
        continuous_attack_test()
    else:
        print(f"Unknown mode: {mode}")

if __name__ == '__main__':
    main()