#!/bin/bash
# Helper scripts for Mininet SDN simulation

# =================================================================
# 1. Setup Script
# File: setup.sh
#!/bin/bash

echo "Setting up SDN DDoS Detection Test Environment"
echo "=============================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Install required packages
echo "Installing required packages..."
apt-get update
apt-get install -y mininet openvswitch-switch python3-pip hping3 netcat-openbsd

# Install Python packages
echo "Installing Python packages..."
pip3 install ryu mininet pandas scikit-learn river joblib

# Create directories
echo "Creating project directories..."
mkdir -p ~/sdn_ddos_test/logs
mkdir -p ~/sdn_ddos_test/data
mkdir -p ~/sdn_ddos_test/scripts

# Set permissions
chown -R $SUDO_USER:$SUDO_USER ~/sdn_ddos_test/

echo "Setup completed successfully!"
echo ""
echo "Next steps:"
echo "1. Place your app.py in ~/sdn_ddos_test/"
echo "2. Place training data in ~/sdn_ddos_test/Training data/"
echo "3. Run: ./start_simulation.sh"

# =================================================================
# 2. Start Simulation Script  
# File: start_simulation.sh
#!/bin/bash

echo "Starting SDN DDoS Detection Simulation"
echo "====================================="

# Set environment variables
export PYTHONPATH=$PYTHONPATH:~/sdn_ddos_test

# Check if controller is already running
if pgrep -f "ryu-manager" > /dev/null; then
    echo "Stopping existing Ryu controller..."
    pkill -f "ryu-manager"
    sleep 2
fi

# Check if Mininet is running
if pgrep -f "mininet" > /dev/null; then
    echo "Cleaning up existing Mininet..."
    mn -c
    sleep 2
fi

# Start Ryu controller in background
echo "Starting Ryu controller..."
cd ~/sdn_ddos_test
ryu-manager app.py --verbose > logs/controller.log 2>&1 &
CONTROLLER_PID=$!

# Wait for controller to start
echo "Waiting for controller to initialize..."
sleep 5

# Check if controller started successfully
if ! kill -0 $CONTROLLER_PID 2>/dev/null; then
    echo "ERROR: Controller failed to start. Check logs/controller.log"
    exit 1
fi

echo "Controller started (PID: $CONTROLLER_PID)"

# Start Mininet topology
echo "Starting Mininet topology..."
python3 scripts/topology.py &
MININET_PID=$!

echo ""
echo "Simulation started successfully!"
echo "Controller PID: $CONTROLLER_PID"
echo "Mininet PID: $MININET_PID"
echo ""
echo "To run tests, open new terminals and use:"
echo "  python3 scripts/test_controller.py normal"
echo "  python3 scripts/test_controller.py ddos"
echo "  python3 scripts/test_controller.py sequence"
echo ""
echo "To monitor: tail -f logs/controller.log"
echo "To stop: ./stop_simulation.sh"

# =================================================================
# 3. Stop Simulation Script
# File: stop_simulation.sh
#!/bin/bash

echo "Stopping SDN DDoS Detection Simulation"
echo "======================================"

# Kill Ryu controller
echo "Stopping Ryu controller..."
pkill -f "ryu-manager"

# Clean up Mininet
echo "Cleaning up Mininet..."
mn -c

# Kill any remaining processes
pkill -f "topology.py"
pkill -f "test_controller.py"

echo "Simulation stopped successfully!"

# =================================================================
# 4. Monitor Script
# File: monitor.sh
#!/bin/bash

echo "SDN DDoS Detection Monitor"
echo "========================="

# Function to show real-time logs
show_logs() {
    echo "Controller logs:"
    echo "---------------"
    tail -f ~/sdn_ddos_test/logs/controller.log
}

# Function to show network status
show_network() {
    echo "Network Status:"
    echo "--------------"
    echo "OpenFlow switches:"
    ovs-vsctl show
    echo ""
    echo "Active flows:"
    ovs-ofctl -O OpenFlow13 dump-flows s1
}

# Function to show system resources
show_resources() {
    echo "System Resources:"
    echo "----------------"
    echo "CPU Usage:"
    top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//'
    echo ""
    echo "Memory Usage:"
    free -h
    echo ""
    echo "Network Interfaces:"
    ip addr show | grep -E "(inet|mtu)"
}

# Main menu
while true; do
    echo ""
    echo "Choose monitoring option:"
    echo "1. Show real-time controller logs"
    echo "2. Show network status"
    echo "3. Show system resources"
    echo "4. Exit"
    echo ""
    read -p "Enter choice [1-4]: " choice

    case $choice in
        1) show_logs ;;
        2) show_network ;;
        3) show_resources ;;
        4) echo "Exiting monitor..."; exit 0 ;;
        *) echo "Invalid choice" ;;
    esac
    
    if [ "$choice" != "1" ]; then
        read -p "Press Enter to continue..."
    fi
done

# =================================================================
# 5. Quick Test Script
# File: quick_test.sh
#!/bin/bash

echo "Quick DDoS Detection Test"
echo "========================"

# Check if simulation is running
if ! pgrep -f "ryu-manager" > /dev/null; then
    echo "ERROR: Controller not running. Start with ./start_simulation.sh"
    exit 1
fi

if ! pgrep -f "topology.py" > /dev/null; then
    echo "ERROR: Mininet not running. Start with ./start_simulation.sh"
    exit 1
fi

echo "Running quick test sequence..."

# 1. Generate normal traffic for 30 seconds
echo "Step 1: Generating normal traffic (30s)..."
python3 ~/sdn_ddos_test/scripts/test_controller.py normal &
NORMAL_PID=$!
sleep 30
kill $NORMAL_PID 2>/dev/null

echo "Step 2: Waiting 10 seconds..."
sleep 10

# 2. Generate DDoS attack for 30 seconds  
echo "Step 3: Launching DDoS attack (30s)..."
python3 ~/sdn_ddos_test/scripts/test_controller.py ddos <<< $'icmp\nmedium\n30' &
DDOS_PID=$!
sleep 35
kill $DDOS_PID 2>/dev/null

echo "Step 4: Test completed!"
echo ""
echo "Check the controller logs for AI detection results:"
echo "tail -n 50 ~/sdn_ddos_test/logs/controller.log | grep -i ddos"

# =================================================================
# 6. Log Analysis Script
# File: analyze_logs.sh
#!/bin/bash

LOG_FILE="~/sdn_ddos_test/logs/controller.log"

echo "SDN Controller Log Analysis"
echo "=========================="

if [ ! -f "$LOG_FILE" ]; then
    echo "Log file not found: $LOG_FILE"
    exit 1
fi

echo "1. DDoS Detection Events:"
echo "------------------------"
grep -i "ddos.*detected" "$LOG_FILE" | tail -10

echo ""
echo "2. Mitigation Actions:"
echo "---------------------"
grep -i "rate limiting\|mitigation" "$LOG_FILE" | tail -10

echo ""
echo "3. Flow Statistics:"
echo "------------------"
grep -i "analyzing.*flows" "$LOG_FILE" | tail -5

echo ""
echo "4. AI Model Performance:"
echo "-----------------------"
grep -i "warmup\|accuracy\|probability" "$LOG_FILE" | tail -5

echo ""
echo "5. Recent Errors:"
echo "----------------"
grep -i "error\|exception" "$LOG_FILE" | tail -5

echo ""
echo "6. Traffic Summary (last 100 lines):"
echo "------------------------------------"
tail -100 "$LOG_FILE" | grep -c "packet in"
echo "Packet-in events in last 100 log lines"

# =================================================================
# 7. Performance Test Script
# File: performance_test.sh
#!/bin/bash

echo "SDN Controller Performance Test"
echo "=============================="

# Test different attack intensities and measure response
RESULTS_FILE="~/sdn_ddos_test/performance_results.txt"
echo "Performance Test Results - $(date)" > "$RESULTS_FILE"
echo "=================================" >> "$RESULTS_FILE"

test_attack() {
    local attack_type=$1
    local intensity=$2
    local duration=$3
    
    echo "Testing $attack_type attack at $intensity intensity..."
    
    # Record start time
    start_time=$(date +%s)
    
    # Launch attack
    python3 ~/sdn_ddos_test/scripts/test_controller.py ddos <<< "$attack_type
$intensity
$duration" > /dev/null 2>&1 &
    
    attack_pid=$!
    
    # Monitor for detection
    timeout=60
    detected=false
    
    for ((i=1; i<=timeout; i++)); do
        if grep -q "DDoS.*detected" ~/sdn_ddos_test/logs/controller.log; then
            detection_time=$(($(date +%s) - start_time))
            detected=true
            break
        fi
        sleep 1
    done
    
    # Clean up
    kill $attack_pid 2>/dev/null
    wait $attack_pid 2>/dev/null
    
    # Record results
    if [ "$detected" = true ]; then
        echo "$attack_type,$intensity,$duration,DETECTED,$detection_time" >> "$RESULTS_FILE"
        echo "  ✓ Detected in ${detection_time}s"
    else
        echo "$attack_type,$intensity,$duration,NOT_DETECTED,N/A" >> "$RESULTS_FILE"
        echo "  ✗ Not detected within ${timeout}s"
    fi
    
    sleep 10  # Recovery time between tests
}

# Run performance tests
echo "Attack,Intensity,Duration,Result,DetectionTime" >> "$RESULTS_FILE"

test_attack "icmp" "low" "30"
test_attack "icmp" "medium" "30"  
test_attack "icmp" "high" "30"
test_attack "tcp" "medium" "30"
test_attack "udp" "medium" "30"

echo ""
echo "Performance test completed!"
echo "Results saved to: $RESULTS_FILE"
cat "$RESULTS_FILE"