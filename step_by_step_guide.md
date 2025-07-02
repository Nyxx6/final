# SDN DDoS Detection - Quick Execution Guide

## Prerequisites Setup (5 minutes)

```bash
# Install dependencies
sudo apt update
sudo apt install mininet python3-pip
pip3 install ryu river scikit-learn pandas numpy

# Create training data directory
mkdir -p "Training data"
```

## Step 1: Prepare Training Data (2 minutes)

Create a minimal training dataset:

```bash
cat > "Training data/resampled_dataset1.csv" << 'EOF'
Tot Fwd Pkts,Tot Bwd Pkts,TotLen Fwd Pkts,TotLen Bwd Pkts,Flow Byts/s,Flow Pkts/s,Protocol,Flow Duration,Label
5,2,500,200,350.0,3.5,6,2.0,1
10,5,1000,500,750.0,7.5,6,2.0,1
15,8,1500,800,1150.0,11.5,6,2.0,1
100,20,15000,3000,9000.0,60.0,1,2.0,0
200,50,30000,7500,18750.0,125.0,1,2.0,0
500,100,75000,15000,45000.0,300.0,1,2.0,0
1000,200,150000,30000,90000.0,600.0,1,2.0,0
EOF
```

## Step 2: Apply Critical Fixes to app.py

Apply these fixes to your controller:

1. **Enable mitigation** (line ~137):
```python
self.mitigation_enabled = True
```

2. **Fix model features** (line ~140):
```python
self.model_features = [
    'Tot Fwd Pkts', 'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
    'Flow Byts/s', 'Flow Pkts/s', 'Protocol', 'Flow Duration'
]
```

3. **Lower detection threshold** (in `_detect_ddos` method):
```python
threshold = 0.5  # Instead of 0.7
```

## Step 3: Start Controller (Terminal 1)

```bash
# Start Ryu controller
ryu-manager app.py --verbose
```

## Step 4: Start Mininet Topology (Terminal 2)

```bash
# Simple topology
sudo mn --topo single,8 --controller remote,ip=127.0.0.1,port=6633 --switch ovsk,protocols=OpenFlow13

# In mininet CLI, test connectivity:
mininet> pingall
mininet> h1 ping -c 3 h8
```

## Step 5: Generate Traffic (Terminal 3)

### Option A: Quick Test (5 minutes)
```bash
# Normal traffic (30 seconds)
echo "Starting normal traffic..."
for i in {1..30}; do
    echo "h1 ping -c 1 h8" | sudo mn --topo single,8 --controller remote,ip=127.0.0.1,port=6633
    sleep 1
done

# DDoS attack (60 seconds)
echo "Starting DDoS attack..."
for i in {1..60}; do
    echo "h1 ping -f -c 10 h8 &" | sudo mn --topo single,8 --controller remote,ip=127.0.0.1,port=6633
    echo "h2 ping -f -c 10 h8 &" | sudo mn --topo single,8 --controller remote,ip=127.0.0.1,port=6633
    echo "h3 ping -f -c 10 h8 &" | sudo mn --topo single,8 --controller remote,ip=127.0.0.1,port=6633
    sleep 0.5
done
```

### Option B: Use Mininet CLI
In mininet CLI:
```bash
# Normal traffic
h1 ping -c 5 h8
h2 ping -c 5 h8

# DDoS simulation
h1 ping -f h8 &
h2 ping -f h8 &
h3 ping -f h8 &

# Stop attacks
jobs
kill %1 %2 %3
```

## Step 6: Monitor Results

Watch the controller logs for:

✅ **Success Indicators:**
- `"Warmup completed with X samples"`
- `"DDoS probability: 0.XXX"`
- `"DDoS DETECTED! Probability: 0.XXX"`
- `"Applied rate limiting (XXX bytes/sec)"`

⚠️ **Troubleshooting:**
- No flow stats: Check OpenFlow version (should be 1.3)
- No AI predictions: Verify training data path
- High CPU usage: Reduce STATS_INTERVAL to 10

## Step 7: Validation Checklist

For your thesis defense, demonstrate:

1. **Baseline**: Normal traffic with no alerts
2. **Detection**: DDoS attack triggers AI detection
3. **Mitigation**: Rate limiting is applied
4. **Recovery**: Normal operation resumes
5. **Learning**: Model adapts to new patterns

## Quick Performance Test

```bash
# Test detection speed
time curl -X GET http://127.0.0.1:8080/stats/flow/1  # If REST API enabled

# Monitor system resources
top -p $(pgrep -f "ryu-manager")
```

## Expected Timeline

- **Setup**: 5-10 minutes
- **Normal traffic baseline**: 2-3 minutes
- **DDoS attack detection**: 1-2 minutes
- **Mitigation verification**: 1 minute
- **Total demonstration**: 10-15 minutes

## Thesis Defense Tips

1. **Prepare logs**: Save controller output showing detection
2. **Show metrics**: Demonstrate detection accuracy
3. **Explain thresholds**: Justify 0.5-0.7 detection threshold
4. **Discuss trade-offs**: False positives vs detection speed
5. **Future work**: Mention distributed detection, more attack types

## Emergency Fallback

If AI detection fails, add manual detection:

```python
def _simple_ddos_detection(self, features):
    """Fallback simple detection"""
    pps = features.get('Flow Pkts/s', 0)
    bps = features.get('Flow Byts/s', 0)
    
    # Simple thresholds
    if pps > 100 or bps > 100000:
        return True
    return False
```

This setup should give you a working demonstration within 15-20 minutes!