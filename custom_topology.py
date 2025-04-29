from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel

def custom_topology():
    net = Mininet(controller=RemoteController, link=TCLink, switch=OVSKernelSwitch)

    print("*** Adding controller")
    c0 = net.addController('c0', ip='127.0.0.1', port=6653)

    print("*** Adding switches")
    s1 = net.addSwitch('s1', dpid='0000000000000001')  # Explicit DPID for s1
    s2 = net.addSwitch('s2', dpid='0000000000000002')  # Explicit DPID for s2

    print("*** Adding hosts")
    h1 = net.addHost('h1', mac="00:00:00:00:00:01", ip='10.0.0.1/24')
    h2 = net.addHost('h2', mac="00:00:00:00:00:02", ip='10.0.0.2/24')
    attacker1 = net.addHost('attacker1', mac="00:00:00:00:00:03", ip='10.0.0.3/24')
    attacker2 = net.addHost('attacker2', mac="00:00:00:00:00:04", ip='10.0.0.4/24')
    ta1 = net.addHost('ta1', mac="00:00:00:00:00:05", ip='10.0.0.4/24')  # Traffic Agent host

    print("*** Creating links")
    net.addLink(h1, s1)
    net.addLink(attacker1, s1)
    net.addLink(h2, s2)
    net.addLink(attacker2, s2)
    net.addLink(ta1, s1)      # ta1-eth0 connected to s1
    net.addLink(ta1, s2)      # ta1-eth1 connected to s2
    net.addLink(s1, s2)       # Inter-switch link

    print("*** Starting network")
    net.build()
    net.start()

    print("*** Configuring TrafficAgent on ta1")
    # Get interfaces on ta1 connected to s1 and s2
    ta1_interfaces = [iface.name for iface in ta1.intfList() if iface.name != 'lo']
    # Launch TrafficAgent on ta1
    ta1.cmd(f"xterm -hold -e 'python3 traffic_agent.py --controller-host 127.0.0.1 --controller-port 9000 "
            f"--interfaces {ta1_interfaces[0]} {ta1_interfaces[1]} "
            f"--dpids 1 2 "  # DPIDs for s1 and s2 (hex format not needed here)
            f"--f-low 2 "
            f"--f-high 5 "
            f"--window 5' &")

    print("*** Testing connectivity")
    net.pingAll()

    print("*** Running CLI")
    CLI(net)

    print("*** Stopping network")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    custom_topology()
