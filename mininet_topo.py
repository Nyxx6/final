#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

def create_topology():
    """Creates and runs a custom Mininet topology with 2 switches and 4 hosts."""

    # Instantiate Mininet object
    # OVSKernelSwitch is generally recommended for OpenFlow 1.3+
    # TCLink allows for setting link parameters like bandwidth if needed later
    net = Mininet(controller=None, switch=OVSKernelSwitch, link=TCLink, autoSetMacs=True)

    info('*** Adding controller\n')
    # Assuming your Ryu controller (main.py) is running on localhost, default port 6653
    # If you run Ryu on a different port or IP, change it here.
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    info('*** Adding switches\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')

    info('*** Adding hosts\n')
    h1 = net.addHost('h1', ip='10.0.0.1/24') # Assigning IPs for easier testing
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')
    h4 = net.addHost('h4', ip='10.0.0.4/24')
    h5 = net.addHost('h5', ip='10.0.0.5/24')
    h6 = net.addHost('h6', ip='10.0.0.6/24')

    info('*** Creating links\n')
    # Host links
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s2)
    net.addLink(h5, s2)
    net.addLink(h6, s2)

    # Switch link
    net.addLink(s1, s2)

    info('*** Starting network\n')
    net.build()
    c0.start() # Start the remote controller
    s1.start([c0]) # Connect switch s1 to the controller
    s2.start([c0]) # Connect switch s2 to the controller

    # May enable STP on switches for more complex topologies later
    # s1.cmd('ovs-vsctl set bridge s1 stp_enable=true')
    # s2.cmd('ovs-vsctl set bridge s2 stp_enable=true')

    info('*** Running CLI\n')
    CLI(net) # Start Mininet CLI

    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info') # Set Mininet log level
    create_topology()
