package edu.wisc.cs.sdn.vnet.rt;

import java.util.Arrays;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.MACAddress;
import java.nio.ByteBuffer;
import java.util.Queue;
import java.util.List;
import java.util.LinkedList;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device {
	public final int TIME_EXCEEDED = 1;
	public final int NET_UNREACHABLE = 2;
	public final int HOST_UNREACHABLE = 3;
	public final int PORT_UNREACHABLE = 4;
	public final String BROADCAST_MAC = "FF:FF:FF:FF:FF:FF";
	public final String BROADCAST_IP = "224.0.0.9";

	/** Routing table for the router */
	private RouteTable routeTable;

	/** ARP cache for the router */
	private ArpCache arpCache;

	/** RIP Table for this router's table */

	private RipTable ripTable;

	/** ARP Table for this router's ARP cache */
	private ArpTable arpTable;

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Creates a router for a specific host.
	 * 
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile) {
		super(host, logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.arpTable = new ArpTable();
		this.ripTable = new RipTable(this, routeTable);
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable() {
		return this.routeTable;
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * @return arp cache for the router
	 */
	public ArpCache getArpCache() {
		return this.arpCache;
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Load a new routing table from a file.
	 * 
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile) {
		if (!routeTable.load(routeTableFile, this)) {
			System.err.println("Error setting up routing table from file " + routeTableFile);
			System.exit(1);
		}

		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	public void startRIP() {

		System.out.println("\nStarting RIP()\n");

		int destAddr;
		int gatewayAddr;
		int subnetMask;

		Map<String, Iface> interfaces = this.getInterfaces();

		// populate RouteTable and RipTable with local interfaces
		for (Iface iface : this.interfaces.values()) {

			destAddr = iface.getIpAddress();
			subnetMask = iface.getSubnetMask();

			// Add entry to Route Table
			this.routeTable.insert(destAddr & subnetMask, 0, subnetMask, iface);

			// Add entry to RIP Table (set its type to LOCAL_ROUTER)
			RipTableEntry newEntry = new RipTableEntry(destAddr & subnetMask, subnetMask, 1);
			newEntry.setType(RipTableEntry.LOCAL_ROUTER);
			this.ripTable.addLocalEntry(newEntry);
		}

		// Send RIP REQUEST out to all Interfaces
		sendUnsolicitedRipPacket(RIPv2.COMMAND_REQUEST);

		// Launch the thread to send Unsolicited Rip Responses every 10 seconds and
		// update entries every 30 seconds
		ripTable.initThread();

	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	public void sendUnsolicitedRipPacket(byte command) {

		Map<String, Iface> localInterfaces = this.getInterfaces();
		for (String localIface : localInterfaces.keySet()) {
			Iface outFace = localInterfaces.get(localIface);
			Ethernet outPacket = makeRipBroadcastPacket(outFace, BROADCAST_IP, BROADCAST_MAC, command);
			this.sendPacket(outPacket, outFace);
		}
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	public Ethernet makeRipBroadcastPacket(Iface outface, String destIp, String destMac, byte command) {

		// Ether Header
		Ethernet ether = new Ethernet();
		ether.setDestinationMACAddress(destMac);
		ether.setSourceMACAddress(outface.getMacAddress().toBytes());
		ether.setEtherType(Ethernet.TYPE_IPv4);

		// IPv4 Header
		IPv4 ip = new IPv4();
		ip.setDestinationAddress(IPv4.toIPv4Address(destIp));
		ip.setSourceAddress(outface.getIpAddress());
		ip.setTtl((byte) 64);
		ip.setProtocol(IPv4.PROTOCOL_UDP);

		// UDP Header (srcPort == destPort == 520)
		UDP udp = new UDP();
		udp.setSourcePort(UDP.RIP_PORT);
		udp.setDestinationPort(UDP.RIP_PORT);

		// RIPv2 Packet with all RIP Entries
		RIPv2 ripv2Packet = ripTable.getRipv2Packet(outface, command);

		// Set Payload
		udp.setPayload(ripv2Packet);
		ip.setPayload(udp);
		ether.setPayload(ip);

		return ether;
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	public void handleRipPacket(Ethernet etherPacket, Iface inIface) {
	
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		UDP udpPacket = (UDP) ipPacket.getPayload();
		RIPv2 ripv2Packet = (RIPv2) udpPacket.getPayload();

		if (ripv2Packet.getCommand() == RIPv2.COMMAND_RESPONSE) {
			System.out.println("\nReceived RIP Response\n");
			handleRipResponse(etherPacket, inIface);
		} else if (ripv2Packet.getCommand() == RIPv2.COMMAND_REQUEST) {
			System.out.println("\nReceived RIP Request\n");
			handleRipRequest(etherPacket, inIface);
		} else
			System.out.println("RIP PACKET WITHOUT COMMAND/REQUEST COMMAND");

	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	public void handleRipRequest (Ethernet etherPacket, Iface inIface) {
				
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		UDP udpPacket = (UDP) ipPacket.getPayload();
		RIPv2 ripv2Packet = (RIPv2) udpPacket.getPayload();
	
		int srcAddr = ipPacket.getSourceAddress();

		ArpEntry arpEntry = this.arpCache.lookup(srcAddr);
		if (null == arpEntry) {
			this.sendArpRequest(etherPacket, inIface, srcAddr);
		} else {
			
			Ethernet outPacket = makeRipBroadcastPacket(inIface, IPv4.fromIPv4Address(srcAddr), arpEntry.getMac().toString(), RIPv2.COMMAND_RESPONSE);
			this.sendPacket(outPacket, inIface);
		}
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	public void handleRipResponse(Ethernet etherPacket, Iface inIface) {

		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		UDP udpPacket = (UDP) ipPacket.getPayload();
		RIPv2 ripv2Packet = (RIPv2) udpPacket.getPayload();

		// entries coming from a RIP Response from some other router
		List<RIPv2Entry> ripEntries = ripv2Packet.getEntries();

		int srcAddr = ipPacket.getSourceAddress();

		int address; 
		int subnetMask;
		int metric;
		int nextHop;

		// for all incoming entries in this packet
		for (RIPv2Entry entry : ripEntries) {

			address = entry.getAddress();
			subnetMask = entry.getSubnetMask();
			metric = entry.getMetric() + 1;
			nextHop = entry.getNextHopAddress();	

			// Add to RipTable
			boolean updated = ripTable.addRipEntry(entry, inIface, srcAddr);
			//if (updated) sendUnsolicitedRipPacket(RIPv2.COMMAND_RESPONSE);
		}
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Load a new ARP cache from a file.
	 * 
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile) {
		if (!arpCache.load(arpCacheFile)) {
			System.err.println("Error setting up ARP cache from file " + arpCacheFile);
			System.exit(1);
		}

		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	public void generateICMP(int mode, Ethernet packet, Iface inIface) {

		// construct the packet
		Ethernet ether = new Ethernet();
		IPv4 ip = new IPv4();
		ICMP icmp = new ICMP();
		Data data = new Data();
		ether.setPayload(ip);
		ip.setPayload(icmp);
		icmp.setPayload(data);

		// find best match using original packet
		IPv4 ipPacket = (IPv4) packet.getPayload();
		// editing this line setting dst addr as ippackets src address
		int dstAddr = ipPacket.getSourceAddress();

		RouteEntry match = this.routeTable.lookup(dstAddr);
		int nextHop = match.getGatewayAddress();
		if (0 == nextHop) {
			nextHop = dstAddr;
		}

		ArpEntry arpEntry = this.arpCache.lookup(nextHop);

		if (arpEntry == null) {
			sendArpRequest(packet, inIface, dstAddr);
		}

		// set the ether packet values
		ether.setEtherType(Ethernet.TYPE_IPv4);
		ether.setSourceMACAddress(match.getInterface().getMacAddress().toString());
		ether.setDestinationMACAddress(arpEntry.getMac().toString());

		// set the IP header values for the new packet
		byte ttl = (byte) 64;
		ip.setTtl(ttl);
		ip.setProtocol(IPv4.PROTOCOL_ICMP);
		ip.setSourceAddress(inIface.getIpAddress());
		ip.setDestinationAddress(ipPacket.getSourceAddress());

		// construct data byte array
		byte[] serialPacket = ipPacket.serialize();
		int headerLen = ipPacket.getHeaderLength() * 4;
		byte[] dataIn = new byte[12 + headerLen];

		// first four empty bytes
		for (int i = 0; i < 4; i++) {
			dataIn[i] = 0x0;
		}
		// serialize entire header
		for (int i = 0; i < headerLen; i++) {
			dataIn[i + 4] = serialPacket[i];
		}
		// last 8 bytes
		for (int i = 0; i < 8; i++) {
			dataIn[i + 4 + headerLen] = serialPacket[headerLen + i];
		}

		byte icmpType;
		byte code;

		switch (mode) {

		case TIME_EXCEEDED:

			icmpType = (byte) 11;
			code = (byte) 0;
			icmp.setIcmpType(icmpType);
			icmp.setIcmpCode(code);

			data.setData(dataIn);

			this.sendPacket(ether, inIface);

			break;

		case NET_UNREACHABLE:

			icmpType = (byte) 3;
			code = (byte) 0;
			icmp.setIcmpType(icmpType);
			icmp.setIcmpCode(code);

			data.setData(dataIn);

			this.sendPacket(ether, inIface);

			break;

		case HOST_UNREACHABLE:

			icmpType = (byte) 3;
			code = (byte) 1;
			icmp.setIcmpType(icmpType);
			icmp.setIcmpCode(code);

			data.setData(dataIn);

			this.sendPacket(ether, inIface);

			break;

		case PORT_UNREACHABLE:

			byte protocolNum = ipPacket.getProtocol();

			if (protocolNum == IPv4.PROTOCOL_UDP || protocolNum == IPv4.PROTOCOL_TCP) {
				data.setData(dataIn);

				icmpType = (byte) 3;
				code = (byte) 3;
				icmp.setIcmpType(icmpType);
				icmp.setIcmpCode(code);

				this.sendPacket(ether, inIface);
			}

			else if (protocolNum == IPv4.PROTOCOL_ICMP) {

				ICMP icmpPacket = (ICMP) ipPacket.getPayload();

				if (icmpPacket.getIcmpType() != (byte) 8) {
					return;
				}

				else {
					icmpType = (byte) 0;
					code = (byte) 0;

					// resetting IP header's src and dest addresses for ICMP
					ip.setSourceAddress(ipPacket.getDestinationAddress());
					ip.setDestinationAddress(ipPacket.getSourceAddress());

					icmp.setIcmpType(icmpType);
					icmp.setIcmpCode(code);

					// add ICMP Payload from echo request (no padding, etc.)
					Data entire_data = (Data) icmpPacket.getPayload();
					data.setData(entire_data.getData());

					this.sendPacket(ether, inIface);
				}
			}

			break;
		default:
		}

	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	public void handleArpPacket(Ethernet inPacket, Iface inIface) {

		ARP arpPacket = (ARP) inPacket.getPayload();

		// Received ARP Request, Send an ARP Reply
		if (arpPacket.getOpCode() == ARP.OP_REQUEST) {
			sendArpReply(inPacket, inIface);
		}

		// Received an ARP Reply, Process the reply >> update ARP Cache
		else if (arpPacket.getOpCode() == ARP.OP_REPLY) {
			processArpReply(inPacket, inIface);
		}
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	public void sendArpReply(Ethernet inPacket, Iface inIface) {

		ARP arpPacket = (ARP) inPacket.getPayload();
		int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();

		// construct the packet headers and connect them
		Ethernet ether = new Ethernet();
		ARP arp = new ARP();
		ether.setPayload(arp);

		// populate the ethernet header
		ether.setEtherType(Ethernet.TYPE_ARP);
		ether.setSourceMACAddress(inIface.getMacAddress().toString()); // MAC Address of the incoming Interface
		ether.setDestinationMACAddress(inPacket.getSourceMACAddress()); // MAC address of the incoming Packet

		 
		if (targetIp != inIface.getIpAddress()) {
			System.out.println("Not generating ARP Reply, it wants to go back to its original host");
			return;
		}
		// */

		arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arp.setProtocolType(ARP.PROTO_TYPE_IP);
		Short val1 = new Short(Ethernet.DATALAYER_ADDRESS_LENGTH);
		arp.setHardwareAddressLength(val1.byteValue());
		byte val2 = (byte) 4;
		arp.setProtocolAddressLength(val2);
		arp.setOpCode(ARP.OP_REPLY);
		arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
		arp.setSenderProtocolAddress(inIface.getIpAddress());
		arp.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
		arp.setTargetProtocolAddress(targetIp);

		this.sendPacket(ether, inIface);
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	public synchronized void processArpReply(Ethernet inPacket, Iface inIface) {

		ARP arpPacket = (ARP) inPacket.getPayload();
		// IPv4 ipPacket = (IPv4) inPacket.getPayload();

		MACAddress mac = new MACAddress(arpPacket.getSenderHardwareAddress());
		int ip = ByteBuffer.wrap(arpPacket.getSenderProtocolAddress()).getInt();

		// store this IP-MAC pair in the ARP CACHE
		arpCache.insert(mac, ip);

		Queue<Ethernet> queue = arpTable.getQueue(ip);
		Ethernet outpacket;

		// send ICMP to each packet's source
		while (queue.size() > 0) {
			// dequeue a packet
			outpacket = queue.remove();

			// attach MAC address to the incomplete packet
			outpacket.setDestinationMACAddress(mac.toString());

			// send completed packets from the queue onto the interface where we got the ARP
			// reply
			this.sendPacket(outpacket, inIface);
		}
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	public void sendArpRequest(final Ethernet inPacket, final Iface inface, final int destIP) {

		final IPv4 ipPacket = (IPv4) inPacket.getPayload();

		// check if this destIP has a live thread processing requests
		if (arpTable.containsThread(destIP)) {

			// add this packet to the live thread's queue
			arpTable.addPacket(destIP, inPacket);

			Queue<Ethernet> queue = arpTable.getQueue(destIP);
		}

		else {
			// create a hashmap entry in ArpTable with key==destIP and val==Queue
			arpTable.addThread(destIP, inPacket);

			Queue<Ethernet> queue = arpTable.getQueue(destIP);

			Thread t1 = new Thread() {
				boolean exit = false;

				@Override
				public void run() {
					for (int i = 0; i < 3; i++) {
						// attempt to run thread only if not exited
						if (!exit) {
							try {
								// ARP cache has an entry for this IP now, stop sending ARP Requests
								if (arpCache.lookup(destIP) != null) {
									exit = true;
									break;
								}

								// continue sending ARP requests
								else {
									sendArpRequestPacket(inPacket, inface, destIP);
								}

								Thread.sleep(1000);

							} catch (InterruptedException e) {
								System.out.println(e);
							}
						}
					}

					if (!exit) {

						/**
						 * Thread failed to acquire ARP reply after sending 3 ARP requeusts Dequeue all
						 * packets from the queue, and send ICMP to their sender hosts
						 */

						Queue<Ethernet> failureQueue = arpTable.getQueue(destIP);
						Ethernet outpacket;
						Iface inf;
						IPv4 ipOutPacket;

						// send ICMP to each packet's source
						while (failureQueue.size() > 0) {

							// dequeue a packet
							outpacket = failureQueue.remove();
							ipOutPacket = (IPv4) outpacket.getPayload();

							// get the source IP for generating ICMP
							inf = routeTable.lookup(ipOutPacket.getSourceAddress()).getInterface();

							// send ICMP for this packet
							generateICMP(HOST_UNREACHABLE, outpacket, inf);
						}
					}

				}
			};
			t1.start();
		}
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	public synchronized void sendArpRequestPacket(Ethernet inPacket, Iface inIface, int destIP) {

		IPv4 ipPacket = (IPv4) inPacket.getPayload();

		// construct the packet
		Ethernet ether = new Ethernet();
		ARP arp = new ARP();

		// populate the ethernet header
		ether.setEtherType(Ethernet.TYPE_ARP);
		ether.setSourceMACAddress(inIface.getMacAddress().toString());
		ether.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");

		arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
		arp.setProtocolType(ARP.PROTO_TYPE_IP);
		Short val1 = new Short(Ethernet.DATALAYER_ADDRESS_LENGTH);
		// arp.setHardwareAddressLength(val1.byteValue());
		arp.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
		byte val2 = (byte) 4;
		arp.setProtocolAddressLength((byte) 4);
		arp.setOpCode(ARP.OP_REQUEST);
		arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
		arp.setSenderProtocolAddress(inIface.getIpAddress());

		byte[] res = new byte[6];
		res[0] = 0x0;
		arp.setTargetHardwareAddress(res);
		arp.setTargetProtocolAddress(destIP);

		ether.setPayload(arp);
		this.sendPacket(ether, inIface);
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * 
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface     the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface) {
		System.out.println("*** -> Received packet: " + etherPacket.toString().replace("\n", "\n\t"));

		/********************************************************************/

		switch (etherPacket.getEtherType()) {

		case Ethernet.TYPE_IPv4:
			this.handleIpPacket(etherPacket, inIface);
			break;

		case Ethernet.TYPE_ARP:
			handleArpPacket(etherPacket, inIface);
			break;
		default:
		}

		/********************************************************************/
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	private void handleIpPacket(Ethernet etherPacket, Iface inIface) {

		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4) {
			return;
		}

		// Get IP header
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		//System.out.println("\nHandle IP packet for IP: " + ipPacket.getSourceAddress() + "\n");

		// Verify checksum
		short origCksum = ipPacket.getChecksum();
		ipPacket.resetChecksum();
		byte[] serialized = ipPacket.serialize();
		ipPacket.deserialize(serialized, 0, serialized.length);
		short calcCksum = ipPacket.getChecksum();
		if (origCksum != calcCksum) {
			return;
		}

		// Check TTL
		ipPacket.setTtl((byte) (ipPacket.getTtl() - 1));
		if (0 == ipPacket.getTtl()) {
			System.out.println("TTL EXPIRED, GENERATING ICMP");
			generateICMP(TIME_EXCEEDED, etherPacket, inIface);
			return;
		}

		// Reset checksum now that TTL is decremented
		ipPacket.resetChecksum();

		/***********************************************************************/
		/** CHECK IF THIS PACKET IS UDP */

		// check whether the ipPacket is UDP
		byte protocolNum = ipPacket.getProtocol();

		if (protocolNum == IPv4.PROTOCOL_UDP) {

			// checking whether the packets dest address is 224.0.0.9
			int dest_addr = ipPacket.getDestinationAddress();
			String destination_addr = IPv4.fromIPv4Address(dest_addr);

			if (destination_addr.equals(BROADCAST_IP)) {

				UDP udpPacket = (UDP) ipPacket.getPayload();

				// packets matching the criteria responses or requests
				if (udpPacket.getDestinationPort() == UDP.RIP_PORT) {
					handleRipPacket(etherPacket, inIface);
					return; 	
				}
			}
		}

		/***********************************************************************/

		// Check if packet is destined for one of router's interfaces
		for (Iface iface : this.interfaces.values()) {
			if (ipPacket.getDestinationAddress() == iface.getIpAddress()) {
				System.out.println("Interface is the same as router's, GENERATING ICMP");
				generateICMP(PORT_UNREACHABLE, etherPacket, inIface);
				return;
			}
		}

		// Do route lookup and forward
		this.forwardIpPacket(etherPacket, inIface);
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

	private void forwardIpPacket(Ethernet etherPacket, Iface inIface) {

		// Get IP header
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		int dstAddr = ipPacket.getDestinationAddress();

		RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

		if (null == bestMatch) {
			generateICMP(NET_UNREACHABLE, etherPacket, inIface);
			return;
		}

		// Make sure we don't sent a packet back out the interface it came in
		Iface outIface = bestMatch.getInterface();
		if (outIface == inIface) {
			generateICMP(PORT_UNREACHABLE, etherPacket, inIface);
			return;
		}

		// Set source MAC address in Ethernet header
		etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

		// If no gateway, then nextHop is IP destination
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop) {
			nextHop = dstAddr;
		}

		// Set destination MAC address in Ethernet header
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (null == arpEntry) {

			// inIface - re.iface()
			this.sendArpRequest(etherPacket, outIface, nextHop);
		} else {
			etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
			this.sendPacket(etherPacket, outIface);
		}
	}
}
