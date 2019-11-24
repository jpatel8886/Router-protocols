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
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.LinkedList; 
import java.util.Queue; 

/**
 * @author Jay Patel and Parth Shah
 */
public class ArpTable {

    // HashMap that maps HostIP keys to Queue values
    protected HashMap<Integer, Queue<Ethernet>> packets = new HashMap<>();

    // checks if there exists a queue for this IP
    public boolean containsThread (int ip) {
        return (packets.containsKey(ip));
    }

    // adds a packet to the queue for destIP
    public void addPacket (int destIP, Ethernet packet) {
        Queue<Ethernet> q = packets.get(destIP);
        q.add(packet);
    }

    // create a new entry in the HashMap
    public void addThread (int destIP, Ethernet packet) {
        
        // create new value (queue that holds this first packet)
        Queue<Ethernet> newQueue = new LinkedList<>();
        newQueue.add(packet);

        // add this key-value pair to the HashMap
        packets.put(destIP, newQueue);
    }

    public Queue<Ethernet> getQueue (int destIP) {
        return packets.get(destIP);
    }

}
