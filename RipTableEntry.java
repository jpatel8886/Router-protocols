package edu.wisc.cs.sdn.vnet.rt;

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

/**
 * @author Anubhavnidhi Abhashkumar and Aaron Gember-Jacobson
 */
public class RipTableEntry {
    public static final short ADDRESS_FAMILY_IPv4 = 2;
    public static final String LOCAL_ROUTER = "LOCAL_ROUTER";

    protected int address;
    protected int subnetMask;
    protected int nextHopAddress;
    protected int metric;
    protected String type;
    protected long time;

    public RipTableEntry() {
    }

    public RipTableEntry(int address, int subnetMask, int metric) {
        this.address = address;
        this.subnetMask = subnetMask;
        this.metric = metric;

        this.time = System.currentTimeMillis();
    }

    public String toString() {
        return String.format("RipTableEntry : {address=%s, subnetMask=%s, nextHopAddress=%s, metric=%d, type=%s}",
                IPv4.fromIPv4Address(this.address), IPv4.fromIPv4Address(this.subnetMask),
                IPv4.fromIPv4Address(this.nextHopAddress), this.metric, this.type);
    }

    // returns false if the entry is fresh (not older than 30 seconds)
    public boolean isStale() {
        return ((System.currentTimeMillis() - time) >= 30000);
    }

    // resets the timestamp to refresh this entry
    public void refreshTime() {
        this.time = System.currentTimeMillis();
    }

    public void setTime(long time) {
        this.time = time;
    }
    
    public long getTime() {
        return this.time;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getType() {
        return this.type;
    }

    public int getAddress() {
        return this.address;
    }

    public void setAddress(int address) {
        this.address = address;
    }

    public int getSubnetMask() {
        return this.subnetMask;
    }

    public void setSubnetMask(int subnetMask) {
        this.subnetMask = subnetMask;
    }

    public int getNextHopAddress() {
        return this.nextHopAddress;
    }

    public void setNextHopAddress(int nextHopAddress) {
        this.nextHopAddress = nextHopAddress;
    }

    public int getMetric() {
        return this.metric;
    }

    public void setMetric(int metric) {
        this.metric = metric;
    }

    public byte[] serialize() {
        int length = 4 * 4;
        byte[] data = new byte[length];
        ByteBuffer bb = ByteBuffer.wrap(data);

        bb.putInt(this.address);
        bb.putInt(this.subnetMask);
        bb.putInt(this.nextHopAddress);
        bb.putInt(this.metric);
        return data;
    }

    public RipTableEntry deserialize(byte[] data, int offset, int length) {
        ByteBuffer bb = ByteBuffer.wrap(data, offset, length);

        this.address = bb.getInt();
        this.subnetMask = bb.getInt();
        this.nextHopAddress = bb.getInt();
        this.metric = bb.getInt();
        return this;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (null == obj) {
            return false;
        }
        if (!(obj instanceof RipTableEntry)) {
            return false;
        }
        RipTableEntry other = (RipTableEntry) obj;
        if (this.address != other.address) {
            return false;
        }
        if (this.subnetMask != other.subnetMask) {
            return false;
        }
        if (this.nextHopAddress != other.nextHopAddress) {
            return false;
        }
        if (this.metric != other.metric) {
            return false;
        }
        return true;
    }
}
