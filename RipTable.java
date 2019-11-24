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

import javax.sql.rowset.spi.SyncResolver;

/**
 * @author Jay Patel and Parth Shah
 */
public class RipTable implements Runnable {

	protected List<RipTableEntry> tableEntries;

	private Router router;
	private RouteTable routeTable;
	private Thread timerThread;

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////

	public RipTable(Router router, RouteTable routeTable) {
		this.router = router;
		this.routeTable = routeTable;

		tableEntries = new LinkedList<>();

		timerThread = new Thread(this);
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////


	public void initThread() {	
		timerThread.start();
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Sends out Unsolicited Rip Response every 10 seconds. Refreshes RIP Table
	 * every 30 seconds.
	 */

	public void run() {

		int countToRefresh = 0;
		System.out.println("\nInside RipTable thread run(). Thread Starting\n");

		while (true) {

			// try sleeping for 10 seconds before sending RIP response packets
			try {
				Thread.sleep(10000);
			} catch (InterruptedException e) {
				break;
			}

			// Ask Router to send RIP Response packets
			router.sendUnsolicitedRipPacket(RIPv2.COMMAND_RESPONSE);

			countToRefresh++;
			if (countToRefresh == 3) {

				// Refresh table to remove stale entries
				System.out.println("\nRefreshing Table Entries\n");
				this.refreshTable();
				countToRefresh = 0;
			}
		}
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * 
	 * @param address : IP address of the entry
	 * @param mask    : SubnetMask of the entry
	 * @return : Matching RipTableEntry
	 */

	public synchronized RipTableEntry getRipEntry (int address, int mask) {

		for (RipTableEntry existingEntry : tableEntries) {

			// Entry found in the Rip Table
			if (existingEntry.getAddress() == address
					&& existingEntry.getSubnetMask() == mask) {
				return existingEntry;
			}
		}
		return null;
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * 
	 * @param outface : Interface on which the packet is to be sent
	 * @param command : Request or Response
	 * @return : RIPv2 Packet with all entries fetched from the Route Table
	 *         (non-synchronous)
	 */

	public RIPv2 getRipv2Packet(Iface outface, byte command) {

		RIPv2 ripv2Packet = new RIPv2();

		if (command == RIPv2.COMMAND_RESPONSE)
			ripv2Packet.setCommand(RIPv2.COMMAND_RESPONSE);
		else
			ripv2Packet.setCommand(RIPv2.COMMAND_REQUEST);

		// add all route table entries to this packet

		// for (RouteEntry entry : routeTable.getEntries()) {
		synchronized (this.tableEntries) {

			//System.out.println("SENDING FOLLOWING ENTRIES ON INTERFACE: " + outface);

			for (RipTableEntry entry : this.tableEntries) {

				//skip if null
				if (entry == null) {
					continue;
				}

				int ip = entry.getAddress();
				int mask = entry.getSubnetMask();
				//int nextHopIP = outface.getIpAddress();
				int metric;

				if (entry.getType() == RipTableEntry.LOCAL_ROUTER)
					metric = 1;

				else {
					RipTableEntry ripEntry = getRipEntry(ip, mask);

					// RIP Entry for this IP and Mask wasn't found
					if (ripEntry == null) {
						continue;
					}

					metric = ripEntry.getMetric();
				}

				RIPv2Entry ripEntry = new RIPv2Entry(ip, mask, metric);

				//System.out.println("" + ripEntry);

				// Add this RIP Entry to this RIP Packet
				ripv2Packet.addEntry(ripEntry);
			}
		}

		return ripv2Packet;
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * @param newEntry : Adds the local interfaces of the router, first time it starts
	 */

	public synchronized void addLocalEntry(RipTableEntry newEntry) {
		//System.out.println("Local entry added: " + newEntry);
		tableEntries.add(newEntry);
	}


	/////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * @param newEntry : Entry to be added to the Rip Table  
	 * @param iface : Interface on which the Rip Packet arrived at
	 * @param srcAddr : IP Address of the router that sent the RIPv2 packet
	 * @return : True if packet was added to RipTable, false otherwise
	 */

	public boolean addRipEntry(RIPv2Entry newEntry, Iface iface, int srcAddr) {

		//System.out.println("Adding new entry: " + newEntry);

		int newMetric = newEntry.getMetric() + 1;

		synchronized (this.tableEntries) {

			boolean found = false;
			boolean updated = false;

			for (RipTableEntry existingEntry : tableEntries) {

				// My RIP table has the same IP and Mask as the new entry
				if (existingEntry.getAddress() == newEntry.getAddress()
						&& existingEntry.getSubnetMask() == newEntry.getSubnetMask()) {

					found = true; 

					// I cannot touch my local entry
					if (existingEntry.getType().equals(RipTableEntry.LOCAL_ROUTER)) {
						return false;
					}	

					// My RIP entry also came from this gateway, must be the same entry again
					else if (existingEntry.getNextHopAddress() == srcAddr) {

						existingEntry.setMetric(newMetric);
						existingEntry.refreshTime();

						// Send out UPDATED RIP RESPONSE from router 
						updated = true;
					}

					// New entry came from a different gateway (could be the same entry with a better route/metric) 
					else if (newMetric < existingEntry.getMetric()) {

						// remove this entry from Route Table
						routeTable.remove(existingEntry.getAddress(), existingEntry.getSubnetMask());

						// update the existing entry's gateway and metric in the RIP Table
						existingEntry.setNextHopAddress(srcAddr);
						existingEntry.setMetric(newMetric);

						// add updated RIP Entry to Route Table
						routeTable.insert(existingEntry.getAddress(), srcAddr, existingEntry.getSubnetMask(), iface);

						// Send out UPDATED RIP RESPONSE from router
						updated = true;
					}

					// existing entry has neither the same source IP, nor a better metric from a
					// different source
					else {
						return false;
					}
				}
			}

			if (!found) {

				// add this new entry to RIP Table
				RipTableEntry newRipEntry = new RipTableEntry(newEntry.getAddress(), newEntry.getSubnetMask(), newMetric);
				newRipEntry.setNextHopAddress(srcAddr);
				newRipEntry.setType("");

				tableEntries.add(newRipEntry);

				updated = true; 

				// add to Route Table
				routeTable.insert(newEntry.getAddress(), srcAddr, newEntry.getSubnetMask(), iface);
			}
			if (updated) return true; 
		}
		return false;
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////

	/**
	 * Refreshes the RipTable to remove stale entries (older than 30 seconds)
	 */

	private void refreshTable() {

		synchronized (this.tableEntries) {

			for (RipTableEntry existingEntry : this.tableEntries) {

				// if this entry's time stamp has expired, remove it
				if (existingEntry.getType().equals(RipTableEntry.LOCAL_ROUTER)) continue;

				else if (existingEntry.isStale()) {

					System.out.println("Checking freshness of : " + existingEntry); 
	
					// remove this stale entry from RIP Table and Route Table
					this.tableEntries.remove(existingEntry);
					this.routeTable.remove(existingEntry.getAddress(), existingEntry.getSubnetMask());
				}
			}
		}
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////////////////

	}
