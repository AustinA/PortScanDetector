#!/usr/bin/env python

"""                   CPE 549 Final Project
                        Austin Alderton
                    Christopher (Eric) Whatley

Reads in a PCAP file and determines the number of port scans attempted by port scan type.

Program assumptions:
- Ports scanned by different IP addresses count as individual occurrences
- It is impossible to tell the difference between a Half-SYN and Full-SYN scan unless a connection is established.
  Only if full TCP handshake is successfully detected will the scans from that IP address be considered a full-scan.
- The pcap only contains ethernet packets
- Each port scanned by the given type of port scan is only counted once, even if it occurs in the same scan type
  multiple times

"""

from optparse import OptionParser
import dpkt
import socket
from collections import defaultdict

# Accessors for tcp packet list (these values represent a single tcp packet)
TIMESTAMP = 0
SOURCE_IP = 1
SOURCE_PORT = 2
DESTINATION_IP = 3
DESTINATION_PORT = 4
TCP_FLAGS = 5
ALREADY_PROCESSED = 6

# Flag arrays indices for accessing
FIN_INDEX = 0
SYN_INDEX = 1
RST_INDEX = 2
PSH_INDEX = 3
ACK_INDEX = 4
URG_INDEX = 5
ECE_INDEX = 6
CWR_INDEX = 7

SYN_TYPE = [False, True, False, False, False, False, False, False]

SYN_PACKETS_VOLUME = 5
SAMPLING_INVERVAL_SEC = 0.05
UNIQUE_PORT_SYNS_ALLOWED = 10


def main():
    """
    Main program.

    :return: 0 If no errors occured, 1 if the program did not complete successfully.
    """
    # Get file name from command line options
    file_name = create_cmd_options()

    try:
        # Attempt to open file
        with open(file_name, 'rb') as afile:
            # Create new instance of pcap reader
            pcap_reader = dpkt.pcap.Reader(afile)

            if pcap_reader:
                # Process the entire pcap file, hashing them into groups by a stable combination of their source
                # and destination ips
                (tcp_packets, udp_packets) = process(pcap_reader)

                # Get the number of SYN scans, splitting between a full handshake and half scans
                full_tcp_scan, num_syn_ack_scans = get_num_syn_scans(tcp_packets)

                # Reset processed flag to move to next scan type
                reset_already_processed_flags(tcp_packets)

                # Get the number of NULL scans
                num_null_scans = get_num_null_scans(tcp_packets)

                print_output(num_null_scans, 0, 0, num_syn_ack_scans, full_tcp_scan)
            else:
                raise IOError()
    except IOError:
        print("Could not read the file provided.")
        exit(1)


def process(pcap_reader):
    """
    Process packets and group them into hashes by a stable combination of their destination and source ip addresses
    These groupings represent all packets between two ip addresses.

    :param pcap_reader: An instance of a PCAP reader from dpt
    :return: Dictionaries of UDP and TCP packets by a combined ip hash.
    """

    # Create default dictionary
    tcp_packets = defaultdict(list)

    # For each timestamp and raw byte data in a packet
    for ts, buf in pcap_reader:
        # Parse out the ethernet header
        ethernet_data = dpkt.ethernet.Ethernet(str(buf))

        # Return which packet type and the actual ip packet to work with (only considers UDP and TCP)
        (protocol, ip_packet) = is_valid_packet_type(ethernet_data)

        # If the packet was not UDP or TCP, move along
        if (protocol is None) or (ip_packet is None):
            continue

        # If the packet was TCP
        if protocol == dpkt.ip.IP_PROTO_TCP:
            # Generate a stable unique key for the packet
            key = get_key(socket.inet_ntoa(ip_packet.src), socket.inet_ntoa(ip_packet.dst))

            # Create an entity list representing the pertinent information of the packet
            # A TCP packet in this program looks like this:
            # [source ip, source port, destination ip, destination port, tcp flags, parsed status of the packet]
            tcp_packets[key].append(
                [ts, socket.inet_ntoa(ip_packet.src), ip_packet.data.sport, socket.inet_ntoa(ip_packet.dst),
                 ip_packet.data.dport, create_tcp_flag_array(ip_packet.data), False])

            # TODO:  Add UDP packet support

    # Sort the packets numerically by time stamp
    for key in tcp_packets:
        tcp_packets[key].sort(key=lambda x: x[0])

    return tcp_packets, None


#####################     SCAN TYPE DETERMINATORS   #############################################


def get_num_syn_scans(tcp_packets):
    """
    Gets the number unique ports scanned by a full_scan or half_scan port scan type

    :param tcp_packets: The dictionary of tcp packets discovered in the pcap file
    :return: Number of ports scanned by doing a full TCP handshake, Number of ports scanned using half-scan techniques
    """

    closed_ports = 0
    half_open_scans_results = 0
    full_scan_results = 0

    suspects = []
    for key in tcp_packets:
        packets_by_thresholds = breakup_packets_by_threshold(tcp_packets[key])
        if len(packets_by_thresholds) > 0:
            for ip_src in packets_by_thresholds:
                packets_by_timeslice, left_overs = packets_by_thresholds[ip_src]
                if len(packets_by_timeslice) > 0:
                    for packet_group in packets_by_timeslice:
                        num_syn_packs = get_syn_number(packet_group)
                        if num_syn_packs > SYN_PACKETS_VOLUME:
                            if ip_src not in suspects:
                                suspects.append(ip_src)
                                break
    return 0, 0


def get_num_null_scans(tcp_packets):
    """
    Gets the number unique ports scanned by a null scans

    :param tcp_packets: The dictionary of tcp packets discovered in the pcap file
    :return: Number of ports scanned by doing by a null scan
    """
    null_scan_numbers = 0

    return null_scan_numbers


########################   PACKET PARSING HELPERS ############################################

def get_syn_number(packets):
    num_syn_packs = 0
    if len(packets) > 0:
        for packet in packets:
            if packet[TCP_FLAGS] == SYN_TYPE:
                num_syn_packs += 1
    return num_syn_packs


def breakup_packets_by_threshold(tcp_packets):
    ip_addresses = get_all_ip_addresses(tcp_packets)
    ip_to_time_slices = defaultdict(list)
    for ip_address in ip_addresses:
        all_packets = find_packets_by_source_ip(tcp_packets, ip_address)

        if len(all_packets) > 0:
            all_packets.sort(key=lambda x: x[0])

            packet_timeslices = []
            left_overs = []
            time_slice_index = 0
            threshold = all_packets[0][TIMESTAMP] + SAMPLING_INVERVAL_SEC
            current_time = all_packets[0][TIMESTAMP]
            current_index = 0

            cant_split = False
            if all_packets[len(all_packets) - 1][TIMESTAMP] - current_time <= SAMPLING_INVERVAL_SEC:
                cant_split = True
            if not cant_split:
                for i in range(0, len(all_packets)):
                    if current_time >= threshold:
                        packet_timeslices.append([])
                        for x in range(current_index, i):
                            packet_timeslices[time_slice_index].append(all_packets[x])
                        current_index = i
                        current_time = all_packets[i][TIMESTAMP]
                        threshold = current_time + SAMPLING_INVERVAL_SEC
                        time_slice_index += 1
                    else:
                        current_time = all_packets[i][TIMESTAMP]

                packets_timesliced = 0
                for i in range(0, len(packet_timeslices)):
                    packets_timesliced += len(packet_timeslices[i])
                for i in range(packets_timesliced, len(all_packets)):
                    left_overs.append(all_packets[i])

            ip_to_time_slices[ip_address] = [packet_timeslices, left_overs]

    return ip_to_time_slices


def find_packets_by_ip_port(tcp_packets, source_ip, source_port, destination_ip, destination_port):
    """
    Look through a list of lists and find information matching to the parameters.

    :param tcp_packets: The list of tcp packet lists to look through
    :param source_ip: The source ip address that should match the contents of the result
    :param source_port: The source port address that should match the contents of the result
    :param destination_ip:The destination ip address that should match the contents of the result
    :param destination_port: The destination port address that should match the contents of the result
    :return: Any packets matching the provided characteristics
    """
    found = []
    for packet in tcp_packets:
        if ((packet[SOURCE_IP] == source_ip) and (packet[SOURCE_PORT] == source_port)
                and (packet[DESTINATION_IP] == destination_ip) and (packet[DESTINATION_PORT] == destination_port)):
            found.append(packet)

    return found


def find_packets_by_source_ip(tcp_packets, ip):
    found = []
    for packet in tcp_packets:
        if packet[SOURCE_IP] == ip:
            found.append(packet)
    return found


def get_all_ip_addresses(tcp_packets):
    found = []
    for packet in tcp_packets:
        if packet[SOURCE_IP] not in found:
            found.append(packet[SOURCE_IP])

        if packet[DESTINATION_IP] not in found:
            found.append(packet[DESTINATION_IP])
    return found


def is_valid_packet_type(ethernet_data):
    """
    Filters out any invalid packet types.  Expected input is an ethernet packet.
    If no ethernet packets were found with ip packets (TCP, UDP) return nothing

    :param ethernet_data: Ethernet data packet
    :return: IP protocol type (UDP, TCP), ip data.
    """
    if ethernet_data.type != dpkt.ethernet.ETH_TYPE_IP:
        return None, None

    ip_packet = ethernet_data.data
    if (ip_packet.p == dpkt.ip.IP_PROTO_TCP) or (ip_packet.p == dpkt.ip.IP_PROTO_UDP):
        return ip_packet.p, ip_packet

    return None, None


def create_tcp_flag_array(tcp):
    """
    Generate an array of TCP flags from ip data.

    :param tcp: IP data
    :return: List of tcp flags set or unset.
    """
    fin_flag = (tcp.flags & dpkt.tcp.TH_FIN) != 0
    syn_flag = (tcp.flags & dpkt.tcp.TH_SYN) != 0
    rst_flag = (tcp.flags & dpkt.tcp.TH_RST) != 0
    psh_flag = (tcp.flags & dpkt.tcp.TH_PUSH) != 0
    ack_flag = (tcp.flags & dpkt.tcp.TH_ACK) != 0
    urg_flag = (tcp.flags & dpkt.tcp.TH_URG) != 0
    ece_flag = (tcp.flags & dpkt.tcp.TH_ECE) != 0
    cwr_flag = (tcp.flags & dpkt.tcp.TH_CWR) != 0

    return [fin_flag, syn_flag, rst_flag, psh_flag, ack_flag, urg_flag, ece_flag, cwr_flag]


#########################  GENERAL HELPER FUNCTIONS ############################################

def get_key(ip1, ip2):
    """
    Creates stable id of all packets between two ip addresses.

    :param ip1: IP address 1
    :param ip2: IP address 2
    :return: A string representing a unique identifier to mark any packets between the two ip addresses.
    """
    if ip1 < ip2:
        return ip1 + ip2
    else:
        return ip2 + ip1


def create_cmd_options():
    """
    Creates and parses command line arguments for this script.

    :return: Filename.
    """
    parser = OptionParser(usage="usage: %prog [options] filename.pcap",
                          version="%prog 1.0")

    parser.add_option("-i",
                      action="store_true",
                      dest="file_name",
                      default=False,
                      help="Flag to provide .pcap file to parse")

    (options, args) = parser.parse_args()

    if not options.file_name:
        print("Proper flag option was not provided.")
        exit(1)

    if len(args) != 1:
        print("Incorrect number of arguments.")
        exit(1)

    return args[0]


def reset_already_processed_flags(packet_dict):
    """
    Resets packet state to not processed.

    :param packet_dict: The packet dictionary to reset the parsing flags of
    """
    for key in packet_dict:
        for packet in packet_dict[key]:
            packet[ALREADY_PROCESSED] = False


def generate_tcp_conversation(from_source, from_destination):
    """
    Create a conversation (packets between two ip addresses in time stamp order

    :param from_source: Packets from the source ip
    :param from_destination: Packets from the destination ip
    :return: List of packets in conversation
    """
    # Create a ordered conversation between packets based on the information from the selected packet
    conversation = []
    for x in from_source:
        if not x[ALREADY_PROCESSED]:
            conversation.append(x)
    for y in from_destination:
        if not y[ALREADY_PROCESSED]:
            conversation.append(y)
    conversation.sort(key=lambda x: x[0])
    return conversation


def print_output(nullscan, xmasscan, udpscan, halfopenscan, connectscan):
    """
    Prints output of project.

    :param nullscan: Number of null scan ports
    :param xmasscan: Number of xmas scan ports
    :param udpscan:  Number of udp scan ports
    :param halfopenscan: Number of half open scan ports
    :param connectscan: Number of connect scan ports
    """
    if nullscan is not None:
        print "Null: " + str(nullscan)
    if xmasscan is not None:
        print "XMAS: " + str(xmasscan)
    if udpscan is not None:
        print "UDP: " + str(udpscan)
    if halfopenscan is not None:
        print "Half-open (SYN): " + str(halfopenscan)
    if connectscan is not None:
        print "Connect: " + str(connectscan)


if __name__ == "__main__":
    main()
