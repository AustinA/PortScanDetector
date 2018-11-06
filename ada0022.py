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
from operator import itemgetter

# Accessors for tcp packet list (these values represent a single tcp packet)
TIMESTAMP = 0
SOURCE_IP = 1
SOURCE_PORT = 2
DESTINATION_IP = 3
DESTINATION_PORT = 4
TCP_FLAGS = 5
ALREADY_PROCESSED = 6

# Flag arrays representing packet types in TCP
SYN_TYPE = [False, True, False, False, False, False, False, False]
ACK_TYPE = [False, False, False, False, True, False, False, False]
RST_ACK_TYPE = [False, False, True, False, True, False, False, False]
SYN_ACK_TYPE = [False, True, False, False, True, False, False, False]


def main():
    """
    Main program.

    :return: 0 If no errors occured, 1 if the program did not complete successfully.
    """
    # Get file name from command line options
    file_name = create_cmd_options()

    try:
        # Attempt to open file
        with open(file_name) as afile:
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

                print "Full TCP handshakes on ports from SYN scan: " + str(full_tcp_scan)
                print "Closed ports from TCP SYN scan: " + str(num_syn_ack_scans)
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
        sorted(tcp_packets[key], key=itemgetter(0))
        tcp_packets[key].sort(key=lambda x: x[0])

    return tcp_packets, None


#####################     SCAN TYPE DETERMINATORS   #############################################


def get_num_syn_scans(tcp_packets):
    """
    Gets the number unique ports scanned by a full_scan or half_scan port scan type

    :param tcp_packets: The dictionary of tcp packets discovered in the pcap file
    :return: Number of ports scanned by doing a full TCP handshake, Number of ports scanned using half-scan techniques
    """
    syn_rst_ack_results = 0
    full_hand_shake_results = 0

    # For each packet list for the dictionary key
    for key in tcp_packets:
        # Ports already scanned for packets in this particular key
        already_scanned_ports = []
        # For each packet under the dictionary key
        for packet in tcp_packets[key]:
            # If the packet has not already been looked at
            if not packet[ALREADY_PROCESSED]:

                # Filter out pertinent packets by the source ip, destination ip, source port, and destination port
                from_source = find_packets_by_ip_port(tcp_packets[key], packet[SOURCE_IP], packet[SOURCE_PORT],
                                                      packet[DESTINATION_IP], packet[DESTINATION_PORT])
                from_destination = find_packets_by_ip_port(tcp_packets[key], packet[DESTINATION_IP],
                                                           packet[DESTINATION_PORT], packet[SOURCE_IP],
                                                           packet[SOURCE_PORT])

                # Create a ordered conversation between packets based on the information from the selected packet
                conversation = []
                for x in from_source:
                    if not x[ALREADY_PROCESSED]:
                        conversation.append(x)
                for y in from_destination:
                    if not y[ALREADY_PROCESSED]:
                        conversation.append(y)
                conversation.sort(key=lambda x: x[0])

                # If the conversation length is 4, check to see if a full scan occured
                if len(conversation) == 4:
                    if conversation[0][TCP_FLAGS] == SYN_TYPE:
                        if conversation[0][DESTINATION_PORT] not in already_scanned_ports:
                            if conversation[1][TCP_FLAGS] == SYN_ACK_TYPE:
                                if conversation[2][TCP_FLAGS] == ACK_TYPE:
                                    if conversation[3][TCP_FLAGS] == RST_ACK_TYPE:
                                        if ((conversation[0][SOURCE_IP] == conversation[1][DESTINATION_IP])
                                                and (conversation[1][SOURCE_IP] == conversation[2][DESTINATION_IP])
                                                and (conversation[2][SOURCE_IP] == conversation[0][SOURCE_IP])
                                                and (conversation[0][SOURCE_PORT] == conversation[2][SOURCE_PORT])
                                                and (conversation[1][SOURCE_PORT] == conversation[2][DESTINATION_PORT])
                                                and (conversation[2][SOURCE_PORT] == conversation[3][SOURCE_PORT])):
                                            full_hand_shake_results = full_hand_shake_results + 1
                                            conversation[0][ALREADY_PROCESSED] = True
                                            conversation[1][ALREADY_PROCESSED] = True
                                            conversation[2][ALREADY_PROCESSED] = True
                                            conversation[3][ALREADY_PROCESSED] = True
                                            already_scanned_ports.append(conversation[0][DESTINATION_PORT])

                # If the packet number in the conversation is 2, check to see if the port scanned occured is half-scan
                elif len(conversation) == 2:
                    if conversation[0][TCP_FLAGS] == SYN_TYPE:
                        if conversation[0][DESTINATION_PORT] not in already_scanned_ports:
                            if conversation[1][TCP_FLAGS] == RST_ACK_TYPE:
                                if ((conversation[0][SOURCE_IP] == conversation[1][DESTINATION_IP])
                                        and (conversation[0][DESTINATION_IP] == conversation[1][SOURCE_IP])
                                        and (conversation[0][SOURCE_PORT] == conversation[1][DESTINATION_PORT])
                                        and (conversation[0][DESTINATION_PORT] == conversation[1][SOURCE_PORT])):
                                    syn_rst_ack_results = syn_rst_ack_results + 1
                                    conversation[0][ALREADY_PROCESSED] = True
                                    conversation[1][ALREADY_PROCESSED] = True
                                    already_scanned_ports.append(conversation[0][DESTINATION_PORT])

    return full_hand_shake_results, syn_rst_ack_results


########################   PACKET PARSING HELPERS ############################################

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


if __name__ == "__main__":
    main()
