#!/usr/bin/env python

"""                   CPE 549 Final Project
                        Austin Alderton
                    Christopher (Eric) Whatley

Reads in a PCAP file and determines the number of port scans attempted by port scan type.

Program assumptions:
- Sample destination ports scanned by different IP addresses count as individual occurrences
- It is impossible to tell the difference between a Half-SYN and Full-SYN scan unless a connection is established.
  The only way to tell the difference is to detect a half-scan or full-connect occurrences.  Whichever one has more
  detections will be added to the detected closed port scans.
- The pcap only contains ethernet packets
- Each port scanned by the given type of port scan is only counted once, even if it occurs in the same scan type
  multiple times
- Once a ip address is marked as suspicious, any traffic that matches expected port scan type
  characteristics is considered a port scan. The possibility for false positives is high in a real-world setting.


- Each port scan type determinator is a two step algorithm:
    1.  Using heuristics (number of occurrences of a TCP packet with a specific flag type from one source in a time
        window, or number of UDP/ICMP packets from a source with more than a set number of unique ports within a time
        frame), determines if a source ip address is suspicious
    2. Generates a TCP conversation looking for expected sent and received packets using absolute time ordering
        to determine a port scan that revealed an open or closed port, OR
       Counts ICMP packets and unique destination IP and destination ports to determine port scan results.

"""

from optparse import OptionParser
import dpkt
import socket
from collections import defaultdict

# Accessors for packet list (these values together represent a single tcp/udp packet)
TIMESTAMP = 0
SOURCE_IP = 1
SOURCE_PORT = 2
DESTINATION_IP = 3
DESTINATION_PORT = 4
# Notice how these are interchangable depending on the packet type!
TCP_FLAGS = 5
UDP_INFO = 5
ALREADY_PROCESSED = 6

# TCP Flag buffer access indicies
FIN_INDEX = 0
SYN_INDEX = 1
RST_INDEX = 2
PSH_INDEX = 3
ACK_INDEX = 4
URG_INDEX = 5
ECE_INDEX = 6
CWR_INDEX = 7

# From left to right, the boolean representation of a particular kind of TCP packet's tcp flag settings
SYN_TYPE = [False, True, False, False, False, False, False, False]
RST_ACK_TYPE = [False, False, True, False, True, False, False, False]
SYN_ACK_TYPE = [False, True, False, False, True, False, False, False]
NULL_TYPE = [False, False, False, False, False, False, False, False]
XMAS_TYPE = [True, False, False, True, False, True, False, False]

# The sampling interval for a TCP stream
SAMPLING_INVERVAL_SEC = 0.1

# Within the sampling interval, the number of packet of a type before the ip is marked as suspicious
SYN_PACKETS_VOLUME = 5
NULL_PACKETS_VOLUME = 5
XMAS_PACKETS_VOLUME = 5

# The sampling interval for a UDP stream
UDP_SAMPLING_INTERVAL_SEC = 4

# Within the sampling interval, the number of packet type before the ip is marked as suspicious
ICMP_UNIQUE_PORTS_VOLUME = 4
UDP_UNIQUE_PORTS_VOLUME = 3


def main():
    """
    Main program.

    :return: 0 If no errors occurred, 1 if the program did not complete successfully.
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
                closed_tcp_port_scans, half_tcp_scans, full_tcp_scans = get_num_syn_scans(tcp_packets)

                # Reset processed flag to move to next scan type
                reset_already_processed_flags(tcp_packets)

                # Get the number of NULL scans
                num_null_scans = get_num_null_scans(tcp_packets)

                # Reset processed flag to move to next scan type
                reset_already_processed_flags(tcp_packets)

                # Get the number of XMAS scans
                num_xmas_scans = get_num_xmas_scans(tcp_packets)

                # Get the number of UDP scans
                num_udp_scans = get_num_udp_scans(udp_packets)

                # Based on if a half-scan or full-scan was returned, lump the closed ports results into the final result
                printable_half = 0
                printable_connect = 0
                if half_tcp_scans > full_tcp_scans:
                    printable_half = half_tcp_scans + closed_tcp_port_scans
                else:
                    printable_connect = full_tcp_scans + closed_tcp_port_scans

                # Print the output
                print_output(num_null_scans, num_xmas_scans, num_udp_scans, printable_half, printable_connect)
            else:
                raise IOError()
    except IOError:
        print("Could not read the file provided.")
        exit(1)


def process(pcap_reader):
    """
    Process packets and group them into hashes by a stable combination of their destination and source ip addresses.
    These groupings represent all packets between two ip addresses.

    :param pcap_reader: An instance of a PCAP reader from dpt
    :return: Dictionaries of UDP and TCP packets by a combined ip hash.
    """

    # Create default dictionary
    tcp_packets = defaultdict(list)
    udp_packets = defaultdict(list)

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

        # Creates a UDP packet
        elif protocol == dpkt.ip.IP_PROTO_UDP:
            key = get_key(socket.inet_ntoa(ip_packet.src), socket.inet_ntoa(ip_packet.dst))
            udp_packets[key].append(
                [ts, socket.inet_ntoa(ip_packet.src), ip_packet.data.sport, socket.inet_ntoa(ip_packet.dst),
                 ip_packet.data.dport, (protocol, -1, -1), False])
        # Creates a ICMP packet
        elif protocol == dpkt.ip.IP_PROTO_ICMP:
            key = get_key(socket.inet_ntoa(ip_packet.src), socket.inet_ntoa(ip_packet.dst))
            icmp = ip_packet.data
            if icmp.data is not None:
                if icmp.data.data is not None:
                    if icmp.data.data.data is not None:
                        try:
                            # Notice how tricky this is.  The kind of ICMP packet we're looking for in the traffic
                            # will have a data entry in the ICMP envelope that is a mirror image of the packet that
                            # failed, because ICMP is Network (not Transport) generated message. Grab the information
                            # we need from there
                            dst_ip = socket.inet_ntoa(icmp.data.data.dst)
                            src_ip = socket.inet_ntoa(icmp.data.data.src)
                            dst_port = icmp.data.data.data.dport
                            src_port = icmp.data.data.data.sport
                            udp_packets[key].append(
                                [ts, src_ip, src_port, dst_ip,
                                 dst_port, (protocol, icmp.type, icmp.code), False])
                        except:
                            pass

    # Sort the packets numerically by time stamp
    for key in tcp_packets:
        tcp_packets[key].sort(key=lambda x: x[0])

    for key in udp_packets:
        udp_packets[key].sort(key=lambda x: x[0])

    return tcp_packets, udp_packets


#####################     SCAN TYPE DETERMINATORS   #############################################

def get_num_udp_scans(udp_packets):
    """
    Calculates the number of UDP port scans occured in a given buffer of packets.
    :param udp_packets: Packets to parse.
    :return: The number of port scans that occured with in the buffer of packets.
    """
    suspects = []
    open_ports = 0
    closed_ports = 0
    ports_already_seen = []

    # For each macro-conversation (conversation between two ip addresses without consideration to port)
    for key in udp_packets:
        # Break the packets into time slices
        packets_by_thresholds = breakup_packets_by_threshold(udp_packets[key], UDP_SAMPLING_INTERVAL_SEC)
        if len(packets_by_thresholds) > 0:
            for ip_src in packets_by_thresholds:
                packets_by_timeslice, left_overs = packets_by_thresholds[ip_src]
                if len(packets_by_timeslice) > 0:
                    # For each packet grouping by timeslice
                    for packet_group in packets_by_timeslice:
                        # Determine the number of ICMP type 3 code 3 packets we received
                        num_unique_icmp_ports = num_unique_icmp_ports_not_found(packet_group)

                        # Consider the ip suspcicious if the volume is met
                        if num_unique_icmp_ports > ICMP_UNIQUE_PORTS_VOLUME:
                            if ip_src not in suspects:
                                suspects.append(ip_src)
                        # Determine the number of unique ports to a source sent to a destination ip and port
                        num_unique_ports = num_unique_udp_ports(packet_group)
                        # If the threshold is met, mark as suspicious
                        if num_unique_ports > UDP_UNIQUE_PORTS_VOLUME:
                            if ip_src not in suspects:
                                suspects.append(ip_src)

        # For all packets from each suspicious IP address, count the number of ICMP type 3 code 3 and
        # UDP destination IPs and ports the suspicious IP address sent information to.
        for ip_addr in suspects:
            packets = find_packets_by_source_ip(udp_packets[key], ip_addr)

            for packet in packets:
                if packet[UDP_INFO][0] == dpkt.ip.IP_PROTO_ICMP:
                    if packet[UDP_INFO][1] == 3 and packet[UDP_INFO][2] == 3:
                        entry = (packet[DESTINATION_IP], packet[DESTINATION_PORT])
                        if entry not in ports_already_seen:
                            ports_already_seen.append(entry)
                            closed_ports += 1

            for packet in packets:
                if packet[UDP_INFO][0] == dpkt.ip.IP_PROTO_UDP:
                    entry = (packet[DESTINATION_IP], packet[DESTINATION_PORT])
                    if entry not in ports_already_seen:
                        ports_already_seen.append(entry)
                        open_ports += 1

    return open_ports + closed_ports


def get_num_xmas_scans(tcp_packets):
    """
    Gets the number unique ports scanned by a xmas scans

    :param tcp_packets: The dictionary of tcp packets discovered in the pcap file
    :return: Number of ports scanned by doing by a null scan
    """
    closed_xmas_scan = 0
    open_xmas_scan = 0

    suspects = []
    ip_to_ports_scanned = defaultdict(list)
    # Divide the ordered packet lists into thresholds, and measure how many packets were sent from a source
    # ip with the XMAS flags set.  If the volume is over the expected number of packets of that type in a time
    # interval, then mark the IP address as suspect.
    for key in tcp_packets:
        packets_by_thresholds = breakup_packets_by_threshold(tcp_packets[key], SAMPLING_INVERVAL_SEC)
        if len(packets_by_thresholds) > 0:
            for ip_src in packets_by_thresholds:
                packets_by_timeslice, left_overs = packets_by_thresholds[ip_src]
                if len(packets_by_timeslice) > 0:
                    for packet_group in packets_by_timeslice:
                        num_xmas_packs = get_xmas_number(packet_group)
                        if num_xmas_packs > XMAS_PACKETS_VOLUME:
                            if ip_src not in suspects:
                                suspects.append(ip_src)
                                break
        # For each suspect in the list, if the packet has not been parsed already, build a conversation,
        # and discern between the conversation's open and closed ports revealed by the XMAS scan.
        for ip_addr in suspects:
            packets_from_ip = find_packets_by_source_ip(tcp_packets[key], ip_addr)
            for packet in packets_from_ip:

                if not packet[ALREADY_PROCESSED]:
                    unordered_convo = find_packets_by_ip_port(tcp_packets[key], packet[SOURCE_IP], packet[SOURCE_PORT],
                                                              packet[DESTINATION_IP], packet[DESTINATION_PORT])

                    conversation = generate_tcp_conversation(unordered_convo)

                    if is_closed_xmas_scan(conversation):
                        to_store = (packet[DESTINATION_IP], packet[DESTINATION_PORT])
                        if to_store not in ip_to_ports_scanned[ip_addr]:
                            ip_to_ports_scanned[ip_addr].append(to_store)
                            closed_xmas_scan += 1
                            mark_as_processed(conversation)
                    elif is_open_xmas_scan(conversation):
                        to_store = (packet[DESTINATION_IP], packet[DESTINATION_PORT])
                        if to_store not in ip_to_ports_scanned[ip_addr]:
                            ip_to_ports_scanned[ip_addr].append(to_store)
                            open_xmas_scan += 1
                            mark_as_processed(conversation)

    return closed_xmas_scan + open_xmas_scan


def get_num_syn_scans(tcp_packets):
    """
    Gets the number unique ports scanned by a full_scan or half_scan port scan type

    :param tcp_packets: The dictionary of tcp packets discovered in the pcap file
    :return: Number of ports scanned but were closed, Number of ports scanned by doing a full TCP handshake,
            Number of ports scanned using half-scan techniques
    """

    closed_ports = 0
    half_open_scans_results = 0
    full_scan_results = 0

    suspects = []
    ip_to_ports_scanned = defaultdict(list)
    # Divide the ordered packet lists into thresholds, and measure how many packets were sent from a source
    # ip with the SYN flag set.  If the volume is over the expected number of packets of that type in a time
    # interval, then mark the IP address as suspect.
    for key in tcp_packets:
        packets_by_thresholds = breakup_packets_by_threshold(tcp_packets[key], SAMPLING_INVERVAL_SEC)
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

        # For each suspect list, if the packet has not been parsed already, build a conversation,
        # and discern between the conversation's open and closed ports revealed by
        # either a half-open or full-connect scan.
        for ip_addr in suspects:
            packets_from_ip = find_packets_by_source_ip(tcp_packets[key], ip_addr)
            for packet in packets_from_ip:

                if not packet[ALREADY_PROCESSED]:

                    unordered_conversation = find_packets_by_ip_port(tcp_packets[key], packet[SOURCE_IP],
                                                                     packet[SOURCE_PORT],
                                                                     packet[DESTINATION_IP], packet[DESTINATION_PORT])

                    conversation = generate_tcp_conversation(unordered_conversation)

                    # Determine if the scan is a a full connect scan, half scan, or a non-discernable closed scan
                    # (ie, the port was closed so who the heck knows)
                    if is_full_port_scan(conversation):
                        to_store = (packet[DESTINATION_IP], packet[DESTINATION_PORT])
                        if to_store not in ip_to_ports_scanned[ip_addr]:
                            ip_to_ports_scanned[ip_addr].append(to_store)
                            full_scan_results += 1
                            mark_as_processed(conversation)

                    elif is_half_port_scan(conversation):
                        to_store = (packet[DESTINATION_IP], packet[DESTINATION_PORT])
                        if to_store not in ip_to_ports_scanned[ip_addr]:
                            ip_to_ports_scanned[ip_addr].append(to_store)
                            half_open_scans_results += 1
                            mark_as_processed(conversation)

                    elif is_closed_port_scan(conversation):
                        to_store = (packet[DESTINATION_IP], packet[DESTINATION_PORT])
                        if to_store not in ip_to_ports_scanned[ip_addr]:
                            ip_to_ports_scanned[ip_addr].append(to_store)
                            closed_ports += 1
                            mark_as_processed(conversation)

    return closed_ports, half_open_scans_results, full_scan_results


def get_num_null_scans(tcp_packets):
    """
    Gets the number unique ports scanned by a null scans

    :param tcp_packets: The dictionary of tcp packets discovered in the pcap file
    :return: Number of ports scanned by doing by a null scan
    """
    closed_null_scan = 0
    open_null_scan = 0

    suspects = []
    ip_to_ports_scanned = defaultdict(list)
    # Divide the ordered packet lists into thresholds, and measure how many packets were sent from a source
    # ip with no flags set.  If the volume is over the expected number of packets of that type in a time
    # interval, then mark the IP address as suspect.
    for key in tcp_packets:
        packets_by_thresholds = breakup_packets_by_threshold(tcp_packets[key], SAMPLING_INVERVAL_SEC)
        if len(packets_by_thresholds) > 0:
            for ip_src in packets_by_thresholds:
                packets_by_timeslice, left_overs = packets_by_thresholds[ip_src]
                if len(packets_by_timeslice) > 0:
                    for packet_group in packets_by_timeslice:
                        num_null_packs = get_null_number(packet_group)
                        if num_null_packs > NULL_PACKETS_VOLUME:
                            if ip_src not in suspects:
                                suspects.append(ip_src)
                                break
        # For each suspect in the list, if the packet has not been parsed already, build a conversation,
        # and discern between the conversation's open and closed ports revealed by the null scan.
        for ip_addr in suspects:
            packets_from_ip = find_packets_by_source_ip(tcp_packets[key], ip_addr)
            for packet in packets_from_ip:

                if not packet[ALREADY_PROCESSED]:
                    unordered_conversation = find_packets_by_ip_port(tcp_packets[key], packet[SOURCE_IP],
                                                                     packet[SOURCE_PORT],
                                                                     packet[DESTINATION_IP], packet[DESTINATION_PORT])

                    conversation = generate_tcp_conversation(unordered_conversation)

                    if is_closed_null_scan(conversation):
                        to_store = (packet[DESTINATION_IP], packet[DESTINATION_PORT])
                        if to_store not in ip_to_ports_scanned[ip_addr]:
                            ip_to_ports_scanned[ip_addr].append(to_store)
                            closed_null_scan += 1
                            mark_as_processed(conversation)
                    elif is_open_null_scan(conversation):
                        to_store = (packet[DESTINATION_IP], packet[DESTINATION_PORT])
                        if to_store not in ip_to_ports_scanned[ip_addr]:
                            ip_to_ports_scanned[ip_addr].append(to_store)
                            open_null_scan += 1
                            mark_as_processed(conversation)

    return closed_null_scan + open_null_scan


########################   PACKET PARSING HELPERS ############################################


def is_open_xmas_scan(conversation):
    """
    Determines if a conversation between two sockets contains an open port from the XMAS scan.
    :param conversation: The ordered packets between two sockets across the network.
    :return: True if the port scan revealed an open port.
    """
    has_null = []
    has_rst = []

    for packet in conversation:
        if packet[TCP_FLAGS] == XMAS_TYPE:
            has_null.append(packet)

        if packet[TCP_FLAGS][RST_INDEX] is True:
            has_rst.append(packet)

    if len(has_null) > 0 and len(has_rst) == 0:
        return True

    return False


def is_closed_xmas_scan(conversation):
    """
    Determines if a conversation between two sockets contains a closed port from the XMAS scan.
    :param conversation: The ordered packets between two sockets across the network.
    :return: True if the port scan revealed a closed port.
    """
    has_null = []
    has_rst = []

    for packet in conversation:
        if packet[TCP_FLAGS] == XMAS_TYPE:
            has_null.append(packet)

        if packet[TCP_FLAGS][RST_INDEX] is True:
            has_rst.append(packet)

    for null in has_null:
        for rst in has_rst:
            if null[SOURCE_IP] == rst[DESTINATION_IP] and null[SOURCE_PORT] == rst[DESTINATION_PORT]:
                return True
    return False


def is_open_null_scan(conversation):
    """
    Determines if a conversation between two sockets contains an open port from the null scan.
    :param conversation: The ordered packets between two sockets across the network.
    :return: True if the port scan revealed an open port.
    """
    has_null = []
    has_rst = []

    for packet in conversation:
        if packet[TCP_FLAGS] == NULL_TYPE:
            has_null.append(packet)

        if packet[TCP_FLAGS][RST_INDEX] is True:
            has_rst.append(packet)

    if len(has_null) > 0 and len(has_rst) == 0:
        return True

    return False


def is_closed_null_scan(conversation):
    """
    Determines if a conversation between two sockets contains an closed port from the null scan.
    :param conversation: The ordered packets between two sockets across the network.
    :return: True if the port scan revealed a closed port.
    """
    has_null = []
    has_rst = []

    for packet in conversation:
        if packet[TCP_FLAGS] == NULL_TYPE:
            has_null.append(packet)

        if packet[TCP_FLAGS][RST_INDEX] is True:
            has_rst.append(packet)

    for null in has_null:
        for rst in has_rst:
            if null[SOURCE_IP] == rst[DESTINATION_IP] and null[SOURCE_PORT] == rst[DESTINATION_PORT]:
                return True
    return False


def is_full_port_scan(conversation):
    """
    Determines if a conversation between two sockets contains an open port from a full-connect SYN scan.
    :param conversation: The ordered packets between two sockets across the network.
    :return: True if the port scan revealed an open port.
    """
    has_syn = []
    has_rst = []
    has_syn_ack = []
    has_ack = []

    for packet in conversation:
        if packet[TCP_FLAGS] == SYN_TYPE:
            has_syn.append(packet)

        if packet[TCP_FLAGS][SYN_INDEX] is True and packet[TCP_FLAGS][ACK_INDEX] is True:
            has_syn_ack.append(packet)

        if packet[TCP_FLAGS][RST_INDEX] == 1:
            has_rst.append(packet)

        if packet[TCP_FLAGS][ACK_INDEX] is True and packet[TCP_FLAGS][SYN_INDEX] is not True:
            has_ack.append(packet)

    for syn_packet in has_syn:
        for syn_ack_packet in has_syn_ack:
            if ((syn_packet[DESTINATION_IP] == syn_ack_packet[SOURCE_IP])
                    and (syn_packet[DESTINATION_PORT] == syn_ack_packet[SOURCE_PORT])):

                for ack_packet in has_ack:
                    if ((ack_packet[SOURCE_IP] == syn_ack_packet[DESTINATION_IP])
                            and (ack_packet[SOURCE_PORT] == syn_ack_packet[DESTINATION_PORT])):

                        for rst_packet in has_rst:
                            if ((syn_packet[SOURCE_IP] == rst_packet[SOURCE_IP])
                                    and (syn_packet[SOURCE_PORT] == rst_packet[SOURCE_PORT])):
                                return True
    return False


def is_half_port_scan(conversation):
    """
    Determines if a conversation between two sockets contains an open port from a half-open SYN scan.
    :param conversation: The ordered packets between two sockets across the network.
    :return: True if the port scan revealed an open port.
    """
    has_syn = []
    has_rst = []
    has_syn_ack = []

    for packet in conversation:
        if packet[TCP_FLAGS] == SYN_TYPE:
            has_syn.append(packet)

        if packet[TCP_FLAGS][SYN_INDEX] is True and packet[TCP_FLAGS][ACK_INDEX] is True:
            has_syn_ack.append(packet)

        if packet[TCP_FLAGS][RST_INDEX] == 1:
            has_rst.append(packet)

    for syn_packet in has_syn:
        for syn_ack_packet in has_syn_ack:
            if ((syn_packet[DESTINATION_IP] == syn_ack_packet[SOURCE_IP])
                    and (syn_packet[DESTINATION_PORT] == syn_ack_packet[SOURCE_PORT])):

                for rst_packet in has_rst:
                    if ((syn_packet[SOURCE_IP] == rst_packet[SOURCE_IP])
                            and (syn_packet[SOURCE_PORT] == rst_packet[SOURCE_PORT])):
                        return True
    return False


def is_closed_port_scan(conversation):
    """
    Determines if a conversation between two sockets contains an open port from a closed SYN scan
    :param conversation: The ordered packets between two sockets across the network.
    :return: True if the port scan revealed a closed port.
    """
    has_syn = []
    has_rst_ack = []

    for packet in conversation:
        if packet[TCP_FLAGS] == SYN_TYPE:
            has_syn.append(packet)

        if packet[TCP_FLAGS][RST_INDEX] == 1:
            has_rst_ack.append(packet)

    for syn_packet in has_syn:
        for rst_ack_packet in has_rst_ack:
            if ((syn_packet[DESTINATION_IP] == rst_ack_packet[SOURCE_IP])
                    and (syn_packet[DESTINATION_PORT] == rst_ack_packet[SOURCE_PORT])):
                return True

    return False


def mark_as_processed(conversation):
    """
    Marks the given conversation's packets as already processed (dirty) to avoid duplicating parsing.
    :param conversation: The conversation of ordered packets between two network sockets.
    """
    for packet in conversation:
        packet[ALREADY_PROCESSED] = True


def get_syn_number(packets):
    """
    Gets number of syn packets from a list of packets
    :param packets: The packets
    :return: Number of SYN packets
    """
    num_syn_packs = 0
    if len(packets) > 0:
        for packet in packets:
            if packet[TCP_FLAGS] == SYN_TYPE:
                num_syn_packs += 1
    return num_syn_packs


def get_null_number(packets):
    """
    Gets number of null packets from a list of packets
    :param packets: The packets
    :return: Number of null packets
    """
    num_syn_packs = 0
    if len(packets) > 0:
        for packet in packets:
            if packet[TCP_FLAGS] == NULL_TYPE:
                num_syn_packs += 1
    return num_syn_packs


def num_unique_icmp_ports_not_found(packets):
    """
    Gets the number of unique destinations and ports from ICMP type 3 code 3 packets
    :param packets: The packets in a group.
    :return: The number of unique ICMP type 3 code 3 packets found in the list of packets.
    """
    ports_seen = []
    if len(packets) > 0:
        for packet in packets:
            if packet[UDP_INFO][0] == dpkt.ip.IP_PROTO_ICMP:
                if packet[UDP_INFO][1] == 3 and packet[UDP_INFO][2] == 3:
                    entry = (packet[DESTINATION_IP], packet[DESTINATION_PORT])
                    if entry not in ports_seen:
                        ports_seen.append(entry)
        return len(ports_seen)


def num_unique_udp_ports(packets):
    """
    Gets the number of unique destinations and ports from UDP packets
    :param packets: The packets in a group.
    :return: The number of unique UDP packets found in the list of packets.
    """
    ports_seen = []
    if len(packets) > 0:
        for packet in packets:
            entry = (packet[DESTINATION_IP], packet[DESTINATION_PORT])
            if entry not in ports_seen:
                ports_seen.append(entry)

    return len(ports_seen)


def get_xmas_number(packets):
    """
    Gets the number of XMAS flagged packets from a list of packets.
    :param packets: The list of packets.
    :return: Number of XMAS flagged tcp packets from the list.
    """
    num_syn_packs = 0
    if len(packets) > 0:
        for packet in packets:
            if packet[TCP_FLAGS] == XMAS_TYPE:
                num_syn_packs += 1
    return num_syn_packs


def breakup_packets_by_threshold(tcp_packets, sampling_interval):
    """
    Given an interval, break up packets by timeslices.
    :param tcp_packets: The packets to break up in a provided interval.
    :param sampling_interval: The interval in seconds.
    :return: Packets divided up by time slice, and any left overs.
    """
    ip_addresses = get_all_ip_addresses(tcp_packets)
    ip_to_time_slices = defaultdict(list)
    for ip_address in ip_addresses:
        all_packets = find_packets_by_source_ip(tcp_packets, ip_address)

        if len(all_packets) > 0:
            all_packets.sort(key=lambda x: x[0])

            packet_timeslices = []
            left_overs = []
            time_slice_index = 0
            threshold = all_packets[0][TIMESTAMP] + sampling_interval
            current_time = all_packets[0][TIMESTAMP]
            current_index = 0

            cant_split = False
            if all_packets[len(all_packets) - 1][TIMESTAMP] - current_time <= sampling_interval:
                cant_split = True
            if not cant_split:
                for i in range(0, len(all_packets)):
                    if current_time >= threshold:
                        packet_timeslices.append([])
                        for x in range(current_index, i):
                            packet_timeslices[time_slice_index].append(all_packets[x])
                        current_index = i
                        current_time = all_packets[i][TIMESTAMP]
                        threshold = current_time + sampling_interval
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
        elif ((packet[DESTINATION_IP] == source_ip) and (packet[DESTINATION_PORT] == source_port)
              and (packet[SOURCE_IP] == destination_ip) and (packet[SOURCE_PORT] == destination_port)):
            found.append(packet)

    return found


def find_packets_by_source_ip(tcp_packets, ip):
    """
    Finds packets in a list by source ip
    :param tcp_packets: The list of packets.
    :param ip: The source ip desired used as matching characteristics.
    :return: Packets from the provided source.
    """
    found = []
    for packet in tcp_packets:
        if packet[SOURCE_IP] == ip:
            found.append(packet)
    return found


def get_all_ip_addresses(tcp_packets):
    """
    Gets all participating IP address from a group of packets.
    :param tcp_packets: The packets.
    :return: All IP addresses participating in the list of packets.
    """
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
    if ((ip_packet.p == dpkt.ip.IP_PROTO_TCP)
            or (ip_packet.p == dpkt.ip.IP_PROTO_UDP)
            or (ip_packet.p == dpkt.ip.IP_PROTO_ICMP)):
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


def generate_tcp_conversation(from_source):
    """
    Create a conversation (packets between two ip addresses in time stamp order

    :param from_source: Unordered packet conversation
    :return: List of packets in conversation
    """
    # Create a ordered conversation between packets based on the information from the selected packet
    conversation = []
    for x in from_source:
        if not x[ALREADY_PROCESSED]:
            conversation.append(x)
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
