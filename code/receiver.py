"""A Receiver for the GBN protocol."""

# Disable pylint rules which are incompatible with our naming conventions
# pylint: disable=C0103,W0221,W0201,R0902,R0913,R0201


import os
import random
import logging
import argparse
from scapy.sendrecv import send
from scapy.config import conf
from scapy.layers.inet import IP, ICMP
from scapy.packet import Packet, bind_layers
from scapy.fields import (BitEnumField, BitField, ShortField, ByteField,
                          ConditionalField)
from scapy.automaton import Automaton, ATMT


FORMAT = "   [RECEIVER:%(lineno)3s - %(funcName)12s()] %(message)s"
logging.basicConfig(format=FORMAT)
log = logging.getLogger('sender')
log.setLevel(logging.DEBUG)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# fixed random seed to reproduce packet loss
random.seed('TEST')


class GBN(Packet):
    """The GBN Header.

    It includes the following fields:
        type: DATA or ACK
        options: sack support
        len: payload length
        hlen: header length
        num: sequence/ACK number
        win: sender/receiver window size
    """
    name = 'GBN'
    fields_desc = [BitEnumField("type", 0, 1, {0: "data", 1: "ack"}),
                   BitField("options", 0, 7),
                   ShortField("len", None),
                   ByteField("hlen", 0),
                   ByteField("num", 0),
                   ByteField("win", 0),
                   ConditionalField(ByteField("block_len",0), lambda pkt:pkt.hlen>6),
                   ConditionalField(ByteField("left_1",0), lambda pkt:pkt.hlen>6),
                   ConditionalField(ByteField("len_1",0), lambda pkt:pkt.hlen>6),
                   ConditionalField(ByteField("pad1",0), lambda pkt:pkt.hlen>9),
                   ConditionalField(ByteField("left_2",0), lambda pkt:pkt.hlen>9),
                   ConditionalField(ByteField("len_2",0), lambda pkt:pkt.hlen>9),
                   ConditionalField(ByteField("pad2",0), lambda pkt:pkt.hlen>12),
                   ConditionalField(ByteField("left_3",0), lambda pkt:pkt.hlen>12),
                   ConditionalField(ByteField("len_3",0), lambda pkt:pkt.hlen>12)]


# GBN header is coming after the IP header
bind_layers(IP, GBN, frag=0, proto=222)


class GBNReceiver(Automaton):
    """Receiver implementation for the GBN protocol using a Scapy automaton.

    Attributes:
        win: Window size advertised by receiver
        n_bits: number of bits used to encode sequence number
        p_data: loss probability for data segments (0 <= p_data < 1)
        p_ack: loss probability for ACKs (0 <= p_ack < 1)
        sender: IP address of the sender
        receiver: IP address of the receiver
        next: Next expected sequence number
        out_file: Name of output file
        p_file: Expected payload size
        end_receiver: Can we close the receiver?
        end_num: Sequence number of last packet + 1

    """

    def parse_args(self, receiver, sender, nbits, out_file, window, p_data,
                   p_ack, chunk_size, **kargs):
        """Initialize the automaton."""
        Automaton.parse_args(self, **kargs)
        self.win = window
        self.n_bits = nbits
        assert self.win <= 2**self.n_bits
        self.p_data = p_data
        assert p_data >= 0 and p_data < 1
        self.p_ack = p_ack
        assert p_ack >= 0 and p_ack < 1
        self.sender = sender
        self.receiver = receiver
        self.next = 0
        self.out_file = out_file
        self.p_size = chunk_size
        self.end_receiver = False
        self.end_num = -1
        self.buffer = {}
        self.support_SACK = 1 # set to 1 in Q4.3.1
        self.use_SACK = 0 # set to 1 if sender give option 1 at least once in Q4.3.1

    def master_filter(self, pkt):
        """Filter packets of interest.

        Source has be the sender and both IP and GBN headers are required.
        No ICMP packets.
        """
        return (IP in pkt and pkt[IP].src == self.sender and GBN in pkt
                and ICMP not in pkt)

    @ATMT.state(initial=1)
    def BEGIN(self):
        """Start state of the automaton."""
        raise self.WAIT_SEGMENT()

    @ATMT.state(final=1)
    def END(self):
        """End state of the automaton."""
        log.debug("Receiver closed")

    @ATMT.state()
    def WAIT_SEGMENT(self):
        """Waiting state for new packets."""
        log.debug("Waiting for segment %s", self.next)

    @ATMT.receive_condition(WAIT_SEGMENT)
    def packet_in(self, pkt):
        """Transition: Packet is coming in from the sender."""
        raise self.DATA_IN(pkt)

    @ATMT.state()
    def DATA_IN(self, pkt):
        """State for incoming data."""
        num = pkt.getlayer(GBN).num
        payload = bytes(pkt.getlayer(GBN).payload)

        # received segment was lost/corrupted in the network
        if random.random() < self.p_data:
            log.debug("Data segment lost: [type = %s num = %s win = %s]",
                      pkt.getlayer(GBN).type,
                      num,
                      pkt.getlayer(GBN).win)
            raise self.WAIT_SEGMENT()

        # segment was received correctly
        else:
            log.debug("Received: [type = %s num = %s win = %s]",
                      pkt.getlayer(GBN).type,
                      num,
                      pkt.getlayer(GBN).win)

            # check if segment is a data segment
            ptype = pkt.getlayer(GBN).type
            if ptype == 0:

                '''
                # check if last packet --> end receiver
                if len(payload) < self.p_size:
                    self.end_receiver = True
                    self.end_num = (num + 1) % 2**self.n_bits

                # this is the segment with the expected sequence number
                if num == self.next:
                    log.debug("Packet has expected sequence number: %s", num)

                    # append payload (as binary data) to output file
                    with open(self.out_file, 'ab') as file:
                        file.write(payload)

                    log.debug("Delivered packet to upper layer: %s", num)

                    self.next = int((self.next + 1) % 2**self.n_bits)

                # this was not the expected segment
                else:
                    log.debug("Out of sequence segment [num = %s] received. "
                              "Expected %s", num, self.next)
                '''
                send_win = pkt.getlayer(GBN).win
                if send_win > self.win:
                    # sender does not know the correct window size yet, use a larger window to buffer
                    possible_win = max(send_win, self.win)
                else:
                    possible_win = min(send_win, self.win)

                # detect if we need to buffer
                if self.next + possible_win > 2**self.n_bits:
                    num_in_pwin = num >= self.next + 1 or num < (self.next + possible_win) % 2**self.n_bits
                else:
                    num_in_pwin = num >= self.next + 1 and num < self.next + possible_win
                
                if num == self.next:
                    log.debug("Packet has expected sequence number: %s", num)

                    # check if last packet --> end receiver
                    if len(payload) < self.p_size:
                        self.end_receiver = True
                        self.end_num = int((self.next + 1) % 2**self.n_bits)

                    # append payload (as binary data) to output file
                    with open(self.out_file, 'ab') as file:
                        file.write(payload)

                    log.debug("Delivered packet to upper layer: %s", num)

                    self.next = int((self.next + 1) % 2**self.n_bits)

                    while self.next in self.buffer:

                        pl = self.buffer.pop(self.next)

                        # check if last packet --> end receiver
                        if len(pl) < self.p_size:
                            self.end_receiver = True
                            self.end_num = int((self.next + 1) % 2**self.n_bits)
                        
                        # append payload (as binary data) to output file
                        with open(self.out_file, 'ab') as file:
                            file.write(pl)

                        log.debug("Delivered buffered packet to upper layer: %s", self.next)
                        
                        self.next = int((self.next + 1) % 2**self.n_bits)
                    
                elif num_in_pwin:
                    # buffer this payload
                    self.buffer[num] = payload
                    log.debug("Buffer packet: %s", num)
                
                else:
                    # Discard packets that we don't need
                    log.debug("Discard packet: %s", num)



            else:
                # we received an ACK while we are supposed to receive only
                # data segments
                log.error("ERROR: Received ACK segment: %s", pkt.show())
                raise self.WAIT_SEGMENT()

            # send ACK back to sender
            if random.random() < self.p_ack:
                # the ACK will be lost, discard it
                log.debug("Lost ACK: %s", self.next)

            # the ACK will be received correctly
            else:
                #default header length
                header_length = 6
                num_blocks = 0
                left_edge_arr = [0,0,0]
                len_block_arr = [0,0,0]
                sender_SACK = pkt.getlayer(GBN).options
                # use sack if both support
                if self.use_SACK == 0 and sender_SACK == 1 and self.support_SACK == 1:
                    self.use_SACK = 1
                if self.use_SACK == 1:
                    send_win = pkt.getlayer(GBN).win
                    prev_in_block = -5
                    for i in range(self.next + 1, self.next + possible_win):
                        packet_num = i % 2**self.n_bits
                        if packet_num in self.buffer:
                            # consecutive
                            if prev_in_block == packet_num -1 or (packet_num == 0 and prev_in_block == 2**self.n_bits -1):
                                prev_in_block = packet_num
                                # -1 because array index start from 0
                                len_block_arr[num_blocks-1] += 1
                            # new block if still have space
                            elif num_blocks < 3:
                                num_blocks += 1
                                left_edge_arr[num_blocks-1] = packet_num
                                len_block_arr[num_blocks-1] += 1
                                prev_in_block = packet_num
                    header_length += 3 * num_blocks

                # set header
                header_GBN = GBN(type="ack",
                                options=self.use_SACK,
                                len=0,
                                hlen=header_length,
                                num=self.next,
                                win=self.win,
                                block_len=num_blocks if num_blocks >=1 else None,
                                left_1=left_edge_arr[0] if num_blocks >=1 else None,
                                len_1=len_block_arr[0] if num_blocks >=1 else None,
                                pad1=0 if num_blocks >=2 else None,
                                left_2=left_edge_arr[1] if num_blocks >=2 else None,
                                len_2=len_block_arr[1] if num_blocks >=2 else None,
                                pad2=0 if num_blocks >=3 else None,
                                left_3=left_edge_arr[2] if num_blocks >=3 else None,
                                len_3=len_block_arr[2] if num_blocks >=3 else None)

                send(IP(src=self.receiver, dst=self.sender) / header_GBN,
                    verbose=0)

                # last packet received and all ACKs successfully transmitted
                # --> close receiver
                if self.end_receiver and self.end_num == self.next:
                    raise self.END()

            # transition to WAIT_SEGMENT to receive next segment
            raise self.WAIT_SEGMENT()


if __name__ == "__main__":
    # get input arguments
    parser = argparse.ArgumentParser('GBN receiver')
    parser.add_argument('receiver_IP', type=str,
                        help='The IP address of the receiver')
    parser.add_argument('sender_IP', type=str,
                        help='The IP address of the sender')
    parser.add_argument('n_bits', type=int,
                        help='The number of bits used to encode the sequence '
                        'number field')
    parser.add_argument('output_file', type=str,
                        help='Path to the output file (data from sender is '
                        'stored in this file)')
    parser.add_argument('window_size', type=int,
                        help='The window size of the receiver')
    parser.add_argument('data_l', type=float,
                        help='The loss probability of a data segment '
                        '(between 0 and 1.0)')
    parser.add_argument('ack_l', type=float,
                        help='The loss probability of an ACK '
                        '(between 0 and 1.0)')
    parser.add_argument('--interface', type=str, help='(optional) '
                        'interface to listen on')

    args = parser.parse_args()

    if args.interface:
        conf.iface = args.interface

    output_file = args.output_file    # filename of output file
    size = 2**6                       # normal payload size
    bits = args.n_bits
    assert bits <= 8

    # delete previous output file (if it exists)
    if os.path.exists(output_file):
        os.remove(output_file)

    # initial setup of automaton
    GBN_receiver = GBNReceiver(args.receiver_IP, args.sender_IP, bits,
                               output_file, args.window_size, args.data_l,
                               args.ack_l, size)
    # start automaton
    GBN_receiver.run()
