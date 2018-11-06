#!/usr/bin/env python

import sctp
import binascii
import sys, socket
import time, IPy
from itertools import repeat
#for local testing: sudo ncat --sctp -l -p 36422

#interface 3GPP S1-MME

#verify that the following modules are loaded
#sudo insmod /lib/modules/3.6.11-4.fc16.i686/kernel/lib/libcrc32c.ko
#sudo insmod /lib/modules/3.6.11-4.fc16.i686/kernel/net/sctp/sctp.ko

#echo 1 > /proc/sys/net/sctp/max_init_retransmits

def usage():
    print "usage : python x2_pci_collision_server.py <dst ip > <local_ip>"
    exit(0)

if len(sys.argv) < 3 :
    usage()
    exit(0)

#pci set to 159,157,161 
payload = ("0006008ac9000004001500080022f2100000011000140089cd0540009f0022f210f"
           "4241015926022f210004c2c05dc55002e0022f210f4242010000105dc0022f210f4"
           "242020000005dc0022f210f4242030000205dc0022f210dbedd02000f505dc0022f"
           "210dbedd01000f305dc0022f210dbe7f010006005dc0022f210dbe7f030006105dc"
           "0022f210dbcd702000ac05dc0022f210dbea8040017b05dc0022f210dbd30020011"
           "105dc0022f210dbd30030011305dc0022f210dbf91010002905dc0022f210dbd810"
           "20007705dc0022f210dbcb5040003605dc0022f210dbf7f03000e105dc0022f210d"
           "be7f060006105dc0022f210dbc23040010705dc0022f210dbc23050010505dc0022"
           "f210dbf7f02000e305dc0022f210dbcb901001e605dc0022f210dbe7f040006005d"
           "c0022f210dbcac01001b705dc0022f210dbe7f050006205dc0022f210f424204000"
           "9d0c670022f210f424205000030c670022f210f424206000040c670022f210dbd54"
           "0100113189c0022f210dbd540200112189c0022f210dbd540300111189c0022f210"
           "dbc230100149189c0022f210dbc230200147189c0022f210dbcd50200193189c002"
           "2f210dbc4602001bf189c0022f210dbea8010018e189c0022f210dbeb4030009218"
           "9c0022f210dbdaf01001cc189c0022f210dbd55010010c189c0022f210dbd550200"
           "10b189c0022f210dbd55030010d189c0022f210dbe5a010013a189c0022f210dbcb"
           "5010012b189c0022f210dbe7f0100162189c0022f210dbe7f0300163189c0022f21"
           "0dbe66020005a189c0022f210dbcd50300194189c0022f210dbedb0300150189c40"
           "00a10022f210f4241025926022f210004c2c05dc55001f0022f210f424202000000"
           "5dc0022f210f4242010000105dc0022f210f4242030000205dc0022f210dbd30030"
           "011305dc0022f210dbcac01001b705dc0022f210dbea8040017b05dc0022f210dbf"
           "7f03000e105dc0022f210dbc23050010505dc0022f210dbea8050017a05dc0022f2"
           "10f424204000050c670022f210f424205000030c670022f210f424206000040c670"
           "022f210dbd540100113189c0022f210dbd540200112189c0022f210dbd540300111"
           "189c0022f210dbc230200147189c0022f210dbeb40100090189c0022f210dbeb402"
           "00091189c0022f210dbeb40300092189c0022f210dbeec01000e0189c0022f210db"
           "daf01001cc189c0022f210dbdaf02001cb189c0022f210dbdaf03001cd189c0022f"
           "210dbd55010010c189c0022f210dbd55020010b189c0022f210dbd55030010d189c"
           "0022f210dbdac0200172189c0022f210dbea8020018d189c0022f210dbea8010018"
           "e189c0022f210dbcd50300194189c0022f210dbe1302001bc189c40009f0022f210"
           "f4241035926022f210004c2c05dc5500290022f210f4242010000105dc0022f210f"
           "4242030000205dc0022f210f4242020000005dc0022f210dbedd02000f505dc0022"
           "f210dbedd01000f305dc0022f210dbcd702000ac05dc0022f210dbd30030011305d"
           "c0022f210dbd4202000b105dc0022f210dbf7f03000e105dc0022f210dbca301001"
           "0b05dc0022f210dbca3030010d05dc0022f210dbea8040017b05dc0022f210f4242"
           "04000050c670022f210f424205000030c670022f210f424206000040c670022f210"
           "dbd540100113189c0022f210dbd540200112189c0022f210dbd540300111189c002"
           "2f210dbe9003001e7189c0022f210dbc4602001bf189c0022f210dbc4603001c018"
           "9c0022f210dbcb90400196189c0022f210dbe1303001bd189c0022f210dbea80300"
           "18c189c0022f210dbe3201001d4189c0022f210dbedc010009a189c0022f210dbed"
           "b0300150189c0022f210dbe7903000ae189c0022f210dbcd705000ee189c0022f21"
           "0dbd55010010c189c0022f210dbe5a010013a189c0022f210dbe66010005b189c00"
           "22f210dbdaf01001cc189c0022f210dbea8010018e189c0022f210dbe66030005c1"
           "89c0022f210dbd55020010b189c0022f210dbe5a0300139189c0022f210dbcd7040"
           "00ed189c0022f210dbdaf03001cd189c0022f210dbe66020005a189c0022f210dbe"
           "5a0200138189c4000090022f210f4241045926022f2100052b70c6744001a0022f2"
           "10f424204000050c670022f210f424205000030c670022f210f424206000040c670"
           "022f210f4242010000105dc0022f210f4242020000005dc0022f210f42420300002"
           "05dc0022f210dbd30020011105dc0022f210dbcd702000ac05dc0022f210dbf7f03"
           "000e105dc0022f210dbea8040017b05dc0022f210dbf91010002905dc0022f210db"
           "d540100113189c0022f210dbd540200112189c0022f210dbd540300111189c0022f"
           "210dbc230100149189c0022f210dbc230200147189c0022f210dbcd50200193189c"
           "0022f210dbc4602001bf189c0022f210dbea8010018e189c0022f210dbeb4030009"
           "2189c0022f210dbdaf01001cc189c0022f210dbd55010010c189c0022f210dbd550"
           "20010b189c0022f210dbd55030010d189c0022f210dbe5a010013a189c0022f210d"
           "be7f0100162189c40000b0022f210f4241055926022f2100052b70c674400180022"
           "f210f424204000050c670022f210f424205000030c670022f210f424206000040c6"
           "70022f210f4242010000105dc0022f210f4242030000205dc0022f210f424202000"
           "0005dc0022f210dbea8040017b05dc0022f210dbf7f03000e105dc0022f210dbd54"
           "0100113189c0022f210dbd540200112189c0022f210dbd540300111189c0022f210"
           "dbc230200147189c0022f210dbeb40100090189c0022f210dbeb40200091189c002"
           "2f210dbeb40300092189c0022f210dbeec01000e0189c0022f210dbdaf01001cc18"
           "9c0022f210dbdaf02001cb189c0022f210dbdaf03001cd189c0022f210dbd550100"
           "10c189c0022f210dbd55020010b189c0022f210dbd55030010d189c0022f210dbda"
           "c0200172189c0022f210dbea8010018e189c40000a0022f210f4241065926022f21"
           "00052b70c6744001d0022f210f424204000050c670022f210f424205000030c6700"
           "22f210f424206000040c670022f210f4242010000105dc0022f210f424202000000"
           "5dc0022f210f4242030000205dc0022f210dbcd702000ac05dc0022f210dbd54010"
           "0113189c0022f210dbd540200112189c0022f210dbd540300111189c0022f210dbe"
           "9003001e7189c0022f210dbc4602001bf189c0022f210dbc4603001c0189c0022f2"
           "10dbcb90400196189c0022f210dbe1303001bd189c0022f210dbea8030018c189c0"
           "022f210dbe3201001d4189c0022f210dbedb0300150189c0022f210dbe7903000ae"
           "189c0022f210dbd55030010d189c0022f210dbd55010010c189c0022f210dbe5a03"
           "00139189c0022f210dbd55020010b189c0022f210dbdaf03001cd189c0022f210db"
           "e66010005b189c0022f210dbe5a010013a189c0022f210dbdaf01001cc189c0022f"
           "210dbe66030005c189c0022f210dbe66020005a189c001800060022f210801400c8"
           "4080d90b0022f210f4241010f80a0a010a000001f4100022f210f4241020f80a0a0"
           "10b000001f4100022f210f4241030f80a0a010c000001f4100022f210f4241040f8"
           "0a0a010d000001f4100022f210f4241050f80a0a010e000001f4100022f210f4241"
           "060f80a0a010f000001f4100022f210f4241070f80a0a0110000001f4100022f210"
           "f4241080f80a0a0111000001f4100022f210f4241090f80a0a0112000001f410002"
           "2f210f42410a0f80a0a0113000001f4100022f210f42410b0f80a0a0114000001f4"
           "100022f210f42410c0f80a0a0115000001f410")

dest_ip = sys.argv[1]

    
ip = IPy.IP(sys.argv[2])
local_ip = (ip.strNormal(0), 36422)
s = sctp.sctpsocket_tcp(socket.AF_INET)
s.bind(local_ip)
s.listen(1)
while 1 :
    opened_conn, client_address = s.accept()
    if dest_ip == client_address[0] :
        break

opened_conn.settimeout(5)

data = binascii.unhexlify(payload)
opened_conn.send(data)
time.sleep(1)
raw_input("press ESC to quit....")
s.close()
