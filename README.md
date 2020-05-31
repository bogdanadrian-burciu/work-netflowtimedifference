# work-netflowtimedifference
Calculate difference between NetFlow v9 and IPFIX flowStartMilliseconds values for flows generated for same customer traffic payload, one flow for pre- and another flow for post- Source NAT.

The idea is to check the delta between flowStartMilliseconds (Source: https://www.iana.org/assignments/ipfix/ipfix.xhtml) of pre- and post- NAT traffic flows to determine if NF/IPFIX exporters are in sync.  
From the beginning we should settle what defines two flows as common/identical and given the only aspect known is we’re handling pre- and post- CGNAT 5-tuple flows, I can only assume the NAT imposed is Source NAT so the source socket will get changed between the two 5-tuple IP sessions. To this we add the NF ODID, a 1:1 mapping between pre-CGNAT VLAN 310 traffic and the exporter, with 320 for post-CGNAT traffic respectively. And we can also expect the NF exporter-identified L7 applications to be the same, given that same app signatures are used.

I've spent many days to put together a Python script for finding common NetFlow/IPFIX flows from a PCAP and even though I could not read and parse the PCAP itself in Python (as far as I studied online resources the project https://github.com/bitkeks/python-netflow-v9-softflowd got closest but I did not succeed to implement this work), I managed to get some results while having as input the PCAP exported as CSV (while having cflow.od_id, cflow.pie.ixia.l7-application-name, cflow.dstaddr and cflow.dstport applied as columns in the Wireshark UI table, steps: 
#1 Filter PCAP in Wireshark by (cflow && !icmp), 
#2 File > Export Packet Dissections > As CSV, 
#3 File > Export Packet Dissections > As JSON, 
#4 Excel > Data tab > Get data > CSV > set Data Type Detection to "Do not detect data type" > save as .xlsx) and JSON (to be able to access the information cflow.abstimestart of a certain IPFIX flow, since I found Wireshark export to CSV to be limited to 255 characters).

My Python script does the following:
-	Read values from .xlsx columns for the number and ODID of the frame and the IPFIX flows’ l7app, destination port, destination IP address;
-	Read all PCAP data from JSON and will later decide what frame and flow should be polled for startTime in the format ‘Jul 10, 2019 11:53:30.922000’;
-	Have this data moved to dictionaries to work easier with accessing a specific flow;
-	Iterate through frames with an index i (and its content of elements with index ii) and compare it with next frames (index j, elements indexed jj) and check:
o	Check if ODID is different (one ODID was use for pre-SNAT and another for post-SNAT) between NetFlow/IPFIX frames frame#1 and frame#2;
o	If yes, check each flow of frame#1 vs each flow of frame#2 if destination address is the same;
o	If yes, check each flow of frame#1 vs each flow of frame#2 if destination port is the same;
o	If yes, poll the startTime from each frame and calculate the absolute value of the difference between these two values:
o	If difference (at milliseconds level) is less or equal than 6000 (report was of 5 seconds difference observed) then save and write the metadata and resulted difference to a doc file.

The above logic does provide results, but the nested loops make the Python interpreter take really long time if the number of frames in the CSV/JSON is increasing. I’ve used dictionaries and these need a lot of memory table lookups it seems, so it would probably benefit it’d switch to lists, but for now I believe the purpose has been reached.

