#include <core.p4>
#include <v1model.p4>

// either hereby or in a headers.p4 file to include, you must define headers and metadata for your program
struct headers {}
struct metadata {}


/*************************************************************************
************   PARSER  **************************************************
*************************************************************************/

parser MyParser(packet_in pkt, out headers hdr, inout metadata meta, inout standard_metadata_t std_meta){

	// TODO: here you must write down the code to parse and extract Ethernet/IPv4/TCP
	state start {
                transition accept;
        }
	
}
	

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  } // you can leave this empty
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

	// TODO fill in your program logic into this block
    apply {
  	}
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  } // you can leave this empty
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply { } // you can leave this empty
}

/*************************************************************************      
***********************  D E P A R S E R  ******************************* 
*************************************************************************/      
                                             
control MyDeparser(packet_out pkt, in headers hdr) { 
    apply {  
		// don't forget to deparse your packets
    } 
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
