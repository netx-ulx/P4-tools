/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4     = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dst_addr;
    macAddr_t src_addr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t src_addr;
    ip4Addr_t dst_addr;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;    
}

header meta_count_min_header {
    bit<32> cm_hash_val_0;
    bit<32> cm_hash_val_1;
    bit<32> cm_hash_val_2;
    bit<32> cm_val_0;
    bit<32> cm_val_1;
    bit<32> cm_val_2;
    bit<32> cm_val_final;
}

header meta_bitmap_header {
    bit<32> bitmap_hash_val0;
    bit<32> bitmap_hash_val1;
    bit<32> bitmap_val0;
    bit<32> bitmap_val1;
} 

struct metadata_t {
    meta_count_min_header   meta_count_min; 
    meta_bitmap_header      meta_bitmap;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet, out headers hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata_t meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {

    register<bit<32>>(131072) cm_register_0;
    register<bit<32>>(131072) cm_register_1;  
    register<bit<32>>(131072) cm_register_2;  
    register<bit<32>>(131072) cm_register_final;

    register<bit<32>>(131072) bm_register_0;
    // Bitmap register for the source address.
    register<bit<32>>(131072) bm_register_final; 

    bit<32> cm_hash_0;
    bit<32> cm_hash_1;
    bit<32> cm_hash_2;

    bit<32> bm_hash_0;
    // Bitmap hash for the source address.
    bit<32> bm_hash_1;  

    action action_get_count_min_hash_0_val() {
        hash(cm_hash_0, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.version}, 
            (bit<32>)131072);
        meta.meta_count_min.cm_hash_val_0 = cm_hash_0;
    }

    action action_get_count_min_hash_1_val() {
        hash(cm_hash_1, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr, (bit<32>)hdr.ipv4.ihl}, 
            (bit<32>)131072);
        meta.meta_count_min.cm_hash_val_1 = cm_hash_1;
    }

    action action_get_count_min_hash_2_val() {
        hash(cm_hash_2, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)131072);
        meta.meta_count_min.cm_hash_val_2 = cm_hash_2;
    }

    action action_count_min_sketch_incr() {

        cm_register_0.read(meta.meta_count_min.cm_val_0, (bit<32>)meta.meta_count_min.cm_hash_val_0);
        cm_register_1.read(meta.meta_count_min.cm_val_1, (bit<32>)meta.meta_count_min.cm_hash_val_1);
        cm_register_2.read(meta.meta_count_min.cm_val_2, (bit<32>)meta.meta_count_min.cm_hash_val_2);

        meta.meta_count_min.cm_val_0 = meta.meta_count_min.cm_val_0 + 1;
        meta.meta_count_min.cm_val_1 = meta.meta_count_min.cm_val_1 + 1;
        meta.meta_count_min.cm_val_2 = meta.meta_count_min.cm_val_2 + 1;        

        cm_register_0.write((bit<32>)meta.meta_count_min.cm_hash_val_0, meta.meta_count_min.cm_val_0);
        cm_register_1.write((bit<32>)meta.meta_count_min.cm_hash_val_1, meta.meta_count_min.cm_val_1);
        cm_register_2.write((bit<32>)meta.meta_count_min.cm_hash_val_2, meta.meta_count_min.cm_val_2);
    }

    action action_count_min_register_write() {
        cm_register_final.write((bit<32>)meta.meta_count_min.cm_hash_val_2, meta.meta_count_min.cm_val_final);
    }       

    action action_bitmap_hash_0_val() {
        hash(bm_hash_0,
            HashAlgorithm.crc32_custom,
            (bit<32>)0,
            {hdr.ipv4.src_addr, hdr.ipv4.dst_addr},
            (bit<32>)131072);
        meta.meta_bitmap.bitmap_hash_val0 = bm_hash_0;
    }

    action action_bitmap_hash_1_val() {
        hash(bm_hash_1, 
            HashAlgorithm.crc32_custom, 
            (bit<32>)0, 
            {hdr.ipv4.src_addr}, 
            (bit<32>)131072);
        meta.meta_bitmap.bitmap_hash_val1 = bm_hash_1;
    }        

    action action_bitmap_check_pair() {

        // Check the bitmap value for the (ip src, ip dst) pair
        bm_register_0.read(meta.meta_bitmap.bitmap_val0, (bit<32>)meta.meta_bitmap.bitmap_hash_val0);
    }

    action action_bitmap_new_pair() {

        bm_register_final.read(meta.meta_bitmap.bitmap_val1, (bit<32>)meta.meta_bitmap.bitmap_hash_val1);

        bm_register_0.write((bit<32>)meta.meta_bitmap.bitmap_hash_val0, 1);
        bm_register_final.write((bit<32>)meta.meta_bitmap.bitmap_hash_val1, meta.meta_bitmap.bitmap_val1 + 1);
    }      
    
    apply {
       
        // Count-min sketch

        action_get_count_min_hash_0_val();
        action_get_count_min_hash_1_val();
        action_get_count_min_hash_2_val();
        action_count_min_sketch_incr();                
        
        meta.meta_count_min.cm_val_final = meta.meta_count_min.cm_val_0;
        
        if (meta.meta_count_min.cm_val_final > meta.meta_count_min.cm_val_1) {
            meta.meta_count_min.cm_val_final = meta.meta_count_min.cm_val_1;
        }
        
        if (meta.meta_count_min.cm_val_final > meta.meta_count_min.cm_val_2) {
            meta.meta_count_min.cm_val_final = meta.meta_count_min.cm_val_2;
        }

        action_count_min_register_write();  

        // Bitmap sketch

        action_bitmap_hash_0_val();

        // Check the bitmap value for the (ip src, ip dst) pair
        action_bitmap_check_pair();

        if (meta.meta_bitmap.bitmap_val0 == 0) {
            action_bitmap_hash_1_val();            
            // if the value is 0, we write the bitmap value on register0 and increase the counter
            // for the ip src on register1 (meaning that we have a new pair)
            action_bitmap_new_pair();
        }            

        return;
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr, inout metadata_t meta, inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata_t meta) {
     apply {  }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);        
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
