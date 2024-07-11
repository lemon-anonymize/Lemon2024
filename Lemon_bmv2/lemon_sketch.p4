/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 5
#define PKT_INSTANCE_TYPE_RESUBMIT 6
#define HEAVY_T 100

#define T1 16384
#define T2 8192
#define T3 1024
#define T4 256

#define layer1_size 32w524288
#define layer2_size 32w65536
#define layer3_size 32w8192
#define layer4_size 32w2048
#define layer5_size 32w1024

#define layer1_size_bit1 32w4194304
#define layer2_size_bit1 32w2097152
#define layer3_size_bit1 32w524288
#define layer4_size_bit1 32w131072
#define layer5_size_bit1 32w524288

#define l1_bitmap 32w8
#define l2_bitmap 32w32
#define l3_bitmap 32w64
#define l4_bitmap 32w64
#define l5_bitmap 32w512

#define Hsize 32w8192

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> VirtualLAN= 0x8100;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;
const ether_type_t ETHERTYPE_IPV6 = 16w0x86dd;
const ether_type_t ETHERTYPE_VLAN = 16w0x8100;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;


header cpu_t {
    bit<32> hash;
    bit<32> hash1;
    bit<32> srcip;
    bit<32> dstip;
    bit<16> srcport;
    bit<16> dstport;
    bit<8> protocol;
    bit<32> counter;
    bit<16> epoch;
    bit <8> outputport;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    tos;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
    bit<48> payload;
}

header icmp_t {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
}

header vlan_tag_h {
    bit<3> pcp;
    bit<1> cfi;
    bit<12> vid;
    bit<16> type;
}

struct metadata {   
    bit<32>  dstip;
    bit<32>  srcip;
    bit<16>  srcport;
    bit<16>  dstport;
    bit<8>   protocol;
    bit<8>   kmvflag;
    bit<32>  khash;
    bit<32>  khash1;
    bit<32>  counter;
    bit<16>  epoch;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t        ipv4;
    cpu_t         cpu;
    udp_t        udp;
    tcp_t          tcp;
    icmp_t      icmp;
    vlan_tag_h vlan;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
 

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
 
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: ipv4;
            VirtualLAN:vlan;
            default: accept;
        }
    }
 
    state vlan{
        packet.extract(hdr.vlan);
        transition select(hdr.vlan.type){
            TYPE_IPV4: ipv4;
            default: accept;
        }
    }

    state ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            IP_PROTOCOLS_TCP : parse_tcp;
            IP_PROTOCOLS_UDP : parse_udp;
            IP_PROTOCOLS_ICMP : parse_icmp;
            default : accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

 
/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/


control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    register<bit<1>>(layer1_size_bit1) lemon_layer1;
    register<bit<1>>(layer2_size_bit1) lemon_layer2;
    register<bit<1>>(layer3_size_bit1) lemon_layer3;
    register<bit<1>>(layer4_size_bit1) lemon_layer4;
    register<bit<1>>(layer5_size_bit1) lemon_layer5;

    register<bit<16>>(4) hash_deep_threshold;

    register<bit<32>>(layer1_size) counter;

    register<bit<32>>(8192) lemon_heavy_id;

    register<bit<32>>(8192) lemon_heavy_tag;
 
    action deep_hash(in bit<32> ipv4_src, in bit<32> ipv4_dst, in bit<16> srcport, in bit<16> dstport, in bit<8> protocol, in bit<16> ipsum, in bit<16> checksum, in bit<32> seq_no, in bit<16> hdlen, in bit<48> payload,out bit<16> dhash){
        hash(dhash, HashAlgorithm.crc32_custom, 16w0, {ipv4_src, ipv4_dst,srcport,dstport,protocol,ipsum,checksum,seq_no,hdlen,payload}, 16w65535);
    }

    action slot_hash(in bit<32> ipv4_src, in bit<32> ipv4_dst, in bit<16> srcport, in bit<16> dstport, in bit<8> protocol, out bit<32> shash) {
        hash(shash, HashAlgorithm.crc32_custom, 32w0, {ipv4_src, ipv4_dst,srcport,dstport,protocol}, layer1_size);
    }

    action bitmap_hash(in bit<32> ipv4_src, in bit<32> ipv4_dst, in bit<16> srcport, in bit<16> dstport, in bit<8> protocol, in bit<16> ipsum, in bit<16> checksum, in bit<32> seq_no, in bit<16> hdlen, in bit<48> payload,out bit<32> bhash) {
        hash(bhash, HashAlgorithm.crc32_custom, 32w0, {ipv4_src, ipv4_dst,srcport,dstport,protocol,ipsum,checksum,seq_no,hdlen,payload}, l5_bitmap);
    }

    action routehash(in bit<32> ipv4_src, in bit<32> ipv4_dst, in bit<16> srcport, in bit<16> dstport, in bit<8> protocol, out bit<32> rhash) {
        hash(rhash, HashAlgorithm.crc32_custom, 32w00000000, {ipv4_src, ipv4_dst,srcport,dstport,protocol}, 32w3);
    }
    
    action slot_hash2(in bit<32> ipv4_src, in bit<32> ipv4_dst, in bit<16> srcport, in bit<16> dstport, in bit<8> protocol, out bit<32> shash) {
        hash(shash, HashAlgorithm.identity, 32w0, {ipv4_src, ipv4_dst,srcport,dstport,protocol}, layer1_size);
    }

    register<bit<32>>(Hsize) Heavy_dst;

    action forward(in bit<32> rhash){
        bit<9> finalport = 1;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        if(hdr.ipv4.ttl == 0)
            finalport = 10;
        standard_metadata.egress_spec = finalport+1; 
    }

    apply {
        //standard_metadata.egress_spec = 4;
        bit<32> rhash;
        //only if IPV4 the rule is applied. Therefore other packets will not be forwarded.
        if (hdr.ipv4.isValid()){
            //ipv4_lpm.apply();
            meta.srcip=hdr.ipv4.srcAddr;
            meta.dstip=hdr.ipv4.dstAddr;
            meta.protocol=hdr.ipv4.protocol;
        }

        bit<16> deep_h = 0;
	    bit<32> slot_h = 0;
        bit<32> slot_h2 = 0;
        bit<32> bitmap_h = 0;
        //hdr.ipv4.dstAddr = 1;

        if (hdr.tcp.isValid()) {
            //bloom_hash(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.src_port, hdr.tcp.dst_port,hdr.ipv4.protocol, hdr.tcp.checksum,hdr.tcp.seq_no,0,0, h1, h2, h3);
            
            deep_hash(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.src_port, hdr.tcp.dst_port,hdr.ipv4.protocol,hdr.ipv4.hdrChecksum, hdr.tcp.checksum,hdr.tcp.seq_no, 0, 0, deep_h);
            slot_hash(0, hdr.ipv4.dstAddr, 0, 0, 0, slot_h);
            bitmap_hash(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.src_port, hdr.tcp.dst_port,hdr.ipv4.protocol,hdr.ipv4.hdrChecksum, hdr.tcp.checksum,hdr.tcp.seq_no, 0, 0, bitmap_h);
            routehash(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.src_port, hdr.tcp.dst_port,hdr.ipv4.protocol, rhash);
            forward(rhash);
        }
        else if (hdr.udp.isValid()) {
            deep_hash(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.src_port, hdr.udp.dst_port, hdr.ipv4.protocol,hdr.ipv4.hdrChecksum, hdr.udp.checksum, 0,hdr.udp.hdr_length,hdr.udp.payload, deep_h);
            slot_hash(0, hdr.ipv4.dstAddr, 0, 0, 0,slot_h);
	        bitmap_hash(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.src_port, hdr.udp.dst_port, hdr.ipv4.protocol,hdr.ipv4.hdrChecksum, hdr.udp.checksum, 0,hdr.udp.hdr_length,hdr.udp.payload, bitmap_h);
            routehash(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.src_port, hdr.udp.dst_port,hdr.ipv4.protocol, rhash);
            forward(rhash);
        }else{
            deep_hash(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 0, 0, 0, hdr.ipv4.hdrChecksum, 0, 0, 0, 0, deep_h);
            slot_hash(0, hdr.ipv4.dstAddr, 0, 0, 0, slot_h);
	        bitmap_hash(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 0, 0, 0, hdr.ipv4.hdrChecksum, 0, 0, 0, 0, bitmap_h);
            routehash(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, 0, 0, 0, rhash);
            forward(rhash);
        }

        //slot_h = hdr.ipv4.dstAddr;
        bit<16> deep1;
        bit<16> deep2;
        bit<16> deep3;
        bit<16> deep4;

        hash_deep_threshold.write(0, T1);
        hash_deep_threshold.write(1, T2);
        hash_deep_threshold.write(2, T3);
        hash_deep_threshold.write(3, T4);

        hash_deep_threshold.read(deep1,0);
        hash_deep_threshold.read(deep2,1);
        hash_deep_threshold.read(deep3,2);
        hash_deep_threshold.read(deep4,3);

                   
        bit<32> counter_hash = 0;
        bit<32> counter_val = 0;
        counter_hash[18:0] = slot_h[18:0];
        counter.read(counter_val, counter_hash);
        counter_val = counter_val + 1;
        counter.write(counter_hash,counter_val);

        bit<16> roll = 0;
        if(deep_h<=deep4){
            bit<32> slot = 0;
            slot[18:9] = slot_h[9:0];
            slot[8:0] = bitmap_h[8:0]; //512
            lemon_layer5.write(slot,1);
        }
        if(deep_h<=deep3 && deep_h>deep4){
            bit<32> slot = 0;
            slot[16:6] = slot_h[10:0];
            slot[5:0] = bitmap_h[5:0]; //64
            lemon_layer4.write(slot,1);
        }
        if(deep_h<=deep2 && deep_h>deep3){
            //64
            //bit<16> roll = 0;
            bit<32> slot = 0;
            slot[18:6] = slot_h[12:0];
            slot[5:0] = bitmap_h[5:0]; //64
            lemon_layer3.write(slot,1);
        }
        if(deep_h<=deep1 && deep_h>deep2){
            //32
            //bit<16> roll = 0;
            bit<32> slot = 0;
            slot[20:5] = slot_h[15:0];
            slot[4:0] = bitmap_h[4:0]; //32
            lemon_layer2.write(slot,1);
        }
        if(deep_h>deep1){
            //32
            //bit<16> roll = 0;
            bit<32> slot = 0;
            slot[21:3] = slot_h[18:0];
            slot[2:0] = bitmap_h[2:0]; //8
            lemon_layer1.write(slot,1);
        }
        if(deep_h < deep3){
            bit<32> slot = 0;
            slot[12:0] = slot_h[12:0];
            lemon_heavy_id.write(slot,hdr.ipv4.dstAddr);
            lemon_heavy_tag.write(slot,slot_h);
        }
        hdr.ipv4.srcAddr[31:0] = 0;
        //hdr.ipv4.srcAddr[15:0] = roll;
        hdr.ipv4.identification[15:0] = deep_h;
        standard_metadata.egress_spec = 1;
    }
}

 

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
     //handle the cloned packet   meta.kmvflag   standard_metadata.instance_type != 0
     if (standard_metadata.instance_type != 0){
        hdr.ethernet.etherType =0x1234;       // EtherType 换成 0x1234，controller 用这个来过滤
        hdr.cpu.setValid();                                         // 把克隆的 packet 的 cpu header 设置成 valid
        hdr.vlan.setInvalid();                                         // 把克隆的 packet 的 cpu header 设置成 valid
        hdr.cpu.hash = meta.khash;
        hdr.cpu.hash1 = meta.khash1;
        hdr.cpu.srcip = meta.srcip;  
        hdr.cpu.dstip = meta.dstip;
        hdr.cpu.srcport = meta.srcport;
        hdr.cpu.dstport = meta.dstport;
        hdr.cpu.protocol = meta.protocol;
        hdr.cpu.counter = meta.counter;
        hdr.cpu.epoch= meta.epoch;
        hdr.cpu.outputport = standard_metadata.egress_spec[7:0];
        //truncate((bit<32>)22);                              // 截断 ether(48+48+16 bits)+cpu(48+16 bits) header = 22 bytes 之后的部分，因为我们只需要 cpu header 里面的信息作为 payload
     }
    }

}
 

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.tos,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

 
/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        //parsed headers have to be added again into the packet.
        packet.emit(hdr.ethernet);    
        packet.emit(hdr.vlan);    
        packet.emit(hdr.cpu);   
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
    }
}


/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
