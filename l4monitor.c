#include <uapi/linux/bpf.h>      // Definition of struct __sk_buff, the
                                 // parameter passed to our eBPF program
#include <uapi/linux/pkt_cls.h>  // Definition of valid return codes for eBPF
                                 // programs attached to the TC hook (e.g.
                                 // TC_ACT_OK)

#include <uapi/linux/if_ether.h> // Definition of struct ethhdr
#include <uapi/linux/ip.h>       // Definition of struct iphdr
#include <uapi/linux/tcp.h>      // Definition of struct tcphdr
#include <uapi/linux/udp.h>      // Definition of struct udphdr


// Define a structure containing the values for each entry of the map
struct l3proto_value {
    long count;
    long bytes;
} __attribute__((packed));
// __attribute__((packed)) guarantees that the compiler doesn't add padding
// inside the struct to optimize access. Padding can sometimes cause errors with
// the eBPF verifier.
struct l3proto_key {
    u_int32_t saddr;
    u_short sport;
    u_int32_t daddr;
    u_short dport;
    u_int8_t proto;
} __attribute__((packed));

// Define a hash map with key of type uint16_t (the size of the ethertype),
// value of type struct l3proto_value and a max size of 1024 elements
BPF_HASH(l4map, struct l3proto_key, struct l3proto_value, 64);


int monitor(struct __sk_buff *ctx) {
    // Retrieve pointers to the begin and end of the packet buffer
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Interpret the first part of the packet as an ethernet header
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;

    u_int32_t s_addr = 0;
    u_int32_t d_addr = 0;
    u_short s_port = 0;
    u_short d_port = 0;
    u_int8_t protocol = 0;

    // Every time we access the packet buffer the eBPF verifier requires us to
    // explicitly check that the address we are accessing doesn't exceed the
    // buffer limits
    if (data + sizeof(*eth) > data_end) {
        // The packet is malformed, the TC_ACT_SHOT return code instructs the
        // kernel to drop it
        return TC_ACT_SHOT;
    }else{
        data += sizeof(*eth);
        ip = (struct iphdr *)data;
        s_addr = ip->saddr;
        d_addr = ip->daddr;
        protocol = ip->protocol;
    }

    if (data + sizeof(struct iphdr) > data_end) {
        return TC_ACT_SHOT;
    }else{
        data += sizeof(struct iphdr);
        if(protocol == 0x6){
            if(data + sizeof(struct tcphdr) > data_end){
                return TC_ACT_SHOT;
            }
            tcp = (struct tcphdr *)data;
            s_port = tcp->source;
            d_port = tcp->dest;
        }
        if(protocol == 0x11){
            if(data + sizeof(struct udphdr) > data_end){
                return TC_ACT_SHOT;
            }
            udp = (struct udphdr *)data;
            s_port = tcp->source;
            d_port = tcp->dest;
        }
    }

    //Prepare the new key
    struct l3proto_key key = {
        .saddr = (u_int32_t)s_addr,
        .sport = (u_short)s_port,
        .daddr = (u_int32_t)d_addr,
        .dport = (u_short)d_port,
        .proto = (u_int8_t)protocol
    };

    // Prepare a new entry for the map in case the protocol has not been added yet
    struct l3proto_value value = {
        .count = 0,
        .bytes = 0
    };

    // The lookup_or_try_init is syntactic sugar provided by BCC, it looks for
    // an element and if it doesn't exist creates a new entry and initializes it
    // with the value provided (internally it relies on the
    // bpf_map_lookup_elem() and bpf_map_update_elem() eBPF helpers)
    struct l3proto_value *map_value =
            l4map.lookup_or_try_init(&key, &value);

    // In the same way as with packet buffer every time we want to de-reference
    // a pointer the verifier requires us to check if it is valid (in this case
    // value could be NULL if the eBPF map was full)
    if (!map_value) {
        return TC_ACT_OK;
    }

    // Our eBPF program could be executed concurrently on multiple cores of the
    // machine, the __sync_fetch_and_add() instruction guarantees an atomic
    // operation
    __sync_fetch_and_add(&map_value->count, 1);
    __sync_fetch_and_add(&map_value->bytes, (data_end - data));

    // The TC_ACT_OK return code lets the packet proceed up in the network stack
    // for ingress packets or out of a net device for egress ones
    return TC_ACT_OK;
}

