#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h> 
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "ethhdr.h"
#include <iostream>
using namespace std;

struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip>\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}


/* 디바이스 이름을 입력받아 맥주소를 가져오는 함수*/
int GetInterfaceMacAddress(const char *ifname, char *mac)
{
    uint8_t *mac_addr;
    struct ifreq ifr;
    int sockfd, ret;

    //네트워크 인터페이스 소켓을 연다.
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        perror("sockfd");
        return -1;
    }
    
    //ioctl함수로 맥주소를 가져온다.
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);  
    if (ret < 0) {
      perror("ioctl");
      close(sockfd);
      return -1;
    }
    mac_addr = (uint8_t *)(ifr.ifr_hwaddr.sa_data); 
    close(sockfd);

    sprintf(mac,"%02x:%02x:%02x:%02x:%02x:%02x",mac_addr[0],mac_addr[1],mac_addr[2],mac_addr[3],mac_addr[4],mac_addr[5]); //맥주소를 parmeter로 복사
    return 0;
}

/* 디바이스 이름을 입력바아 ip주소를 가져오는 함수*/
int GetInterfaceIPAddress(const char *ifname, char *ip)
{
    struct ifreq ifr;
    int sockfd, ret;
    char ip_addr[40];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        perror("sockfd");
        return -1;
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
    if (ret < 0) {
      perror("ioctl");
      close(sockfd);
      return -1;
    }
    close(sockfd);
    
    inet_ntop(AF_INET,ifr.ifr_addr.sa_data+2,ip_addr,sizeof(struct sockaddr));
    sprintf(ip,"%s",ip_addr); 
    return 0;
}

/*패킷 포인터와 헤더 value를 입력받아 패킷을 채워주는 함수*/
int make_packet(struct EthArpPacket *packet, char *ethdmac, char *ethsmac, int op, char *arpsmac, char *arpsip, char *arptmac, char *arptip)
{
    packet->eth_.dmac_= Mac(ethdmac);
	packet->eth_.smac_ = Mac(ethsmac);
	packet->eth_.type_ = htons(EthHdr::Arp);

	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;
	packet->arp_.op_ = htons(op);
	packet->arp_.smac_ = Mac(arpsmac);
	packet->arp_.sip_ = htonl(Ip(arpsip));
	packet->arp_.tmac_ = Mac(arptmac);
	packet->arp_.tip_ = htonl(Ip(arptip));
    return 0;
}

/*헤더 정보가 내가 받아야 하는 응답 패킷의 정보와 일치하는지 확인하는 함수*/
bool is_Reply(struct EthHdr *ethhdr,struct ArpHdr *arphdr, char *memac,char *meip, char *vip) {
	if(ntohs(ethhdr->type_)!=0x0806)	return false;   //arp패킷이 아닌 경우
    if(ethhdr->dmac_ != Mac(memac) || arphdr->op()!= ArpHdr::Reply || arphdr->sip_!= htonl(Ip(vip)) || arphdr->tmac_ != Mac(memac) || arphdr->tip_!= htonl(Ip(meip)))  
        {
            printf("ARP BUT WRONG");
            return false;   //arp패킷이지만 정보가 일치하지 않는 경우
        }
    return true;
}