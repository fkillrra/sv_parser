#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h> //ethernet header
#include <netinet/ip.h>   //ip header
#include <netinet/tcp.h>  //tcp header
#include <arpa/inet.h>    //inet_ntoa()

struct ether_header *ethh;

struct Virtual_LAN {
    uint16_t id;
    uint16_t type;
}*virtual_lanh;

struct sample_value {
    uint16_t appid;
    uint16_t length;
    uint16_t reserved1;
    uint16_t reserved2;
    uint8_t tag;
    uint8_t len;
}*sv;

void ethernet_dump(const u_char* packet);
void virtual_lan_dump(const u_char* packet);
void sv_dump(const u_char* packet);
void callback(u_char* handle, const struct pcap_pkthdr* header, const u_char* packet);
void usage()
{
  printf("sysntax : sv_parser <interface>\n");
  printf("sample@linux~$ ./sv_parser ens33\n");
}

void printByHexData(uint8_t *printArr, int len)
{
    for(int i = 0; i < len; i++)
    {
        if(i % 16 == 0)
            printf("\n");
        printf("%02x ", printArr[i]);
    }
}

int main(int argc, char* argv[])
{
  // usage error check!
  if(argc != 2)
  {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];  // errbuf
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);  // packet descripter

  dev = pcap_lookupdev(errbuf);

  // device error check!
  if(handle == NULL)
  {
    fprintf(stderr,"Couldn't open device : %s : %s\n",dev,errbuf);
    return -1;
  }
  printf("dev : %s\n",dev);

  pcap_loop(handle,0,callback,NULL);
  return 0;
}

void callback(u_char* handle, const struct pcap_pkthdr* header, const u_char* packet)
{
  // Ethernet header
  ethernet_dump(packet);
  packet += sizeof(struct ether_header);

  // next heaeder Virtual LAN
  if(ntohs(ethh->ether_type) == 0x8100)
  {
      virtual_lan_dump(packet);
      packet += sizeof(struct Virtual_LAN);
      sv_dump(packet);
  }
}

void ethernet_dump(const u_char* packet)
{
    ethh = (struct ether_header *)packet;
    printf("\n[Layer 2] DataLink\n");
    printf("[*]Dst Mac address[*] : ");

    for(int i = 0; i < 6; i++)
    {
       printf("%02x", packet[i]);
       if (i != 5)
        printf(":");
    }
    printf("\n");
    printf("[*]Src Mac address[*] : ");
    for(int i = 6; i < 12; i++)
    {
       printf("%02x", packet[i]);
       if (i != 11)
        printf(":");
    }
    printf("\n");
}

void virtual_lan_dump(const u_char* packet)
{
    virtual_lanh = (struct Virtual_LAN *)packet;
    printf("\n[Layer 3] High-Level Link\n");
    printf("[*]ID[*] : %d\n", ntohs(virtual_lanh->id));
    printf("[*]Type[*] : %#x\n", ntohs(virtual_lanh->type));
}

void sv_dump(const u_char* packet)
{
    sv = (struct sample_value *)packet;
    printf("\n[Sample Value] \n");
    printf("[*]APPID[*] : %#x\n", ntohs(sv->appid));
    printf("[*]Length[*] : %d\n", ntohs(sv->appid));
    printf("[*]Reserved 1[*] : %#x\n", ntohs(sv->reserved1));
    printf("[*]Reserved 2[*] : %#x\n", ntohs(sv->reserved2));
    printf("[DEBUG] tag : %#x | len : %#x\n", sv->tag, sv->len);

    packet += sizeof(struct sample_value);
    printByHexData(packet, sv->len);

    printf("\n");
}
