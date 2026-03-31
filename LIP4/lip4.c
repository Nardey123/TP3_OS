/* liste des interfaces reseaux avec les adresses IPv4 et de broadcasts */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_link.h>

int main(int N, char *P[])
{
struct ifaddrs *ifaddr, *ifa;
int family, e, n;
char adip[NI_MAXHOST];
char bcast[NI_MAXHOST];
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs"); return 1;
    }
    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
        if (ifa->ifa_addr == NULL) continue;
        if ((family = ifa->ifa_addr->sa_family) != AF_INET) continue;
        if ((e=getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                    adip, NI_MAXHOST, NULL, 0, NI_NUMERICHOST))) {
           printf("getnameinfo() failed: %s\n", gai_strerror(e)); return 1;
        }
        if((e=getnameinfo(ifa->ifa_broadaddr, sizeof(struct sockaddr_in),
                    bcast, NI_MAXHOST, NULL, 0, NI_NUMERICHOST))) {
           printf("getnameinfo(2) failed: %s\n", gai_strerror(e)); return 1;
        }
        printf("%-13sadresse: <%s>\tbcast: <%s>\n",ifa->ifa_name,adip,bcast);
    }
    freeifaddrs(ifaddr);
    return 0;
}


