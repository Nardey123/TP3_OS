/*
 * clitcp.c : client TCP
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define LBUF 100

int main(int N, char*P[])
{
int sock;
struct sockaddr_in sin;
struct hostent *h;
char nom[LBUF], addr[LBUF];

    if (N != 3 ) {
        fprintf(stderr,"Utilisation : %s nom_serveur port\n",P[0]);
        exit(1);
    }
    /* initialisation socket */
    if ((sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)) < 0) {
        perror("socket");
        exit(2);
    }
    if(!(h=gethostbyname(P[1]))) {
        perror("gethostbyname");
        exit(3);
    }
    /* initialisation de sin */
    bzero(&sin,sizeof(sin));
    sin.sin_family = AF_INET;
    bcopy(h->h_addr,&sin.sin_addr,h->h_length);
    sin.sin_port = htons(atoi(P[2]));
    if (connect(sock,(struct sockaddr*)&sin,sizeof(sin)) < 0) {
        perror("connect");
        exit(4);
    }
    printf("Donner un nom de machine\n");
    fgets(nom,LBUF,stdin);
    write(sock,nom,strlen(nom));
    nom[strlen(nom)-1]='\0'; /* on supprime le \n */
    read(sock,addr,LBUF);
    if (strncmp(addr,"erreur !! ",10) == 0)
       printf("La machine %s n'existe pas !\n", nom);
    else
       printf("La machine %s a pour adresse IP %s\n",nom,addr);
    close(sock);
    return 0;
}


