/*
 * biceps.c - version 3
 * On passe en multi-threading pour partager la liste des contacts
 * entre le shell et le serveur UDP, sans risque d'attaque man-in-the-middle.
 * On ajoute aussi un serveur TCP pour partager des fichiers.
 *
 * Compilation : gcc -Wall -Wextra -o biceps biceps.c -lpthread
 * Avec traces : gcc -Wall -Wextra -DTRACE -o biceps biceps.c -lpthread
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* pour deboguer : -DTRACE active les messages de niveau 1,
   -DTRACE2 active aussi le niveau 2 (plus verbeux) */
#ifdef TRACE
#define TRACEF(...) fprintf(stderr, "[TRACE] " __VA_ARGS__)
#else
#define TRACEF(...) ((void)0)
#endif

#ifdef TRACE2
#define TRACEF2(...) fprintf(stderr, "[TRACE2] " __VA_ARGS__)
#else
#define TRACEF2(...) ((void)0)
#endif

#define BEUIP_PORT      9998
#define TCP_PORT        9998
#define BEUIP_MAGIC     "BEUIP"
#define BEUIP_MAGIC_LEN 5
#define MAX_MSG         512
#define LPSEUDO         23
#define BEUIP_BROADCAST "192.168.88.255"

/* un contact = son pseudo + son IP */
struct elt {
    char        nom[LPSEUDO + 1];
    char        adip[16];
    struct elt *next;
};

/* la liste des contacts, partagee entre le thread UDP et le shell */
static struct elt      *liste        = NULL;
static pthread_mutex_t  mutex_liste  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t  mutex_send   = PTHREAD_MUTEX_INITIALIZER;

static char self_pseudo[LPSEUDO + 1];
static char reppub[256] = "pub";

static int  udp_sock        = -1;
static int  tcp_sock_listen = -1;

/* flags pour demander aux threads de s'arreter */
static volatile int stop_udp      = 0;
static volatile int stop_tcp      = 0;
static volatile int serveur_actif = 0;

static pthread_t th_udp;
static pthread_t th_tcp;

/* --- liste chainee --- */

/* ajoute un contact ou met a jour son pseudo si l'IP est deja la.
   la liste reste triee alphabetiquement par pseudo. */
void ajouteElt(char *pseudo, char *adip)
{
    struct elt *nouv, *prev, *cur;

    pthread_mutex_lock(&mutex_liste);

    /* si on connait deja cette IP, on met juste le pseudo a jour */
    for (cur = liste; cur; cur = cur->next) {
        if (strcmp(cur->adip, adip) == 0) {
            strncpy(cur->nom, pseudo, LPSEUDO);
            cur->nom[LPSEUDO] = '\0';
            pthread_mutex_unlock(&mutex_liste);
            TRACEF("ajouteElt: mise a jour %s (%s)\n", pseudo, adip);
            return;
        }
    }

    nouv = malloc(sizeof(struct elt));
    if (!nouv) {
        perror("malloc ajouteElt");
        pthread_mutex_unlock(&mutex_liste);
        return;
    }
    strncpy(nouv->nom, pseudo, LPSEUDO);
    nouv->nom[LPSEUDO] = '\0';
    strncpy(nouv->adip, adip, 15);
    nouv->adip[15] = '\0';
    nouv->next = NULL;

    /* on cherche ou inserer pour rester trie */
    if (!liste || strcmp(pseudo, liste->nom) < 0) {
        nouv->next = liste;
        liste = nouv;
    } else {
        prev = liste;
        cur  = liste->next;
        while (cur && strcmp(pseudo, cur->nom) >= 0) {
            prev = cur;
            cur  = cur->next;
        }
        nouv->next = cur;
        prev->next = nouv;
    }

    pthread_mutex_unlock(&mutex_liste);
    TRACEF("ajouteElt: ajout %s (%s)\n", pseudo, adip);
}

/* retire un contact par son IP (quand il se deconnecte) */
void supprimeElt(char *adip)
{
    struct elt *prev = NULL, *cur;

    pthread_mutex_lock(&mutex_liste);
    cur = liste;
    while (cur) {
        if (strcmp(cur->adip, adip) == 0) {
            if (prev)
                prev->next = cur->next;
            else
                liste = cur->next;
            TRACEF("supprimeElt: %s (%s)\n", cur->nom, adip);
            free(cur);
            break;
        }
        prev = cur;
        cur  = cur->next;
    }
    pthread_mutex_unlock(&mutex_liste);
}

/* affiche tous les contacts au format "IP : pseudo" */
void listeElts(void)
{
    struct elt *cur;

    pthread_mutex_lock(&mutex_liste);
    for (cur = liste; cur; cur = cur->next)
        printf("%s : %s\n", cur->adip, cur->nom);
    pthread_mutex_unlock(&mutex_liste);
}

/* vide la liste entierement (appele apres beuip stop, sans verrou) */
static void viderListe(void)
{
    struct elt *cur = liste, *next;
    while (cur) {
        next = cur->next;
        free(cur);
        cur = next;
    }
    liste = NULL;
}

/* --- construction et lecture des datagrammes BEUIP --- */

/* construit un datagramme : code + "BEUIP" + payload */
static int build_message(char *out, size_t outsz,
                         char code, const void *payload, size_t plen)
{
    if (outsz < (size_t)(1 + BEUIP_MAGIC_LEN) ||
        plen > outsz - (size_t)(1 + BEUIP_MAGIC_LEN))
        return -1;
    out[0] = code;
    memcpy(out + 1, BEUIP_MAGIC, BEUIP_MAGIC_LEN);
    if (payload && plen)
        memcpy(out + 1 + BEUIP_MAGIC_LEN, payload, plen);
    return (int)(1 + BEUIP_MAGIC_LEN + plen);
}

/* verifie le magic et extrait le code + payload */
static int parse_message(const char *buf, int n,
                         char *code, const char **payload, size_t *plen)
{
    if (n < (int)(1 + BEUIP_MAGIC_LEN))
        return -1;
    if (memcmp(buf + 1, BEUIP_MAGIC, BEUIP_MAGIC_LEN) != 0)
        return -1;
    *code    = buf[0];
    *payload = buf + 1 + BEUIP_MAGIC_LEN;
    *plen    = (size_t)(n - (1 + BEUIP_MAGIC_LEN));
    return 0;
}

/* envoie un datagramme BEUIP a une IP precise */
static int send_beuip_to(const char *adip, char code,
                         const void *payload, size_t plen)
{
    char msg[MAX_MSG];
    int  mlen, r;
    struct sockaddr_in dst;

    mlen = build_message(msg, sizeof(msg), code, payload, plen);
    if (mlen < 0) return -1;

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port   = htons(BEUIP_PORT);
    if (inet_pton(AF_INET, adip, &dst.sin_addr) != 1)
        return -1;

    /* le mutex evite que deux threads envoient en meme temps */
    pthread_mutex_lock(&mutex_send);
    r = (int)sendto(udp_sock, msg, (size_t)mlen, 0,
                    (const struct sockaddr *)&dst, sizeof(dst));
    pthread_mutex_unlock(&mutex_send);
    return r;
}

/* envoie un broadcast sur toutes les interfaces reseau (sauf loopback).
   on utilise getifaddrs pour ne pas etre lies a une adresse fixe. */
static void send_broadcast_all(char code, const void *payload, size_t plen)
{
    struct ifaddrs *ifaddr, *ifa;
    char bcast[NI_MAXHOST];
    int e;

    if (getifaddrs(&ifaddr) < 0) {
        perror("getifaddrs");
        return;
    }

    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;
        if (!ifa->ifa_broadaddr)
            continue;

        e = getnameinfo(ifa->ifa_broadaddr, sizeof(struct sockaddr_in),
                        bcast, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        if (e != 0) {
            TRACEF("getnameinfo broadcast: %s\n", gai_strerror(e));
            continue;
        }

        /* on saute le loopback, ca ne sert a rien d'y broadcaster */
        if (strcmp(bcast, "127.0.0.1") == 0 || strncmp(bcast, "127.", 4) == 0)
            continue;

        TRACEF("broadcast sur %s via %s\n", bcast, ifa->ifa_name);
        send_beuip_to(bcast, code, payload, plen);
    }

    freeifaddrs(ifaddr);

    /* adresse de broadcast du sous-reseau de la salle */
    send_beuip_to(BEUIP_BROADCAST, code, payload, plen);
}

/* --- commande() : gere '3', '4', '5' directement en memoire ---
   plus besoin de passer par UDP, ce qui bloquait les attaques
   de type man-in-the-middle (codes '3'/'4'/'5' depuis localhost). */
void commande(char octet1, char *message, char *pseudo)
{
    if (octet1 == '3') {
        listeElts();
        return;
    }

    if (octet1 == '4') {
        /* message prive : on cherche l'IP du pseudo dans la liste */
        char adip[16] = "";
        struct elt *cur;

        pthread_mutex_lock(&mutex_liste);
        for (cur = liste; cur; cur = cur->next) {
            if (strcmp(cur->nom, pseudo) == 0) {
                strncpy(adip, cur->adip, 15);
                adip[15] = '\0';
                break;
            }
        }
        pthread_mutex_unlock(&mutex_liste);

        if (adip[0] == '\0') {
            fprintf(stderr, "Pseudo inconnu: %s\n", pseudo);
            return;
        }
        if (send_beuip_to(adip, '9', message, strlen(message)) < 0)
            perror("envoi message prive");
        TRACEF("message prive vers %s (%s)\n", pseudo, adip);
        return;
    }

    if (octet1 == '5') {
        /* message pour tout le monde : on parcourt la liste */
        struct elt *cur;

        pthread_mutex_lock(&mutex_liste);
        for (cur = liste; cur; cur = cur->next) {
            if (strcmp(cur->nom, self_pseudo) == 0)
                continue; /* pas la peine de s'envoyer a soi-meme */
            if (send_beuip_to(cur->adip, '9', message, strlen(message)) < 0)
                perror("envoi message all");
        }
        pthread_mutex_unlock(&mutex_liste);
        TRACEF("message global envoye\n");
        return;
    }
}

/* --- thread serveur UDP ---
   tourne en fond, recoit les datagrammes des autres.
   ne traite que '0', '1', '2', '9'. les codes '3'/'4'/'5'
   sont maintenant geres directement par commande(). */
void *serveur_udp(void *p)
{
    char buf[MAX_MSG + 1];
    struct sockaddr_in from;
    socklen_t lfrom;
    int n;

    (void)p;

    /* on annonce notre presence sur le reseau */
    send_broadcast_all('1', self_pseudo, strlen(self_pseudo) + 1);

    while (!stop_udp) {
        char        code;
        const char *payload;
        size_t      plen;
        char        src_ip[16];

        lfrom = sizeof(from);
        n = (int)recvfrom(udp_sock, buf, MAX_MSG, 0,
                          (struct sockaddr *)&from, &lfrom);
        if (n < 0) {
            if (stop_udp) break;
            perror("recvfrom");
            continue;
        }

        if (parse_message(buf, n, &code, &payload, &plen) < 0) {
            TRACEF2("datagramme ignore (entete invalide)\n");
            continue;
        }

        if (stop_udp) break;

        if (inet_ntop(AF_INET, &from.sin_addr, src_ip, sizeof(src_ip)) == NULL)
            strcpy(src_ip, "?");

        if (code == '0') {
            /* quelqu'un se deconnecte */
            supprimeElt(src_ip);
            TRACEF("deconnexion de %s\n", src_ip);
            continue;
        }

        if (code == '1' || code == '2') {
            /* quelqu'un s'annonce ('1') ou repond a notre annonce ('2') */
            char pseudo_src[LPSEUDO + 1];
            size_t p_len = strnlen(payload, plen);

            if (p_len == 0 || p_len >= (size_t)(LPSEUDO + 1) || p_len == plen) {
                TRACEF("message identification invalide depuis %s\n", src_ip);
                continue;
            }
            memcpy(pseudo_src, payload, p_len);
            pseudo_src[p_len] = '\0';

            ajouteElt(pseudo_src, src_ip);

            if (code == '1') {
                /* il s'annonce, on lui repond avec notre pseudo */
                send_beuip_to(src_ip, '2', self_pseudo, strlen(self_pseudo) + 1);
            }
            continue;
        }

        if (code == '9') {
            /* on a recu un message, on cherche le pseudo de l'expediteur */
            char nom[LPSEUDO + 1] = "?";
            struct elt *cur;

            pthread_mutex_lock(&mutex_liste);
            for (cur = liste; cur; cur = cur->next) {
                if (strcmp(cur->adip, src_ip) == 0) {
                    strncpy(nom, cur->nom, LPSEUDO);
                    nom[LPSEUDO] = '\0';
                    break;
                }
            }
            pthread_mutex_unlock(&mutex_liste);

            printf("\nMessage de %s : %.*s\n", nom, (int)plen, payload);
            fflush(stdout);
            continue;
        }

        /* quelqu'un essaie d'envoyer '3'/'4'/'5' depuis le reseau : suspect */
        fprintf(stderr, "[SECURITE] Code '%c' refuse depuis %s\n", code, src_ip);
    }

    TRACEF("thread serveur UDP termine\n");
    return NULL;
}

/* lit une ligne depuis un fd jusqu'au '\n' ou EOF */
static int readlig_fd(int fd, char *b, int max)
{
    int  n;
    char c;
    for (n = 0; n < max - 1; n++) {
        if (read(fd, &c, 1) <= 0) break;
        if (c == '\n') break;
        *b++ = c;
    }
    *b = '\0';
    return n;
}

/* repond a une connexion TCP :
   'L' -> envoie le listing du repertoire public (ls -l)
   'F' + nom\n -> envoie le fichier demande (cat)
   Dans les deux cas on fork et on redirige stdout vers la socket. */
void envoiContenu(int fd)
{
    char octet;

    if (read(fd, &octet, 1) <= 0) {
        close(fd);
        return;
    }

    if (octet == 'L') {
        pid_t p = fork();
        if (p < 0) { perror("fork (ls)"); close(fd); return; }
        if (p == 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
            execlp("ls", "ls", "-l", reppub, (char *)NULL);
            _exit(1);
        }
        waitpid(p, NULL, 0);
        close(fd);
        return;
    }

    if (octet == 'F') {
        char nomfic[256];
        char chemin[512];

        readlig_fd(fd, nomfic, sizeof(nomfic));

        if (nomfic[0] == '\0') {
            write(fd, "Nom de fichier manquant\n", 24);
            close(fd);
            return;
        }

        snprintf(chemin, sizeof(chemin), "%s/%s", reppub, nomfic);

        if (access(chemin, R_OK) < 0) {
            write(fd, "Fichier non trouve\n", 19);
            TRACEF("fichier demande introuvable: %s\n", chemin);
            close(fd);
            return;
        }

        pid_t p = fork();
        if (p < 0) { perror("fork (cat)"); close(fd); return; }
        if (p == 0) {
            dup2(fd, STDOUT_FILENO);
            dup2(fd, STDERR_FILENO);
            close(fd);
            execlp("cat", "cat", chemin, (char *)NULL);
            _exit(1);
        }
        waitpid(p, NULL, 0);
        close(fd);
        return;
    }

    write(fd, "Commande TCP inconnue\n", 22);
    close(fd);
}

/* un thread par client TCP, pour ne pas bloquer les autres */
static void *tcp_client_thread(void *arg)
{
    long fd = (long)arg;
    envoiContenu((int)fd);
    return NULL;
}

/* thread serveur TCP : attend des connexions et cree un thread par client.
   tcp_sock_listen est deja bind/listen avant le demarrage du thread. */
void *serveur_tcp(void *rep)
{
    (void)rep;

    TRACEF("thread serveur TCP actif sur port %d\n", TCP_PORT);

    while (!stop_tcp) {
        struct sockaddr_in from;
        socklen_t lfrom = sizeof(from);
        int       nsock;
        pthread_t th;
        long      param;

        nsock = accept(tcp_sock_listen, (struct sockaddr *)&from, &lfrom);
        if (nsock < 0) {
            if (stop_tcp) break;
            perror("accept TCP");
            continue;
        }

        TRACEF2("connexion TCP depuis %s\n", inet_ntoa(from.sin_addr));

        param = nsock;
        if (pthread_create(&th, NULL, tcp_client_thread, (void *)param) != 0) {
            fprintf(stderr, "Erreur creation thread TCP client\n");
            close(nsock);
        } else {
            pthread_detach(th);
        }
    }

    TRACEF("thread serveur TCP termine\n");
    return NULL;
}

/* cherche l'IP d'un pseudo dans la liste (buffer statique) */
static const char *get_adip_for_pseudo(const char *pseudo)
{
    static char adip[16];
    struct elt *cur;

    pthread_mutex_lock(&mutex_liste);
    for (cur = liste; cur; cur = cur->next) {
        if (strcmp(cur->nom, pseudo) == 0) {
            strncpy(adip, cur->adip, 15);
            adip[15] = '\0';
            pthread_mutex_unlock(&mutex_liste);
            return adip;
        }
    }
    pthread_mutex_unlock(&mutex_liste);
    return NULL;
}

/* ouvre une connexion TCP vers une IP sur le port TCP_PORT */
static int tcp_connect_to(const char *adip)
{
    int sock;
    struct sockaddr_in srv;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) { perror("socket TCP client"); return -1; }

    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_port   = htons(TCP_PORT);
    if (inet_pton(AF_INET, adip, &srv.sin_addr) != 1) {
        fprintf(stderr, "Adresse invalide: %s\n", adip);
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
        perror("connect TCP");
        close(sock);
        return -1;
    }

    return sock;
}

/* beuip ls pseudo : demande la liste des fichiers publics */
void demandeListe(char *pseudo)
{
    const char *adip;
    int   sock, n;
    char  buf[1024];

    adip = get_adip_for_pseudo(pseudo);
    if (!adip) { fprintf(stderr, "Pseudo inconnu: %s\n", pseudo); return; }

    sock = tcp_connect_to(adip);
    if (sock < 0) return;

    write(sock, "L", 1);

    while ((n = read(sock, buf, sizeof(buf))) > 0)
        fwrite(buf, 1, (size_t)n, stdout);
    fflush(stdout);

    close(sock);
}

/* beuip get pseudo nomfic : telecharge un fichier et le sauvegarde dans pub/ */
void demandeFichier(char *pseudo, char *nomfic)
{
    const char *adip;
    int   sock, n;
    char  buf[1024];
    char  chemin[512];
    char  req[512];
    FILE *f;

    adip = get_adip_for_pseudo(pseudo);
    if (!adip) { fprintf(stderr, "Pseudo inconnu: %s\n", pseudo); return; }

    snprintf(chemin, sizeof(chemin), "%s/%s", reppub, nomfic);

    /* on refuse d'ecraser un fichier local existant */
    if (access(chemin, F_OK) == 0) {
        fprintf(stderr,
                "'%s' existe deja dans %s, supprimez-le d'abord.\n",
                nomfic, reppub);
        return;
    }

    sock = tcp_connect_to(adip);
    if (sock < 0) return;

    snprintf(req, sizeof(req), "F%s\n", nomfic);
    write(sock, req, strlen(req));

    f = fopen(chemin, "wb");
    if (!f) { perror("fopen"); close(sock); return; }

    while ((n = read(sock, buf, sizeof(buf))) > 0)
        fwrite(buf, 1, (size_t)n, f);

    fclose(f);
    close(sock);
    printf("Fichier '%s' sauvegarde dans %s\n", nomfic, chemin);
}

/* --- beuip start : cree les sockets et lance les deux threads --- */
static void do_beuip_start(char *pseudo)
{
    int opt = 1;
    struct sockaddr_in local;

    if (serveur_actif) {
        fprintf(stderr, "Le serveur est deja demarre\n");
        return;
    }
    if (*pseudo == '\0') {
        fprintf(stderr, "Pseudo manquant\n");
        return;
    }

    strncpy(self_pseudo, pseudo, LPSEUDO);
    self_pseudo[LPSEUDO] = '\0';

    /* on cree le dossier public si il n'existe pas encore */
    if (mkdir(reppub, 0755) < 0 && errno != EEXIST)
        perror("mkdir reppub");

    /* socket UDP */
    udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock < 0) { perror("socket UDP"); return; }
    setsockopt(udp_sock, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
    setsockopt(udp_sock, SOL_SOCKET, SO_REUSEADDR,  &opt, sizeof(opt));

    memset(&local, 0, sizeof(local));
    local.sin_family      = AF_INET;
    local.sin_port        = htons(BEUIP_PORT);
    local.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(udp_sock, (struct sockaddr *)&local, sizeof(local)) < 0) {
        perror("bind UDP");
        close(udp_sock); udp_sock = -1;
        return;
    }

    /* socket TCP : on fait bind+listen ici (avant de demarrer le thread)
       pour eviter une race condition sur tcp_sock_listen */
    tcp_sock_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (tcp_sock_listen < 0) {
        perror("socket TCP");
        close(udp_sock); udp_sock = -1;
        return;
    }
    setsockopt(tcp_sock_listen, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&local, 0, sizeof(local));
    local.sin_family      = AF_INET;
    local.sin_port        = htons(TCP_PORT);
    local.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(tcp_sock_listen, (struct sockaddr *)&local, sizeof(local)) < 0) {
        perror("bind TCP");
        close(tcp_sock_listen); tcp_sock_listen = -1;
        close(udp_sock);        udp_sock        = -1;
        return;
    }
    if (listen(tcp_sock_listen, 5) < 0) {
        perror("listen TCP");
        close(tcp_sock_listen); tcp_sock_listen = -1;
        close(udp_sock);        udp_sock        = -1;
        return;
    }

    stop_udp = 0;
    stop_tcp = 0;

    if (pthread_create(&th_udp, NULL, serveur_udp, NULL) != 0) {
        perror("pthread_create UDP");
        close(tcp_sock_listen); tcp_sock_listen = -1;
        close(udp_sock);        udp_sock        = -1;
        return;
    }

    if (pthread_create(&th_tcp, NULL, serveur_tcp, reppub) != 0) {
        perror("pthread_create TCP");
        stop_udp = 1;
        send_beuip_to("127.0.0.1", '0', self_pseudo, strlen(self_pseudo) + 1);
        pthread_join(th_udp, NULL);
        close(tcp_sock_listen); tcp_sock_listen = -1;
        close(udp_sock);        udp_sock        = -1;
        return;
    }

    serveur_actif = 1;
    printf("Serveur demarre (pseudo=%s, pub=%s)\n", self_pseudo, reppub);
}

/* --- beuip stop : previent tout le monde et arrete les threads --- */
static void do_beuip_stop(void)
{
    struct elt *cur;

    if (!serveur_actif) {
        fprintf(stderr, "Le serveur n'est pas actif\n");
        return;
    }

    /* on envoie '0' a tout le monde pour dire qu'on part (sans AR) */
    pthread_mutex_lock(&mutex_liste);
    for (cur = liste; cur; cur = cur->next)
        send_beuip_to(cur->adip, '0', self_pseudo, strlen(self_pseudo) + 1);
    pthread_mutex_unlock(&mutex_liste);

    send_broadcast_all('0', self_pseudo, strlen(self_pseudo) + 1);

    /* pour debloquer recvfrom : on pose le flag puis on s'envoie
       un datagramme a soi-meme, ce qui reveille le thread */
    stop_udp = 1;
    send_beuip_to("127.0.0.1", '0', self_pseudo, strlen(self_pseudo) + 1);
    pthread_join(th_udp, NULL);
    close(udp_sock);
    udp_sock = -1;

    /* pour debloquer accept : on ferme le socket d'ecoute */
    stop_tcp = 1;
    close(tcp_sock_listen);
    tcp_sock_listen = -1;
    pthread_join(th_tcp, NULL);

    pthread_mutex_lock(&mutex_liste);
    viderListe();
    pthread_mutex_unlock(&mutex_liste);

    serveur_actif = 0;
    printf("Serveur arrete\n");
}

/* --- shell biceps --- */

static char *skip_spaces(char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    return s;
}

static void print_help(void)
{
    puts("Commandes disponibles:");
    puts("  beuip start <pseudo>              -- se connecter au reseau");
    puts("  beuip stop                        -- se deconnecter");
    puts("  beuip list                        -- voir les contacts connectes");
    puts("  beuip message all <message>       -- envoyer un message a tout le monde");
    puts("  beuip message <pseudo> <message>  -- envoyer un message prive");
    puts("  beuip ls <pseudo>                 -- voir les fichiers publics d'un contact");
    puts("  beuip get <pseudo> <fichier>      -- telecharger un fichier");
    puts("  help                              -- afficher cette aide");
    puts("  exit | quit                       -- quitter");
}

int main(void)
{
    char line[1024];

    /* evite un crash si l'autre cote ferme la connexion TCP pendant un write */
    signal(SIGPIPE, SIG_IGN);

    print_help();

    for (;;) {
        char *cmd;

        printf("biceps> ");
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) {
            putchar('\n');
            break;
        }

        line[strcspn(line, "\n")] = '\0';
        cmd = skip_spaces(line);

        if (*cmd == '\0')
            continue;

        if (strcmp(cmd, "help") == 0) {
            print_help();
            continue;
        }

        if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0)
            break;

        if (strncmp(cmd, "beuip start", 11) == 0) {
            do_beuip_start(skip_spaces(cmd + 11));
            continue;
        }

        if (strcmp(cmd, "beuip stop") == 0) {
            do_beuip_stop();
            continue;
        }

        if (strcmp(cmd, "beuip list") == 0) {
            if (!serveur_actif) { fprintf(stderr, "Serveur non actif\n"); continue; }
            commande('3', NULL, NULL);
            continue;
        }

        if (strncmp(cmd, "beuip message", 13) == 0 &&
            (cmd[13] == ' ' || cmd[13] == '\t' || cmd[13] == '\0')) {
            char *args = skip_spaces(cmd + 13);
            if (!serveur_actif) { fprintf(stderr, "Serveur non actif\n"); continue; }

            if (strncmp(args, "all", 3) == 0 && (args[3] == ' ' || args[3] == '\t')) {
                char *msg = skip_spaces(args + 3);
                if (*msg == '\0') { fprintf(stderr, "Message manquant\n"); continue; }
                commande('5', msg, NULL);
                continue;
            }

            {
                char *pseudo = args, *msg, *p = args;
                while (*p && *p != ' ' && *p != '\t') p++;
                if (*p == '\0') { fprintf(stderr, "Usage: beuip message <pseudo> <message>\n"); continue; }
                *p = '\0';
                msg = skip_spaces(p + 1);
                if (*pseudo == '\0' || *msg == '\0') { fprintf(stderr, "Usage: beuip message <pseudo> <message>\n"); continue; }
                commande('4', msg, pseudo);
            }
            continue;
        }

        if (strncmp(cmd, "beuip ls", 8) == 0) {
            char *pseudo = skip_spaces(cmd + 8);
            if (!serveur_actif) { fprintf(stderr, "Serveur non actif\n"); continue; }
            if (*pseudo == '\0') { fprintf(stderr, "Usage: beuip ls <pseudo>\n"); continue; }
            demandeListe(pseudo);
            continue;
        }

        if (strncmp(cmd, "beuip get", 9) == 0) {
            char *args = skip_spaces(cmd + 9);
            char *pseudo = args, *nomfic, *p = args;
            if (!serveur_actif) { fprintf(stderr, "Serveur non actif\n"); continue; }
            while (*p && *p != ' ' && *p != '\t') p++;
            if (*p == '\0') { fprintf(stderr, "Usage: beuip get <pseudo> <fichier>\n"); continue; }
            *p = '\0';
            nomfic = skip_spaces(p + 1);
            if (*nomfic == '\0') { fprintf(stderr, "Usage: beuip get <pseudo> <fichier>\n"); continue; }
            demandeFichier(pseudo, nomfic);
            continue;
        }

        if (strncmp(cmd, "mess", 4) == 0 &&
            (cmd[4] == ' ' || cmd[4] == '\t' || cmd[4] == '\0')) {
            char *args = skip_spaces(cmd + 4);
            if (!serveur_actif) { fprintf(stderr, "Serveur non actif\n"); continue; }

            if (strcmp(args, "liste") == 0) {
                commande('3', NULL, NULL);
                continue;
            }

            if (strncmp(args, "all", 3) == 0 && (args[3] == ' ' || args[3] == '\t')) {
                char *msg = skip_spaces(args + 3);
                if (*msg == '\0') { fprintf(stderr, "Message manquant\n"); continue; }
                commande('5', msg, NULL);
                continue;
            }

            {
                char *pseudo = args, *msg, *p = args;
                while (*p && *p != ' ' && *p != '\t') p++;
                if (*p == '\0') { fprintf(stderr, "Usage: mess <pseudo> <message>\n"); continue; }
                *p = '\0';
                msg = skip_spaces(p + 1);
                if (*pseudo == '\0' || *msg == '\0') { fprintf(stderr, "Usage: mess <pseudo> <message>\n"); continue; }
                commande('4', msg, pseudo);
            }
            continue;
        }

        fprintf(stderr, "Commande inconnue: %s\n", cmd);
    }

    if (serveur_actif)
        do_beuip_stop();

    return 0;
}