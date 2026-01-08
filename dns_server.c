// Acesta este proiectul pentru un server DNS asa cum trebuie sa fie,
//cu rezolvare locala a interogarilor de domenii (daca am configurat zonele)
//sau cu trimiterea de cereri catre un resolver DNS pe internet care va
//gestiona asta

//in drepata am explicatia pentru fiecare biblioteca la ce o folosesc
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>              //pentru fork, close getpid()
#include<sys/socket.h>          //pentru socketi
#include<arpa/inet.h>           //pentru sockaddr_in
#include<sys/mman.h>            // pentru memorie partajata (mmap)
#include<semaphore.h>           //pentru semafoare (mutexuri)
#include<fcntl.h>               //pentru constante date apelurilor de sistem (O_CREATE, O_RDONLY, etc)
#include<time.h>                //pentru a putea spune timpul sistemului
#include<sys/time.h>            //pentru lucrul cu structuri ce timp (timeval)
#include<signal.h>              //pentru semnale
#include<sys/wait.h>            //pentru a putea astepta dupa procese
#include<pthread.h>             // pentru lucrul cu threaduri

#define PORT 9999
#define BUFF_SIZE 65536 //8192 de octeti
#define MAX_CACHE_SIZE 100      //100 de intrari in cache
#define MAX_ZONES 50            //50 de zone


//Structuri de date utilizate in proiect
typedef struct {
    char domain[256];
    char type[10];              // A, CNAME, MX
    char value[256];            //IP sau numele domeniului tinta
    int priority;
    time_t created_at;
    int ttl;
    int is_valid;
}DNSRecord;

typedef struct {
    DNSRecord cache[MAX_CACHE_SIZE];
    sem_t mutex;
    int total_requests;
}SharedMemory;

//Date locale pentru proces (zone) (mostenite in toti copiii)
DNSRecord local_zones[MAX_ZONES];
int zones_count = 0;

//Structura pentru header DNS
struct DNS_HEADER {
    unsigned short id;

    //in acest context, pentru a nu ma complica cu tipuri de date care sa ocupe memorie multa
    //folosesc un artificiu (care e folosit si in practica) bit fields
    //ordinea bitilor este standard
    unsigned char rd : 1;
    unsigned char tc : 1;
    unsigned char aa : 1;
    unsigned char opcode : 4;
    unsigned char qr : 1;

    unsigned char rcode : 4;
    unsigned char cd : 1;
    unsigned char ad : 1;
    unsigned char z : 1;
    unsigned char ra : 1;

    unsigned short q_count;
    unsigned short ans_count;
    unsigned short auth_count;
    unsigned short add_count;
}__attribute__((packed)); // spunem compilatorului sa nu optimizeze asezarea bitilor


struct R_DATA {
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
}__attribute__((packed));



//---------- Functii auxiliare --------

//funtie pentru CNAME/MX Converteste 'www.google.com' in "\3www\6google\3com\0"
int dn_format(unsigned char* dest, char* host) {
    int lock = 0;
    char host_copy[256];
    strcpy(host_copy, host);
    strcat(host_copy, ".");

    int len = strlen(host_copy);
    int dest_pos = 0;

    for (int i = 0; i < len; i++) {
        if (host_copy[i] == '.') {
            int segment_len = i - lock;
            dest[dest_pos++] = segment_len;
            for (int j = 0; j < segment_len; j++) {
                dest[dest_pos++] = host_copy[lock + j];
            }
            lock = i + 1;
        }
    }
    dest[dest_pos++] = 0x00;        //pun null la final
    return dest_pos;
}


void load_zones(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        perror("Eroare la deschiderea fisieurlui zones.txt\n");
        return;
    }

    char domain[256], value[256], type[10];
    int priority, ttl;

    //Citire format extins: domain, type, value, priority, ttl
    while (fscanf(fp, "%s %s %s %d %d", domain, type, value, &priority, &ttl) != EOF) {
        strcpy(local_zones[zones_count].domain, domain);
        strcpy(local_zones[zones_count].type, type);
        strcpy(local_zones[zones_count].value, value);
        local_zones[zones_count].priority = priority;
        local_zones[zones_count].ttl = ttl;
        local_zones[zones_count].is_valid = 1;
        zones_count++;
    }
    fclose(fp);
    printf("[INFO] Serverul a incarcat %d zone din fisier.\n", zones_count);
}


SharedMemory* init_shared_memory() {
    SharedMemory* shm = mmap(NULL, sizeof(SharedMemory), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (shm == MAP_FAILED) {
        perror("Eroare alocare memorie cu mmap.\n");
        exit(1);
    }
    if (sem_init(&shm->mutex, 1, 1) < 0) {
        perror("Initializare semafor esuata\n");
        exit(1);
    }
    shm->total_requests = 0;
    for (int i = 0; i < MAX_CACHE_SIZE; i++) {
        shm->cache[i].is_valid = 0;
    }
    return shm;
}

void* monitor_ttl_thread(void* arg) {
    SharedMemory* shm = (SharedMemory*)arg;    //facem cast pe pointerul de tip void la pointer de tip structura ca sa mapez corespunzator datele din structura (fara aritmetici de pointeri dubioase)
    printf("[THREAD] Monitor TTL pornit.\n");
    while (1) {
        sleep(5);      //verificare din 5 in 5 secunde
        time_t now = time(NULL);
        int expired_count = 0;

        sem_wait(&shm->mutex);
        for (int i = 0; i < MAX_CACHE_SIZE; i++) {
            if (shm->cache[i].is_valid) {
                double elapsed = difftime(now, shm->cache[i].created_at);
                if (elapsed > shm->cache[i].ttl) {
                    printf("[THREAD] Domeniul %s a expirat. Eliminare din cache.\n", shm->cache[i].domain);
                    shm->cache[i].is_valid = 0;
                    expired_count++;
                }
            }
        }
        sem_post(&shm->mutex);

        //Afisaz cand am facut curatenie
        if (expired_count > 0)
            printf("[THREAD] Curatenie: %d intrari sterse.", expired_count);

    }
    return NULL;
}

// elimina procesele zombie fara a intrerupe programul principal
void handle_sigchild(int sig) {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}


//functie pentru citirea numelui dns
unsigned char* read_dns_name(unsigned char* reader, unsigned char* buffer, int* count) {
    unsigned char* name = (unsigned char*)malloc(256);
    name[0] = '\0';
    unsigned int offset;
    *count = 1;
    unsigned int jumped = 0;

    while (*reader != 0) {
        if (*reader > 192) {
            offset = (*reader) * 256 + *(reader + 1) - 49152;
            reader = buffer + offset - 1;
            jumped = 1;
        }
        else {
            int len = *reader;
            reader++;
            if (name[0] != '\0')
                strcat((char*)name, ".");
            strncat((char*)name, (char*)reader, len);
            reader += len;
            if (jumped == 0)
                *count = *count + len + 1;
        }
    }

    if (jumped == 1) {
        *count = *count + 1;
    }
    else {
        *count = *count + 1;
    }
    return name;
}


/// -------------- MAIN -----------------------
int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    char buffer[BUFF_SIZE];
    socklen_t addr_len = sizeof(client_addr);

    //initializari
    signal(SIGCHLD, handle_sigchild);
    load_zones("zones.txt");
    SharedMemory* shm = init_shared_memory();

    pthread_t tid;
    if (pthread_create(&tid, NULL, monitor_ttl_thread, (void*)shm) != 0) {
        perror("Eroare la crearea threadului!");
    }
    pthread_detach(tid);

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Creare socket esuata");
        exit(1);
    }

    //zeroizare structura socket si setarea ei
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(sockfd, (const struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind esuat!");
        exit(1);
    }

    printf("[SERVER] Server DNS pornit pe portul %d\n", PORT);


    //bucla in care preiau cereri
    while (1) {
        int n = recvfrom(sockfd, (char*)buffer, BUFF_SIZE, 0, (struct sockaddr*)&client_addr, &addr_len);
        if (n < 0) continue;

        pid_t pid = fork();

        if (pid < 0) {
            perror("Apel fork() esuat!");
        }
        else if (pid == 0) {
            //bucla pentru tratarea copiilor (requesturilor DNS)
            //---- PROCES COPIL ----
            struct DNS_HEADER* dns = (struct DNS_HEADER*)buffer;

            //1. Parsare nume
            unsigned char* qname_ptr = (unsigned char*)(buffer + sizeof(struct DNS_HEADER));
            int name_len = 0;
            unsigned char* domain_name = read_dns_name(qname_ptr, (unsigned char*)buffer, &name_len);

            printf("[COPIL PID: %d] Cerere pentru: %s\n", getpid(), domain_name);

            //Facem cautarea
            int found_idx = -1;     // index pentru local zones
            int cache_slot = -1;    // index in cache

            // Cautare in cache si zone locale
            sem_wait(&shm->mutex);
            shm->total_requests++;
            for (int i = 0; i < MAX_CACHE_SIZE; i++) {
                if (shm->cache[i].is_valid && strcmp(shm->cache[i].domain, (char*)domain_name) == 0) {
                    cache_slot = i;
                    break;
                }
            }
            sem_post(&shm->mutex);

            //2. Cautare locala
            if (cache_slot == -1) {
                for (int i = 0; i < zones_count; i++) {
                    if (strcmp(local_zones[i].domain, (char*)domain_name) == 0) {
                        found_idx = i;
                        break;
                    }
                }
            }

            if (cache_slot != -1 || found_idx != -1) {
                //raspuns local
                dns->qr = 1;
                dns->aa = 1;
                dns->tc = 0;
                dns->ra = 0;
                dns->rcode = 0;
                dns->ans_count = htons(1);

                unsigned char* writer = (unsigned char*)(qname_ptr + name_len + 4);

                //pointer la nume
                *writer++ = 0xC0;
                *writer++ = 0X0C;

                struct R_DATA* rdata = (struct R_DATA*)writer;
                unsigned char* rdata_payload = writer + sizeof(struct R_DATA);
                int payload_len = 0;

                rdata->_class = htons(1);       //IN

                if (cache_slot != -1) {
                    //daca este din cache, vom presupune flagurile mereu A si IP 

                    printf("[CACHE HIT] %s\n", domain_name);
                    rdata->type = htons(1);
                    rdata->ttl = htonl(shm->cache[cache_slot].ttl);
                    struct in_addr ip;
                    inet_aton(shm->cache[cache_slot].value, &ip);           //value memoreaza IP-ul

                    memcpy(rdata_payload, &ip, 4);
                    payload_len = 4;
                }
                else {
                    //este din local zone (am suport complet pentru A, CNAME, MX)
                    printf("[ZONE HIT] %s Tip: %s\n", domain_name, local_zones[found_idx].type);
                    rdata->ttl = htonl(local_zones[found_idx].ttl);

                    if (strcmp(local_zones[found_idx].type, "A") == 0) {
                        rdata->type = htons(1);
                        struct in_addr ip;
                        inet_aton(local_zones[found_idx].value, &ip);
                        memcpy(rdata_payload, &ip, 4);
                        payload_len = 4;
                    }
                    else if (strcmp(local_zones[found_idx].type, "CNAME") == 0) {
                        rdata->type = htons(5);
                        payload_len = dn_format(rdata_payload, local_zones[found_idx].value);
                    }
                    else if (strcmp(local_zones[found_idx].type, "MX") == 0) {
                        rdata->type = htons(15);
                        unsigned short prio = htons(local_zones[found_idx].priority);
                        memcpy(rdata_payload, &prio, 2);
                        int mx_len = dn_format(rdata_payload + 2, local_zones[found_idx].value);
                        payload_len = 2 + mx_len;
                    }
                }

                rdata->data_len = htons(payload_len);
                writer += sizeof(struct R_DATA) + payload_len;

                int packet_len = (int)(writer - (unsigned char*)buffer);
                sendto(sockfd, buffer, packet_len, 0, (struct sockaddr*)&client_addr, addr_len);

                free(domain_name);
                close(sockfd);
                exit(0);
            }
            else {

                //FORWARDING
                printf("[FORWARD] %s -> 8.8.8.8\n", domain_name);
                struct sockaddr_in dest;
                memset(&dest, 0, sizeof(dest));
                dest.sin_family = AF_INET;
                dest.sin_port = htons(53);
                inet_aton("8.8.8.8", &dest.sin_addr);

                int fs = socket(AF_INET, SOCK_DGRAM, 0);
                struct timeval tv = { 4,0 };
                setsockopt(fs, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof tv);

                sendto(fs, buffer, n, 0, (struct sockaddr*)&dest, sizeof(dest));


                char gbuf[BUFF_SIZE];
                socklen_t dlen = sizeof(dest);
                int rlen = recvfrom(fs, gbuf, BUFF_SIZE, 0, (struct sockaddr*)&dest, &dlen);
                close(fs);

                if (rlen > 0) {
                    sendto(sockfd, gbuf, rlen, 0, (struct sockaddr*)&client_addr, addr_len);

                    //CACHING (doar pentru IP)
                    struct DNS_HEADER* gh = (struct DNS_HEADER*)gbuf;
                    unsigned char* reader = (unsigned char*)(gbuf + sizeof(struct DNS_HEADER));
                    int q_cnt = ntohs(gh->q_count);
                    int a_cnt = ntohs(gh->ans_count);

                    for (int i = 0; i < q_cnt; i++) {
                        while (*reader != 0) {
                            if ((*reader & 0xC0) == 0xC0) {
                                reader += 2;
                                goto skq;
                            }
                            reader += *reader + 1;
                        }
                        reader++;
                    skq:
                        reader += 4;
                    }

                    for (int i = 0; i < a_cnt; i++) {
                        if ((*reader & 0XC0) == 0xC0)
                            reader += 2;
                        else {
                            while (*reader != 0)
                                reader += *reader + 1;
                            reader++;
                        }

                        struct R_DATA* res = (struct R_DATA*)reader;
                        unsigned short rtype = ntohs(res->type);
                        unsigned short dlen = ntohs(res->data_len);
                        unsigned int rttl = ntohl(res->ttl);
                        reader += sizeof(struct R_DATA);

                        if (rtype == 1 && dlen == 4) { // Save ONLY IPv4 to cache
                            struct in_addr* ptr = (struct in_addr*)reader;
                            char* ip_s = inet_ntoa(*ptr);

                            sem_wait(&shm->mutex);
                            int sl = -1;
                            for (int k = 0; k < MAX_CACHE_SIZE; k++) if (!shm->cache[k].is_valid) { sl = k; break; }
                            if (sl == -1) sl = 0;

                            strcpy(shm->cache[sl].domain, (char*)domain_name);
                            strcpy(shm->cache[sl].type, "A"); // Cache e doar A
                            strcpy(shm->cache[sl].value, ip_s);
                            shm->cache[sl].ttl = (rttl > 0) ? rttl : 300;
                            shm->cache[sl].created_at = time(NULL);
                            shm->cache[sl].is_valid = 1;
                            printf("[CACHE UPDATE] %s -> %s\n", domain_name, ip_s);
                            sem_post(&shm->mutex);
                        }
                        reader += dlen;
                    }
                }
                else {
                    perror("Forward timeout");
                }
                free(domain_name);
                close(sockfd);
                exit(0);
            }

        }
        else {
            //parintele nu face nimic
        }
    }

    //cleanup 
    sem_destroy(&shm->mutex);
    munmap(shm, sizeof(SharedMemory));
    return 0;
}

