#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <time.h>
#include <sys/time.h>
#include <ctype.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#define MAX_HOST_LEN 256
#define HASH_TABLE_SIZE 65536
#define INITIAL_BUCKET_SIZE 8

typedef struct host_entry {
    char *host;
    struct host_entry *next;
} host_entry_t;

host_entry_t **hash_table = NULL;

unsigned long total_hosts = 0;
unsigned long hash_collisions = 0;
unsigned long memory_used = 0;

struct timeval start_time, end_time;
double load_time = 0.0;

double get_elapsed_time(struct timeval *start, struct timeval *end) {
    return (end->tv_sec - start->tv_sec) + 
           (end->tv_usec - start->tv_usec) / 1000000.0;
}

unsigned int hash_function(const char *host) {
    unsigned int hash = 0;
    while (*host) {
        hash = (hash * 31) + (unsigned char)tolower(*host);
        host++;
    }
    return hash & (HASH_TABLE_SIZE - 1);
}

void init_hash_table() {
    hash_table = (host_entry_t **)calloc(HASH_TABLE_SIZE, sizeof(host_entry_t *));
    if (!hash_table) {
        fprintf(stderr, "Failed to allocate memory for hash table\n");
        exit(1);
    }
    memory_used += HASH_TABLE_SIZE * sizeof(host_entry_t *);
    printf("Initialized hash table with %d buckets, using %.2f MB\n", 
           HASH_TABLE_SIZE, memory_used / (1024.0 * 1024.0));
}

void add_host_to_hash(const char *host) {
    if (!host || !*host) return;
    
    unsigned int index = hash_function(host);
    host_entry_t *entry = (host_entry_t *)malloc(sizeof(host_entry_t));
    if (!entry) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }
    
    entry->host = strdup(host);
    if (!entry->host) {
        free(entry);
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }
    
    memory_used += strlen(host) + 1 + sizeof(host_entry_t);
    
    entry->next = hash_table[index];
    hash_table[index] = entry;
    
    if (entry->next) hash_collisions++;
    total_hosts++;
}

int is_host_blocked(const char *host) {
    if (!host || !hash_table) return 0;
    
    struct timeval search_start, search_end;
    gettimeofday(&search_start, NULL);
    
    unsigned int index = hash_function(host);
    host_entry_t *entry = hash_table[index];
    
    while (entry) {
        if (strcasecmp(entry->host, host) == 0) {
            gettimeofday(&search_end, NULL);
            double search_time = get_elapsed_time(&search_start, &search_end);
            printf("Host '%s' found in %.6f seconds\n", host, search_time);
            return 1;
        }
        entry = entry->next;
    }
    
    gettimeofday(&search_end, NULL);
    double search_time = get_elapsed_time(&search_start, &search_end);
    printf("Host '%s' not found in hash table (search took %.6f seconds)\n", 
           host, search_time);
    
    return 0;
}

void cleanup_hash_table() {
    if (!hash_table) return;
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        host_entry_t *entry = hash_table[i];
        while (entry) {
            host_entry_t *temp = entry;
            entry = entry->next;
            free(temp->host);
            free(temp);
        }
    }
    
    free(hash_table);
    hash_table = NULL;
}

int load_domains_from_csv(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open file: %s\n", filename);
        return 0;
    }
    
    printf("Loading domains from %s\n", filename);
    gettimeofday(&start_time, NULL);
    
    char line[MAX_HOST_LEN];
    char domain[MAX_HOST_LEN];
    
    while (fgets(line, sizeof(line), fp)) {
        char *comma = strchr(line, ',');
        if (comma) {
            strncpy(domain, comma + 1, sizeof(domain) - 1);
        } else {
            strncpy(domain, line, sizeof(domain) - 1);
        }
        
        char *newline = strchr(domain, '\n');
        if (newline) *newline = '\0';
        
        add_host_to_hash(domain);
        
        if (total_hosts % 100000 == 0) {
            printf("Loaded %lu domains...\n", total_hosts);
        }
    }
    
    gettimeofday(&end_time, NULL);
    load_time = get_elapsed_time(&start_time, &end_time);
    
    printf("Loaded %lu domains in %.2f seconds\n", total_hosts, load_time);
    printf("Memory used: %.2f MB\n", memory_used / (1024.0 * 1024.0));
    printf("Hash collisions: %lu (%.2f%%)\n", 
           hash_collisions, (hash_collisions * 100.0) / total_hosts);
    
    fclose(fp);
    return 1;
}

int sort_csv_file(const char *input_filename, const char *output_filename) {
    FILE *check = fopen(output_filename, "r");
    if (check) {
        printf("Sorted file %s already exists, using existing file\n", output_filename);
        fclose(check);
        return 1;
    }
    
    printf("Sorting CSV file %s to %s\n", input_filename, output_filename);
    gettimeofday(&start_time, NULL);
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "sort -t, -k2 %s > %s", input_filename, output_filename);
    
    int result = system(cmd);
    
    gettimeofday(&end_time, NULL);
    double sort_time = get_elapsed_time(&start_time, &end_time);
    
    if (result == 0) {
        printf("Successfully sorted CSV file in %.2f seconds\n", sort_time);
        return 1;
    } else {
        fprintf(stderr, "Failed to sort CSV file\n");
        return 0;
    }
}

void dump(unsigned char* buf, int size) {
        int i;
        for (i = 0; i < size; i++) {
                if (i != 0 && i % 16 == 0)
                        printf("\n");
                printf("%02X ", buf[i]);
        }
        printf("\n");
}

int check_http_host(unsigned char *data, int len) {
    if (len < (int)(sizeof(struct iphdr) + sizeof(struct tcphdr))) {
        return 0;
    }

    struct iphdr *iph = (struct iphdr*)data;
    int ip_header_len = iph->ihl * 4;
    
    if (iph->protocol != IPPROTO_TCP) {
        return 0;
    }

    struct tcphdr *tcph = (struct tcphdr*)(data + ip_header_len);
    int tcp_header_len = tcph->doff * 4;
    
    unsigned char *http_payload = data + ip_header_len + tcp_header_len;
    int payload_len = len - ip_header_len - tcp_header_len;
    
    if (payload_len <= 0) {
        return 0;
    }
    
    if (payload_len > 3 && 
        ((http_payload[0] == 'G' && http_payload[1] == 'E' && http_payload[2] == 'T') ||
         (http_payload[0] == 'P' && http_payload[1] == 'O' && http_payload[2] == 'S' && http_payload[3] == 'T') ||
         (http_payload[0] == 'H' && http_payload[1] == 'E' && http_payload[2] == 'A' && http_payload[3] == 'D'))) {
        
        unsigned char *host_field = memmem(http_payload, payload_len, "Host: ", 6);
        if (host_field) {
            host_field += 6;
            
            unsigned char *end_of_line = memchr(host_field, '\r', payload_len - (size_t)(host_field - http_payload));
            if (!end_of_line) {
                end_of_line = memchr(host_field, '\n', payload_len - (size_t)(host_field - http_payload));
            }
            
            if (end_of_line) {
                int host_len = (int)(end_of_line - host_field);
                char host[MAX_HOST_LEN] = {0};
                
                if (host_len < (int)sizeof(host)) {
                    memcpy(host, host_field, host_len);
                    host[host_len] = '\0';
                    
                    char *port = strchr(host, ':');
                    if (port) {
                        *port = '\0';
                    }
                    
                    printf("HTTP Host: %s\n", host);
                    
                    if (is_host_blocked(host)) {
                        printf("Dropping packet to blocked website: %s\n", host);
                        return 1;
                    }
                }
            }
        }
    }
    
    return 0;
}

static u_int32_t print_pkt (struct nfq_data *tb)
{
        int id = 0;
        struct nfqnl_msg_packet_hdr *ph;
        struct nfqnl_msg_packet_hw *hwph;
        u_int32_t mark,ifi;
        int ret;
        unsigned char *data;

        ph = nfq_get_msg_packet_hdr(tb);
        if (ph) {
                id = ntohl(ph->packet_id);
                printf("hw_protocol=0x%04x hook=%u id=%u ",
                        ntohs(ph->hw_protocol), ph->hook, id);
        }

        hwph = nfq_get_packet_hw(tb);
        if (hwph) {
                int i, hlen = ntohs(hwph->hw_addrlen);

                printf("hw_src_addr=");
                for (i = 0; i < hlen-1; i++)
                        printf("%02x:", hwph->hw_addr[i]);
                printf("%02x ", hwph->hw_addr[hlen-1]);
        }

        mark = nfq_get_nfmark(tb);
        if (mark)
                printf("mark=%u ", mark);

        ifi = nfq_get_indev(tb);
        if (ifi)
                printf("indev=%u ", ifi);

        ifi = nfq_get_outdev(tb);
        if (ifi)
                printf("outdev=%u ", ifi);
        ifi = nfq_get_physindev(tb);
        if (ifi)
                printf("physindev=%u ", ifi);

        ifi = nfq_get_physoutdev(tb);
        if (ifi)
                printf("physoutdev=%u ", ifi);

        ret = nfq_get_payload(tb, &data);
        if (ret >= 0) {
                printf("payload_len=%d\n", ret);
        }
        fputc('\n', stdout);

        return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg __attribute__((unused)),
              struct nfq_data *nfa, void *data __attribute__((unused)))
{
        u_int32_t id = print_pkt(nfa);
        printf("entering callback\n");
        
        unsigned char *packet_data;
        int packet_len = nfq_get_payload(nfa, &packet_data);
        
        if (packet_len >= 0) {
            if (check_http_host(packet_data, packet_len)) {
                printf("Dropping packet to harmful website\n");
                return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
            }
        }
        
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
        struct nfq_handle *h;
        struct nfq_q_handle *qh;
        int fd;
        int rv;
        char buf[4096] __attribute__ ((aligned));

        if (argc != 2) {
            printf("syntax : 1m_block <csv_file>\n");
            printf("sample : 1m_block top-1m.csv\n");
            return 1;
        }
        
        const char *csv_file = argv[1];
        const char *sorted_csv_file = "sortA.csv";
        
        init_hash_table();
        
        sort_csv_file(csv_file, sorted_csv_file);
        
        if (!load_domains_from_csv(sorted_csv_file)) {
            fprintf(stderr, "Failed to load domains from CSV file\n");
            cleanup_hash_table();
            return 1;
        }
        
        printf("opening library handle\n");
        h = nfq_open();
        if (!h) {
                fprintf(stderr, "error during nfq_open()\n");
                cleanup_hash_table();
                exit(1);
        }

        printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
        if (nfq_unbind_pf(h, AF_INET) < 0) {
                fprintf(stderr, "error during nfq_unbind_pf()\n");
                cleanup_hash_table();
                exit(1);
        }

        printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
        if (nfq_bind_pf(h, AF_INET) < 0) {
                fprintf(stderr, "error during nfq_bind_pf()\n");
                cleanup_hash_table();
                exit(1);
        }

        printf("binding this socket to queue '0'\n");
        qh = nfq_create_queue(h,  0, &cb, NULL);
        if (!qh) {
                fprintf(stderr, "error during nfq_create_queue()\n");
                cleanup_hash_table();
                exit(1);
        }

        printf("setting copy_packet mode\n");
        if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
                fprintf(stderr, "can't set packet_copy mode\n");
                cleanup_hash_table();
                exit(1);
        }

        fd = nfq_fd(h);

        printf("Ready to filter. Run the following command to redirect packets to the queue:\n");
        printf("sudo iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0\n");
        printf("sudo iptables -A INPUT -p tcp --sport 80 -j NFQUEUE --queue-num 0\n");
        printf("Test with: wget http://example.com\n");

        for (;;) {
                if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
                        printf("pkt received\n");
                        nfq_handle_packet(h, buf, rv);
                        continue;
                }

                if (rv < 0 && errno == ENOBUFS) {
                        printf("losing packets!\n");
                        continue;
                }
                perror("recv failed");
                break;
        }

        printf("unbinding from queue 0\n");
        nfq_destroy_queue(qh);

        printf("unbinding from AF_INET\n");
        nfq_unbind_pf(h, AF_INET);

        printf("closing library handle\n");
        nfq_close(h);
        
        cleanup_hash_table();

        exit(0);
}
