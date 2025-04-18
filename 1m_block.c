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
#define HASH_SIZE 65536  

typedef struct DomainNode {
    char *domain;              
    struct DomainNode *next;   
} DomainNode;

struct {
    DomainNode **table;        
    unsigned long count;       
    unsigned long collisions;  
    unsigned long memory;      
    double load_time;          
} HashTable;

struct timeval start_time, end_time;

double time_diff(struct timeval *start, struct timeval *end) {
    return (end->tv_sec - start->tv_sec) + 
           (end->tv_usec - start->tv_usec) / 1000000.0;
}

unsigned int hash(const char *domain) {
    unsigned int h = 0;
    while (*domain) {
        h = (h * 31) + (unsigned char)tolower(*domain);
        domain++;
    }
    return h % HASH_SIZE;
}

int convert_csv_to_txt(const char *csv_filename, const char *txt_filename) {
    FILE *csv_fp = fopen(csv_filename, "r");
    if (!csv_fp) {
        fprintf(stderr, "CSV 파일 열기 실패: %s\n", csv_filename);
        return 0;
    }
    
    FILE *txt_fp = fopen(txt_filename, "w");
    if (!txt_fp) {
        fprintf(stderr, "TXT 파일 생성 실패: %s\n", txt_filename);
        fclose(csv_fp);
        return 0;
    }
    
    printf("CSV 파일 %s을(를) TXT 파일 %s(으)로 변환 중...\n", csv_filename, txt_filename);
    gettimeofday(&start_time, NULL);
    
    char line[MAX_HOST_LEN];
    char domain[MAX_HOST_LEN];
    unsigned long lines_converted = 0;
    
    while (fgets(line, sizeof(line), csv_fp)) {
        char *comma = strchr(line, ',');
        if (comma) {
            // CSV 형식 (순위,도메인)
            strncpy(domain, comma + 1, sizeof(domain) - 1);
            domain[sizeof(domain) - 1] = '\0';
            

            char *newline = strchr(domain, '\n');
            if (newline) *newline = '\0';
            
            fprintf(txt_fp, "%s\n", domain);
        } else {
            fputs(line, txt_fp);
            if (line[strlen(line) - 1] != '\n') {
                fputc('\n', txt_fp);
            }
        }
        
        lines_converted++;
        if (lines_converted % 100000 == 0) {
            printf("%lu줄 변환됨...\n", lines_converted);
        }
    }
    
    gettimeofday(&end_time, NULL);
    double conversion_time = time_diff(&start_time, &end_time);
    
    printf("변환 완료: %lu줄 (소요 시간: %.2f초)\n", lines_converted, conversion_time);
    
    fclose(csv_fp);
    fclose(txt_fp);
    return 1;
}

int load_domains_from_txt(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "파일 열기 실패: %s\n", filename);
        return 0;
    }
    
    printf("파일 %s에서 도메인 로딩 중...\n", filename);
    gettimeofday(&start_time, NULL);
    
    char line[MAX_HOST_LEN];
    
    while (fgets(line, sizeof(line), fp)) {
        char *newline = strchr(line, '\n');
        if (newline) *newline = '\0';
        
        if (line[0] != '\0') {
            add_domain(line);
        }
    }
    
    gettimeofday(&end_time, NULL);
    HashTable.load_time = time_diff(&start_time, &end_time);
    
    printf("도메인 로딩 완료: %lu개 (소요 시간: %.2f초)\n", HashTable.count, HashTable.load_time);
    printf("메모리 사용량: %.2f MB\n", HashTable.memory / (1024.0 * 1024.0));
    printf("해시 충돌: %lu회 (충돌률: %.2f%%)\n", 
           HashTable.collisions, (HashTable.collisions * 100.0) / HashTable.count);
    
    fclose(fp);
    return 1;
}

int sort_txt_file(const char *input_filename, const char *output_filename) {
    FILE *check = fopen(output_filename, "r");
    if (check) {
        printf("정렬된 파일 %s이(가) 이미 존재합니다. 기존 파일을 사용합니다.\n", output_filename);
        fclose(check);
        return 1;
    }
    
    printf("파일 %s을(를) 정렬하여 %s에 저장 중...\n", input_filename, output_filename);
    gettimeofday(&start_time, NULL);
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "sort %s > %s", input_filename, output_filename);
    
    int result = system(cmd);
    
    gettimeofday(&end_time, NULL);
    double sort_time = time_diff(&start_time, &end_time);
    
    if (result == 0) {
        printf("파일 정렬 완료 (소요 시간: %.2f초)\n", sort_time);
        return 1;
    } else {
        fprintf(stderr, "파일 정렬 실패\n");
        return 0;
    }
}

// 해시 테이블 초기화
void init_hashtable() {
    HashTable.table = (DomainNode **)calloc(HASH_SIZE, sizeof(DomainNode *));
    if (!HashTable.table) {
        fprintf(stderr, "해시 테이블 메모리 할당 실패\n");
        exit(1);
    }
    
    HashTable.count = 0;
    HashTable.collisions = 0;
    HashTable.memory = HASH_SIZE * sizeof(DomainNode *);
    HashTable.load_time = 0.0;
    
    printf("해시 테이블 초기화 완료 (크기: %d, 메모리: %.2f MB)\n", 
           HASH_SIZE, HashTable.memory / (1024.0 * 1024.0));
}

// 해시 테이블에 도메인 추가
void add_domain(const char *domain) {
    if (!domain || !*domain) return;
    
    unsigned int index = hash(domain);
    
    DomainNode *new_node = (DomainNode *)malloc(sizeof(DomainNode));
    if (!new_node) {
        fprintf(stderr, "메모리 할당 실패\n");
        return;
    }
    
    
    new_node->domain = strdup(domain);
    if (!new_node->domain) {
        free(new_node);
        fprintf(stderr, "메모리 할당 실패\n");
        return;
    }
    
    // 메모리 사용량 업데이트
    HashTable.memory += strlen(domain) + 1 + sizeof(DomainNode);

    new_node->next = HashTable.table[index];
    HashTable.table[index] = new_node;
    
    // 해시 충돌 발생 여부 확인
    if (new_node->next) {
        HashTable.collisions++;
    }
    
    HashTable.count++;
    
    if (HashTable.count % 100000 == 0) {
        printf("현재 %lu개 도메인 로드됨...\n", HashTable.count);
    }
}

// 해시 테이블에서 도메인 검색
int is_blocked_domain(const char *domain) {
    struct timeval search_start, search_end;
    gettimeofday(&search_start, NULL);
    
    unsigned int index = hash(domain);
    
    DomainNode *node = HashTable.table[index];
    while (node) {
        if (strcasecmp(node->domain, domain) == 0) {
            gettimeofday(&search_end, NULL);
            double search_time = time_diff(&search_start, &search_end);
            
            printf("도메인 '%s' 발견 (검색 시간: %.6f초)\n", domain, search_time);
            return 1;  
        }
        node = node->next;
    }
    
    gettimeofday(&search_end, NULL);
    double search_time = time_diff(&search_start, &search_end);
    
    printf("도메인 '%s' 발견되지 않음 (검색 시간: %.6f초)\n", domain, search_time);
    return 0;  // 발견되지 않음
}

// 해시 테이블 메모리 정리
void cleanup_hashtable() {
    if (!HashTable.table) return;
    
    printf("해시 테이블 정리 중...\n");
    
    for (int i = 0; i < HASH_SIZE; i++) {
        DomainNode *node = HashTable.table[i];
        while (node) {
            DomainNode *temp = node;
            node = node->next;
            free(temp->domain);
            free(temp);
        }
    }
    
    free(HashTable.table);
    HashTable.table = NULL;
    
    printf("해시 테이블 정리 완료\n");
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
                    
                    printf("HTTP 호스트: %s\n", host);
                    
                    if (is_blocked_domain(host)) {
                        printf("차단된 웹사이트로의 패킷 차단: %s\n", host);
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
        printf("콜백 함수 진입\n");
        
        unsigned char *packet_data;
        int packet_len = nfq_get_payload(nfa, &packet_data);
        
        if (packet_len >= 0) {
            if (check_http_host(packet_data, packet_len)) {
                printf("유해 웹사이트로의 패킷 차단\n");
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
            printf("사용법: 1m-block <사이트 목록 파일>\n");
            printf("예시: 1m-block top-1m.csv\n");
            return 1;
        }
        
        const char *input_file = argv[1];
        const char *converted_txt_file = "converted.txt";
        const char *sorted_txt_file = "sortA.txt";
        
        // 해시 테이블 초기화
        init_hashtable();
        
        // 파일 확장자 확인
        const char *ext = strrchr(input_file, '.');
        int is_csv = 0;
        
        if (ext && strcasecmp(ext, ".csv") == 0) {
            is_csv = 1;
            printf("CSV 파일이 감지되었습니다. TXT 파일로 변환합니다.\n");
            
            // CSV 파일을 TXT로 변환
            if (!convert_csv_to_txt(input_file, converted_txt_file)) {
                fprintf(stderr, "CSV 파일을 TXT 파일로 변환하는데 실패했습니다.\n");
                cleanup_hashtable();
                return 1;
            }
            
            // 변환된 TXT 파일 정렬
            if (!sort_txt_file(converted_txt_file, sorted_txt_file)) {
                fprintf(stderr, "TXT 파일 정렬에 실패했습니다.\n");
                cleanup_hashtable();
                return 1;
            }
        } else {
            // TXT 파일 바로 정렬
            if (!sort_txt_file(input_file, sorted_txt_file)) {
                fprintf(stderr, "파일 정렬에 실패했습니다.\n");
                cleanup_hashtable();
                return 1;
            }
        }
        
        // 정렬된 파일에서 도메인 로드
        if (!load_domains_from_txt(sorted_txt_file)) {
            fprintf(stderr, "도메인 로드에 실패했습니다.\n");
            cleanup_hashtable();
            return 1;
        }
        
        printf("Target host to block: %s\n", target_host);

        printf("opening library handle\n");
        h = nfq_open();
        if (!h) {
                fprintf(stderr, "error during nfq_open()\n");
                exit(1);
        }

        printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
        if (nfq_unbind_pf(h, AF_INET) < 0) {
                fprintf(stderr, "error during nfq_unbind_pf()\n");
                exit(1);
        }

        printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
        if (nfq_bind_pf(h, AF_INET) < 0) {
                fprintf(stderr, "error during nfq_bind_pf()\n");
                exit(1);
        }

        printf("binding this socket to queue '0'\n");
        qh = nfq_create_queue(h,  0, &cb, NULL);
        if (!qh) {
                fprintf(stderr, "error during nfq_create_queue()\n");
                exit(1);
        }

        printf("setting copy_packet mode\n");
        if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
                fprintf(stderr, "can't set packet_copy mode\n");
                exit(1);
        }

        fd = nfq_fd(h);

        printf("Ready to filter. Run the following command to redirect packets to the queue:\n");
        printf("sudo iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE --queue-num 0\n");
        printf("sudo iptables -A INPUT -p tcp --sport 80 -j NFQUEUE --queue-num 0\n");

        for (;;) {
                if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
                        printf("패킷 수신\n");
                        nfq_handle_packet(h, buf, rv);
                        continue;
                }

                if (rv < 0 && errno == ENOBUFS) {
                        printf("패킷 손실 발생!\n");
                        continue;
                }
                perror("recv 실패");
                break;
        }

        printf("큐 0에서 언바인딩\n");
        nfq_destroy_queue(qh);

        printf("AF_INET에서 언바인딩\n");
        nfq_unbind_pf(h, AF_INET);

        printf("라이브러리 핸들 닫기\n");
        nfq_close(h);
        
        // 리소스 정리
        cleanup_hashtable();

        exit(0);
}
