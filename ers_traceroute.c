#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <sys/time.h>

#define PACKET_SIZE 64
#define TIMEOUT 2

// 計算 checksum
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// 解析主機名稱或 IP 位址
int resolve_hostname(const char *hostname, struct sockaddr_in *addr) {
    struct hostent *host;
    
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
    
    // 嘗試直接解析為 IP
    if (inet_pton(AF_INET, hostname, &(addr->sin_addr)) == 1) {
        return 0;
    }
    
    // 嘗試解析主機名稱
    host = gethostbyname(hostname);
    if (host == NULL) {
        fprintf(stderr, "Cannot resolve hostname: %s\n", hostname);
        return -1;
    }
    
    memcpy(&(addr->sin_addr), host->h_addr, host->h_length);
    return 0;
}

// 發送 ICMP Echo Request
int send_icmp_request(int sockfd, struct sockaddr_in *dest_addr, int ttl, int seq) {
    char packet[PACKET_SIZE];
    struct icmp *icmp_hdr;
    
    memset(packet, 0, PACKET_SIZE);
    
    // 設定 ICMP header
    icmp_hdr = (struct icmp *)packet;
    icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_id = getpid() & 0xFFFF;
    icmp_hdr->icmp_seq = seq;
    icmp_hdr->icmp_cksum = 0;
    icmp_hdr->icmp_cksum = checksum(icmp_hdr, PACKET_SIZE);
    
    // 設定 TTL
    if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        perror("setsockopt TTL");
        return -1;
    }
    
    // 發送封包
    if (sendto(sockfd, packet, PACKET_SIZE, 0, 
               (struct sockaddr *)dest_addr, sizeof(struct sockaddr_in)) < 0) {
        perror("sendto");
        return -1;
    }
    
    return 0;
}

// 接收 ICMP 回應
int receive_icmp_reply(int sockfd, char *from_addr, int addr_len) {
    char buffer[512];
    struct sockaddr_in recv_addr;
    socklen_t recv_addr_len = sizeof(recv_addr);
    struct ip *ip_hdr;
    struct icmp *icmp_hdr;
    int n;
    
    // 設定接收超時
    struct timeval tv;
    tv.tv_sec = TIMEOUT;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt SO_RCVTIMEO");
        return -1;
    }
    
    // 接收封包
    n = recvfrom(sockfd, buffer, sizeof(buffer), 0, 
                 (struct sockaddr *)&recv_addr, &recv_addr_len);
    
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            strcpy(from_addr, "*");
            return 0;
        }
        perror("recvfrom");
        return -1;
    }
    
    // 解析 IP header
    ip_hdr = (struct ip *)buffer;
    int ip_hdr_len = ip_hdr->ip_hl << 2;
    
    // 解析 ICMP header
    icmp_hdr = (struct icmp *)(buffer + ip_hdr_len);
    
    // 檢查是否為我們期待的回應
    if (icmp_hdr->icmp_type == ICMP_TIME_EXCEEDED || 
        icmp_hdr->icmp_type == ICMP_ECHOREPLY) {
        inet_ntop(AF_INET, &(recv_addr.sin_addr), from_addr, addr_len);
        return 1;
    }
    
    return 0;
}

int main(int argc, char *argv[]) {
    int hop_distance;
    char *destination;
    int sockfd;
    struct sockaddr_in dest_addr;
    char from_addr[INET_ADDRSTRLEN];
    int result;
    
    // 檢查參數
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <hop-distance> <destination>\n", argv[0]);
        fprintf(stderr, "Example: %s 3 140.117.11.1\n", argv[0]);
        return 1;
    }
    
    hop_distance = atoi(argv[1]);
    destination = argv[2];
    
    if (hop_distance <= 0) {
        fprintf(stderr, "Error: hop-distance must be positive\n");
        return 1;
    }
    
    // 解析目標位址
    if (resolve_hostname(destination, &dest_addr) < 0) {
        return 1;
    }
    
    // 建立 raw socket (需要 root 權限)
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket");
        fprintf(stderr, "Note: This program requires root privileges\n");
        return 1;
    }
    
    printf("Searching for router at hop %d to %s...\n", hop_distance, destination);
    
    // 發送 ICMP 請求，TTL 設為指定的 hop distance
    if (send_icmp_request(sockfd, &dest_addr, hop_distance, 1) < 0) {
        close(sockfd);
        return 1;
    }
    
    // 接收回應
    result = receive_icmp_reply(sockfd, from_addr, sizeof(from_addr));
    
    if (result > 0) {
        printf("Hop %d: %s\n", hop_distance, from_addr);
    } else if (result == 0) {
        printf("Hop %d: * (timeout)\n", hop_distance);
    } else {
        printf("Error receiving reply\n");
    }
    
    close(sockfd);
    return 0;
}