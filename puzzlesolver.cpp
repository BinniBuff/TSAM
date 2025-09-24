#include <stdio.h>
#include <iostream>
#include <cstdio>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <array>
#include <cstring>
#include <stdint.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdbool.h>

#define PACK_LEN 4096

using namespace std;

// ip_checksum
static uint16_t ip_checksum(const void* vdata, size_t length) {
    const uint16_t* data = (const uint16_t*)vdata;
    uint32_t acc = 0;
    for (size_t i = 0; i + 1 < length; i += 2) acc += *data++;
    if (length & 1) acc += *(const uint8_t*)data << 8;
    while (acc >> 16) acc = (acc & 0xffff) + (acc >> 16);
    return htons(~acc);
}

static uint16_t udp_checksum_ipv4(const iphdr* iph, const udphdr* udph, const uint8_t* payload, size_t plen) {
    struct {
        uint32_t saddr;
        uint32_t daddr;
        uint8_t  zero;
        uint8_t  protocol;
        uint16_t udp_len;
    } __attribute__((packed)) psh;
    psh.saddr = iph->saddr;
    psh.daddr = iph->daddr;
    psh.zero = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_len = udph->len; // already network order

    uint32_t sum = 0;

    auto add = [&](const uint8_t* data, size_t len){
        while (len > 1) { sum += *(const uint16_t*)data; data += 2; len -= 2; }
        if (len) sum += *(const uint8_t*)data << 8; // odd byte
    };

    add((uint8_t*)&psh, sizeof(psh));
    add((const uint8_t*)udph, sizeof(*udph));
    add(payload, plen);

    // fold carries
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    uint16_t res = ~((uint16_t)sum);
    if (res == 0) res = 0xffff; // UDP checksum of 0 means "no checksum"; use 0xFFFF instead
    return res;
}

void evil(int udpsock, struct sockaddr_in *udpAddress, char *buffer, socklen_t *address_length_ptr, int evil_port, uint32_t signature, char *out_phrase, size_t out_phrase_len)
{
    // To learn "https://gist.github.com/leonid-ed/909a883c114eb58ed49f"


    struct iphdr *ip = (struct iphdr *) buffer;
    struct udphdr *udp = (struct udphdr *) (buffer + sizeof(struct iphdr));
    socklen_t address_length = *address_length_ptr;

    struct sockaddr_in sin;
    struct sockaddr_in local_ip;
    socklen_t local_ip_len = sizeof(local_ip);
    int one = 1;
    const int *val = &one;


    memset(buffer, 0, PACK_LEN);

    // create a raw socket with UDP protocol
    int sd;
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sd < 0)
    {
		perror("socket() error");
		exit(2);
    }
    printf("OK: a raw socket is created.\n");

    // inform the kernel do not fill up the packet structure, we will build our own
    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
		perror("setsockopt() error");
		exit(2);
    }
    printf("OK: socket option IP_HDRINCL is set.\n");

    sin.sin_family = AF_INET;
    sin.sin_port = htons(evil_port);
    sin.sin_addr.s_addr = udpAddress->sin_addr.s_addr;

    // fabricate the IP header
    ip->ihl      = 5;
    ip->version  = 4;
    ip->tos      = 16; // low delay
    // ip->tot_len  = sizeof(struct iphdr) + sizeof(struct udphdr);
    // ip->id       = htons(54321);
    // ip->ttl      = 64; // hops
    // ip->protocol = 17; // UDP
    // ip->frag_off |= htons(0x8000);  // Muhahahahaha
    // ip->check = 0;
    // ip->check = csum((unsigned short *)ip, sizeof(struct iphdr) / 2);
    int pktlen = sizeof(struct iphdr) + sizeof(struct udphdr);
    ip->tot_len  = htons(pktlen);   // total length in network order
    ip->id       = htons(54321);
    ip->ttl      = 64;              // hops
    ip->protocol = IPPROTO_UDP;     // UDP
    ip->frag_off = htons(0x8000);


    // source IP address, can use spoofed address here
    // ip->saddr = getsockname(udpsock, (struct sockaddr *)&local_ip, &local_ip_len);
    if (getsockname(udpsock, (struct sockaddr *)&local_ip, &local_ip_len) == 0)
    {
        ip->saddr = local_ip.sin_addr.s_addr;
    } else {
        perror("getsockname");
        ip->saddr = inet_addr("0.0.0.0");
    }
    ip->daddr = udpAddress->sin_addr.s_addr;
    ip->check = 0;
    ip->check = ip_checksum((unsigned short *)ip, sizeof(struct iphdr) / 2);


    // fabricate the UDP header
    // udp->source = udpAddress->sin_port;
    // // destination port number
    // udp->dest = htons(evil_port);
    // udp->len = htons(sizeof(struct udphdr));

    // if (sendto(sd, buffer, ip->tot_len, 0,
    //             (struct sockaddr *)&sin, sizeof(sin)) < 0)
    // {
    //     perror("sendto()");
    //     exit(3);
    // }
    udp->source = htons(54321);
    udp->dest   = htons(evil_port);
    udp->len    = htons(sizeof(struct udphdr));

    
    if (sendto(sd, buffer, pktlen, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto()");
        close(sd);
        exit(3);
    }
    close(sd);

    ssize_t resp_1 = recvfrom(udpsock, buffer, PACK_LEN - 1, 0, (struct sockaddr *)udpAddress, &address_length);
    if (resp_1 < 0)
    {
        // no reply timeout, or error
        perror("recvfrom (waiting for secret reply)");
    } else {
        // print length and sender IP:port
        char saddr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &udpAddress->sin_addr, saddr, sizeof(saddr));
        printf("recvfrom returned %zd bytes from %s:%d\n", resp_1, saddr, ntohs(udpAddress->sin_port));

        // hex dump
        printf("data (hex):");
        for (ssize_t i = 0; i < resp_1; ++i) printf(" %02x", (unsigned char)buffer[i]);
        printf("\n");

        // safe string view
        {
            size_t n = (size_t)resp_1;
            char tmp[n+1];
            memcpy(tmp, buffer, n);
            tmp[n] = '\0';
            printf("as-string: '%s'\n", tmp);
        }
    }

    uint32_t net_signature = htonl(signature);
    ssize_t sent = sendto(udpsock, &net_signature, 4, 0, (struct sockaddr *)udpAddress, sizeof(*udpAddress));

    if (sent != 4)
    {
        perror("sendto signature to evil port failed");
    } else {
        printf("Sent 4-byte signature to evil port (net order): %02x%02x%02x%02x\n", ((unsigned char *)&net_signature)[0], ((unsigned char *)&net_signature)[1], ((unsigned char *)&net_signature)[2], ((unsigned char *)&net_signature)[3]);

        // Reply
        socklen_t addrlen2 = sizeof(*udpAddress);
        ssize_t rlen = recvfrom(udpsock, buffer, PACK_LEN, 0, (struct sockaddr *)udpAddress, &addrlen2);
        if (rlen < 0) {
            perror("recvfrom after sending signature to evil port");
        } else {
            char saddr2[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &udpAddress->sin_addr, saddr2, sizeof(saddr2));
            printf("recvfrom returned %zd bytes from %s:%d\n", rlen, saddr2, ntohs(udpAddress->sin_port));



            // debug: hex + ascii
            // printf("data (hex):-----------------------");
            // for (ssize_t j = 0; j < rlen; ++j) printf(" %02x", (unsigned char)buffer[j]);
            // printf("\n");

            
            // safe string view 
            {
                 size_t n = (size_t)rlen;
                // char the_secret_phrase[n+1];
                // memcpy(the_secret_phrase, buffer, n);
                // the_secret_phrase[n] = '\0';
                // printf("as-string: '%s'\n", the_secret_phrase);
                // *out_phrase = the_secret_phrase;
                if (n > 0 && out_phrase != NULL && out_phrase_len > 0) {
                
                size_t copy_len = (n < out_phrase_len - 1) ? n : (out_phrase_len - 1);
                memcpy(out_phrase, buffer, copy_len);
                out_phrase[copy_len] = '\0';
    }
            // debug print
            printf("as-string (evil reply): '%s' (len=%zd)\n", out_phrase ? out_phrase : "(null)", rlen);
            }

            // try parse ASCII port
            // NO PORT HERE (as far as I can see)
            // {
            //     char tmp2[rlen+1];
            //     memcpy(tmp2, buffer, rlen);
            //     tmp2[rlen] = '\0';
            //     long port = strtol(tmp2, NULL, 10);
            //     if (port > 0 && port <= 65535)
            //     {
            //         printf("Parsed ASCII port: %ld\n", port);
            //         *out_port = port;
            //         // stored_secret_port = (int)p;
            //     }
            // }
            
        }
    }
}

void secrete(int udpsock, struct sockaddr_in *udpAddress, char *buffer, socklen_t *address_length_ptr, uint32_t *out_signature, uint16_t *out_port)
//char *secrete(int udpsock, struct sockaddr_in *udpAddress, char *buffer, socklen_t *address_length_ptr)
{
    // Note: address_length_ptr is a pointer to the socklen_t used by the caller
    socklen_t address_length = *address_length_ptr;
    char answer[4096];

    *out_signature = 0;
    *out_port = 0;

    cout << "In secret!" << endl;
    memset(buffer, 0, 4096);
    u_int32_t secret_num = 0x55555555;      // or 0101-0101 0101-0101 0101-0101 0101-0101 0101-0101 0101-0101 0101-0101 0101-0101
    uint32_t secret_num_ordered = htonl(secret_num);    // Secret number in network order
    const char users[] = "brynjolfur23,sigurjong22";
    char secret_message[256];           // create a char array to assemble secrete msg in
    size_t char_arr_index = 0;
    secret_message[char_arr_index] = 'S';    // S is put in index 0, in secret_message
    char_arr_index++;                        // incrament index

    //secret_message.resize(1 + sizeof(secret_num));
    //memcpy(secret_message[1], &secret_num, sizeof(secret_num));
    memcpy(secret_message + char_arr_index, &secret_num_ordered, 4);    // Go into secret_message, then move char_arr_index amount of spaces and put secret_num_ordered there
    char_arr_index += 4;    // Move the index by 4 bytes

    size_t users_len = strlen(users);

    //strcpy(secret_message + char_arr_index, users);            // extend secret_message by users
    memcpy(secret_message + char_arr_index, users, users_len);
    char_arr_index += users_len;        // Move index to end

    secret_message[char_arr_index] = '\0'; // ensure safe printing (and not change logic)

    cout << "\n---- ***" << secret_message << "*** ----\n" << endl;
    if(sendto(udpsock, secret_message, char_arr_index, 0, (struct sockaddr *)udpAddress, sizeof(*udpAddress)) < 0)
    {
        perror("Could not connect");
        close(udpsock);
        exit(0);
    }
    ssize_t resp_len = recvfrom(udpsock, buffer, PACK_LEN - 1, 0, (struct sockaddr *)udpAddress, &address_length);
    if (resp_len < 0)
    {
        // no reply timeout, or error
        perror("recvfrom (waiting for secret reply)");
    } else {
        // print length and sender IP:port
        char saddr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &udpAddress->sin_addr, saddr, sizeof(saddr));
        printf("recvfrom returned %zd bytes from %s:%d\n", resp_len, saddr, ntohs(udpAddress->sin_port));

        // hex dump
        printf("data (hex):");
        for (ssize_t i = 0; i < resp_len; ++i) printf(" %02x", (unsigned char)buffer[i]);
        printf("\n");

        // safe string view
        {
            size_t n = (size_t)resp_len;
            char tmp[n+1];
            memcpy(tmp, buffer, n);
            tmp[n] = '\0';
            printf("as-string: '%s'\n", tmp);
        }

        // If this is the 5-byte S.E.C.R.E.T. reply, parse it and print values
        if (resp_len >= 5)
        {
            uint8_t group_id = (uint8_t)buffer[0];
            answer[0] = buffer[0]; //-------------------------------------------------------------------------
            uint32_t net_challenge;
            memcpy(&net_challenge, buffer + 1, 4);
            uint32_t challenge = ntohl(net_challenge);
            printf("Parsed S.E.C.R.E.T. reply -> group_id=%u, challenge=0x%08x (%u)\n", (unsigned)group_id, challenge, (unsigned)challenge);

            uint32_t signature = challenge ^ secret_num;
            *out_signature = signature;      // The signature

            // Prepping reply with signature
            uint32_t net_signature = htonl(signature);
            // The reply
            unsigned char five_byte_msg[5];
            five_byte_msg[0] = group_id;
            memcpy(five_byte_msg + 1, &net_signature, 4);

            ssize_t sent = sendto(udpsock, five_byte_msg, sizeof(five_byte_msg), 0, (struct sockaddr *)udpAddress, sizeof(*udpAddress));
            if (sent != (ssize_t)sizeof(five_byte_msg))
            {
                perror("sendto signature failed");
            } else {
                printf("Sent signature for group %u: 0x%08x\n", (unsigned)group_id, signature);

            }

            char final_buf[PACK_LEN];
            socklen_t final_addr_len = sizeof(*udpAddress);
            ssize_t final_len = recvfrom(udpsock, final_buf, PACK_LEN, 0, (struct sockaddr *)udpAddress, &final_addr_len);
            if (final_len < 0)
            {
                perror("recvfrom (waiting for secret-port)");
            } else {
                printf("data (hex):");
                for (ssize_t i = 0; i < final_len; ++i) printf(" %02x", (unsigned char)final_buf[i]);
                printf("\n");

                {
                    size_t n = (size_t)final_len;
                    char tmp[n+1];
                    memcpy(tmp, final_buf, n);
                    tmp[n] = '\0';
                    long p = strtol(tmp, NULL, 10);
                    if (p > 0 && p <= 65535) {
                        printf("Parsed ASCII port: %ld\n", p);
                    } else {
                        // 5) Try to parse as binary 16-bit or 32-bit network-order integer(s)
                        if (final_len >= 2)
                        {
                            uint16_t v16;
                            memcpy(&v16, final_buf, 2);
                            uint16_t port16 = ntohs(v16);
                            if (port16 > 0 && port16 <= 65535)
                            {
                                printf("Network-order port: %u\n", (unsigned)port16);
                                *out_port = port16; // The port
                            }
                        }
                    }
                }
            }
        }
    }
    
    
}

void checksum(int udpsock, struct sockaddr_in *udpAddress, char *buffer, socklen_t *address_length_ptr, uint32_t signature, uint16_t secret_port, char *out_phrase)
{
	uint32_t net_signature = htonl(signature);
    ssize_t sent = sendto(udpsock, &net_signature, 4, 0, (struct sockaddr *)udpAddress, sizeof(*udpAddress));

    if (sent != 4)
    {
        perror("sendto signature to evil port failed");
    } 
    else 
    {
        printf("Sent 4-byte signature to checksum port (net order): %02x%02x%02x%02x\n", ((unsigned char *)&net_signature)[0], ((unsigned char *)&net_signature)[1], ((unsigned char *)&net_signature)[2], ((unsigned char *)&net_signature)[3]);

        // Reply
        socklen_t addrlen2 = sizeof(*udpAddress);
        ssize_t rlen = recvfrom(udpsock, buffer, PACK_LEN, 0, (struct sockaddr *)udpAddress, &addrlen2);
        if (rlen < 0) {
            perror("recvfrom after sending signature to checksum port");
        } 
        else 
        {
            char saddr2[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &udpAddress->sin_addr, saddr2, sizeof(saddr2));
            printf("recvfrom returned %zd bytes from %s:%d\n", rlen, saddr2, ntohs(udpAddress->sin_port));
            // hex dump
			printf("data (hex):");
			for (ssize_t i = 0; i < rlen; ++i) printf(" %02x", (unsigned char)buffer[i]);
			printf("\n");

			// safe string view
			{
				size_t n = (size_t)rlen;
				char tmp[n+1];
				memcpy(tmp, buffer, n);
				tmp[n] = '\0';
				printf("as-string: '%s'\n", tmp);
			}
			uint32_t ip_from_checksum;
			memcpy(&ip_from_checksum, buffer + rlen - 4, 4);
			uint16_t checksum;
			memcpy(&checksum, buffer + rlen - 6, 2);
			
			uint8_t headers[20 + 8 + 2] = {0};
			struct iphdr *ip = (struct iphdr *)headers;
			struct udphdr *udp = (struct udphdr *)(headers + sizeof(struct iphdr));
			uint8_t *pl  = headers + 20 + 8;
			
			ip->ihl      = 5;                             
			ip->version  = 4;
			ip->tos      = 0;
			ip->tot_len  = htons(sizeof(headers));          
			ip->id       = htons(0);
			ip->frag_off = htons(0);
			ip->ttl      = 64;
			ip->protocol = IPPROTO_UDP;
			ip->saddr    = ip_from_checksum;                  
			ip->daddr    = udpAddress->sin_addr.s_addr;   
			ip->check    = 0;
			ip->check    = ip_checksum(ip, sizeof(*ip));
			
			udp->source = htons(secret_port);                  
			udp->dest   = udpAddress->sin_port;           
			udp->len    = htons(sizeof(struct udphdr) + 2);
			udp->check = 0; 
			
			uint16_t calc0 = udp_checksum_ipv4(ip, udp, nullptr, 0);
			
			// expected checksum (host order)
			uint16_t Ehost = ntohs(checksum);

			// baseline checksum you computed with len=10 and no payload (host order)
			uint16_t calc0_host = ntohs(calc0);

			// target folded sum is ~E (host)
			uint16_t target = (uint16_t)(~Ehost & 0xFFFF);

			// K must satisfy: fold( S + K ) == target, where S = ~calc0_host
			// A minimal solution is: K = fold( target + calc0_host )
			uint32_t ksum = (uint32_t)target + (uint32_t)calc0_host;
			ksum = (ksum & 0xFFFF) + (ksum >> 16);   // end-around carry
			ksum = (ksum & 0xFFFF) + (ksum >> 16);   // (once more, just in case)
			uint16_t K = (uint16_t)ksum;
			
			*(uint16_t*)pl = htons(K);
			uint16_t final = udp_checksum_ipv4(ip, udp, pl, 2);
			udp->check = final;
			
			printf("expected=0x%04x  calc0=0x%04x  F=0x%04x  K=0x%04x  final=0x%04x\n", Ehost, ntohs(calc0), target, K, ntohs(final));
			
			ssize_t sent_2 = sendto(udpsock, headers, sizeof(headers), 0, (struct sockaddr *)udpAddress, sizeof(*udpAddress));
			if (sent_2 != sizeof(headers))
			{
				perror("sending second message to checksum failed");
				exit(0);
			}
			else
			{
				ssize_t rlen2 = recvfrom(udpsock, buffer, PACK_LEN, 0, (struct sockaddr *)udpAddress, &addrlen2);
				if (rlen2 < 0) {
					perror("recvfrom error after sending second message to checksum port");
				} 
				else 
				{
					char saddr2[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, &udpAddress->sin_addr, saddr2, sizeof(saddr2));
					printf("recvfrom returned %zd bytes from %s:%d\n", rlen2, saddr2, ntohs(udpAddress->sin_port));
					// hex dump
					printf("data (hex):");
					for (ssize_t i = 0; i < rlen2; ++i) printf(" %02x", (unsigned char)buffer[i]);
					printf("\n");

					// safe string view
					{
						size_t n = (size_t)rlen2;
						char tmp[n+1];
						memcpy(tmp, buffer, n);
						tmp[n] = '\0';
						printf("as-string: '%s'\n", tmp);
						for (int j = 0; j < n; j++)
						{
							if (tmp[j] == '"')
							{
								memcpy(out_phrase, tmp + j, n - j);
							}
						}
					}
				}
			}
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc != 6)            // Arguments need to be 6 including the program
    {
        cout << "The number of arguments needs to be 6! ./puzzlesolver <IP address> <port1> <port2> <port3> <port4>" << endl;
        exit(0);
    }

    int udpsock;

    if ((udpsock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)    // open the socket
    {
        perror("Failed to open socket");
        exit(0);
    }

    // Get IP address and ports
    char *ipAddress = argv[1];
    int port1 = atoi(argv[2]);
    int port2 = atoi(argv[3]);
    int port3 = atoi(argv[4]);
    int port4 = atoi(argv[5]);
    int portnrs[] = {port1, port2, port3, port4};
    int portnrsord[4];

    // fall {order}

    // {portnrs
    // secret [0]
    // evil [1]
    // chk [2]
    // knok[3]

    // }

    // try to reach all ports in the given range
    //for (int i = 0; i < sizeof(portnrs); i++)            // sizeof returns the number of bytes, not items
    int portCount = sizeof(portnrs) / sizeof(portnrs[0]);        // Size of the array in bytes divided by the size of the first item, should give the number of items
    struct sockaddr_in udpAddress;
    // set IP address in socket
    if(inet_pton(AF_INET, ipAddress, &udpAddress.sin_addr) != 1)
    {
        cout << "Failed to set socket address" << endl;
        exit(0);
    }

    socklen_t address_length = sizeof(udpAddress);

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    if (setsockopt(udpsock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        perror("timeout failed");
        exit(0);
    }

    for (int i = 0; i < portCount; ++i)
    {
        // set up socket port number
        
        udpAddress.sin_family = AF_INET;
        udpAddress.sin_port = htons(portnrs[i]);

        const char *message = "hello UDP";

        // try to connect to the socket
        if(sendto(udpsock, message, strlen(message), 0, (struct sockaddr *)&udpAddress, sizeof(udpAddress)) < 0)
        {
            perror("Could not connect");
            close(udpsock);
            exit(0);
        }

        char buffer[4096];

        ssize_t recvfrom_len = recvfrom(udpsock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&udpAddress, &address_length);

        // if (recvfrom(udpsock, &buffer, 4096, 0, (struct sockaddr *)&
        // udpAddress, &address_length) >= 0)
        if (recvfrom_len >= 0)
        {
            buffer[recvfrom_len] = '\0';        // add null termination
            cout << portnrs[i] << ": \n" << buffer << endl;
            if (buffer[0] == 'G' && buffer[9] != '!')
            {
                portnrsord[0] = portnrs[i];
                // call the function (secrete) that contains the previous block
                // secrete(udpsock, &udpAddress, buffer, &address_length);
            }
            else if (buffer[0] == 'G' && buffer[9] == '!')
            {
                portnrsord[3] = portnrs[i];
                // call the function (secrete) that contains the previous block
                // secrete(udpsock, &udpAddress, buffer, &address_length);
            }
            else if (buffer[0] == 'T')
            {
                portnrsord[1] = portnrs[i];
                // call the function (secrete) that contains the previous block
                // secrete(udpsock, &udpAddress, buffer, &address_length);
            }
            else if(buffer[0] == 'S')
            {
                portnrsord[2] = portnrs[i];
                // call the function (secrete) that contains the previous block
                // secrete(udpsock, &udpAddress, buffer, &address_length);
            }
        }
    }
    char buffer[4096];
    uint32_t secret_signature = 0;      // The signature from secret not in network order
    uint16_t secret_port = 0;           // port from secret
    char the_secret_phrase[256] = {0};             // the secret phrase from checksum
    for (int i = 0; i < portCount; ++i)
    {
        // set up socket port number
        
        udpAddress.sin_family = AF_INET;
        udpAddress.sin_port = htons(portnrsord[i]);

        if (i == 0)
        {   
            printf("Entering secret.\n");
            secrete(udpsock, &udpAddress, buffer, &address_length, &secret_signature, &secret_port);
            printf("After secrete: secret_signature=0x%08x, secret_port=%u\n", (unsigned)secret_signature, (unsigned)secret_port);
        }
        else if (i == 1)
        {
            printf("Entering evil.\n");
            evil(udpsock, &udpAddress, buffer, &address_length, portnrsord[1], secret_signature, the_secret_phrase, sizeof(the_secret_phrase));
            printf("After evil: secret phrase: '%s'\n", the_secret_phrase);
        }
        else if (i == 2)
        {
			printf("Entering checksum.\n");
			checksum(udpsock, &udpAddress, buffer, &address_length, secret_signature, secret_port, the_secret_phrase);
			printf("After checksum: secret phrase: '%s'\n", the_secret_phrase);
		}
    }
    close(udpsock);
}
