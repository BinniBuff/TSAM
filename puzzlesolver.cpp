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
#include <linux/udp.h>
#include <stdbool.h>
#include <netinet/ip_icmp.h>

#define PACK_LEN 4096

using namespace std;

// Clear the receive buffer
void flush_socket(int sock) {
    char dummy_buffer[1];
    while (recvfrom(sock, dummy_buffer, sizeof(dummy_buffer), MSG_DONTWAIT, NULL, NULL) > 0);
}

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
    if (res == 0) res = 0xffff;
    return res;
}


void send_bonus_ping(int group_id, const char* ip_address) {
    // Create the raw socket for ICMP
    int icmp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_socket < 0) {
        perror("bonus socket");
        return;
    }

    // Set up destination address
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip_address, &dest_addr.sin_addr);

    // Prepare the packet buffer and payload
    char packet[128];
    memset(packet, 0, sizeof(packet));

    struct icmphdr *icmp_hdr = (struct icmphdr *)packet;
    char *payload = packet + sizeof(struct icmphdr);
    
    char payload_str[32];
    snprintf(payload_str, sizeof(payload_str), "$group_%d$", group_id);

    // Fill in the ICMP header
    icmp_hdr->type = ICMP_ECHO;
    icmp_hdr->code = 0;
    icmp_hdr->un.echo.id = htons(getpid()); // Use process ID
    icmp_hdr->un.echo.sequence = htons(1);
    
    // Copy the payload into the packet
    memcpy(payload, payload_str, strlen(payload_str));
    
    // Calculate checksum over the whole packet (header + payload)
    int packet_size = sizeof(struct icmphdr) + strlen(payload_str);
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = ip_checksum(packet, packet_size);

    // Send the packet
    printf("\nSending bonus ICMP echo request...\n");
    if (sendto(icmp_socket, packet, packet_size, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("bonus sendto");
    }

    close(icmp_socket);
}


void evil(int udpsock, struct sockaddr_in *udpAddress, char *buffer, socklen_t *address_length_ptr, uint32_t signature, uint16_t *out_port)
{
    struct sockaddr_in sender_address;
    socklen_t sender_len = sizeof(sender_address);
    *out_port = 0; // Initialize output port

    uint32_t net_signature = htonl(signature);

    // Create and send the single raw packet with signature as payload
    {
        int sraw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sraw < 0) {
            perror("socket raw");
            return;
        }

        int one = 1;
        if (setsockopt(sraw, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
            perror("setsockopt IP_HDRINCL");
            close(sraw);
            return;
        }

        unsigned char pkt[PACK_LEN];
        memset(pkt, 0, sizeof(pkt));

        struct iphdr *ip2 = (struct iphdr *)pkt;
        struct udphdr *udp2 = (struct udphdr *)(pkt + sizeof(struct iphdr));

        int payload_len = 4;
        int pktlen = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;

        // IP header
        ip2->ihl = 5;
        ip2->version = 4;
        ip2->tos = 0;
        ip2->tot_len = htons(pktlen);
        ip2->id = htons(54322);
        ip2->frag_off = htons(0x8000); // Muhahahahaha
        ip2->ttl = 64;
        ip2->protocol = IPPROTO_UDP;

        struct sockaddr_in local_ip;
        socklen_t local_ip_len = sizeof(local_ip);
        if (getsockname(udpsock, (struct sockaddr *)&local_ip, &local_ip_len) == 0) {
            ip2->saddr = local_ip.sin_addr.s_addr;
        } else {
            perror("getsockname for raw send");
            ip2->saddr = inet_addr("0.0.0.0");
        }
        ip2->daddr = udpAddress->sin_addr.s_addr;

        // UDP header
        udp2->source = local_ip.sin_port;
        udp2->dest = udpAddress->sin_port;
        udp2->len = htons(sizeof(struct udphdr) + payload_len);
        udp2->check = 0;

        memcpy((unsigned char*)udp2 + sizeof(struct udphdr), &net_signature, 4);

        ip2->check = 0;
        ip2->check = ip_checksum((unsigned short *)ip2, sizeof(struct iphdr));

        if (sendto(sraw, pkt, pktlen, 0, (struct sockaddr *)udpAddress, sizeof(*udpAddress)) < 0) {
            perror("sendto raw signature");
        } else {
            printf("Sent raw 4-byte signature (evil) to %s:%u\n",
                inet_ntoa(udpAddress->sin_addr), ntohs(udpAddress->sin_port));
        }
        close(sraw);
    }

    // Receive the reply on a normal UDP socket
    {
        char acc[PACK_LEN];
        ssize_t rlen = recvfrom(udpsock, acc, sizeof(acc) - 1, 0, (struct sockaddr *)&sender_address, &sender_len);
        if (rlen < 0) {
            perror("recvfrom after sending raw evil packet");
        } else {
            acc[rlen] = '\0'; // Null-terminate
            printf("as-string (evil reply): '%s'\n", acc);
            
            // Find the last colon ':' in the message, the port number should follow
            char* last_colon = strrchr(acc, ':');
            if (last_colon != NULL) {
                char* num_start = last_colon + 1;
                while (*num_start == ' ' || *num_start == '\n' || *num_start == '\t') {
                    num_start++;
                }
                
                long port = strtol(num_start, NULL, 10);
                if (port > 0 && port <= 65535) {
                    printf("Successfully parsed evil port: %ld\n", port);
                    *out_port = (uint16_t)port;
                }
            } else {
                printf("Could not find port number in evil reply.\n");
            }
        }
    }
}


void secrete(int udpsock, struct sockaddr_in *udpAddress, char *buffer, socklen_t *address_length_ptr, uint32_t *out_signature, uint16_t *out_port)
{
    struct sockaddr_in sender_address;
    socklen_t sender_address_len = sizeof(sender_address);
    // address_length_ptr is a pointer to the socklen_t used by the caller
    // socklen_t address_length = *address_length_ptr;
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
    // ssize_t resp_len = recvfrom(udpsock, buffer, PACK_LEN - 1, 0, (struct sockaddr *)udpAddress, &address_length);
    ssize_t resp_len = recvfrom(udpsock, buffer, PACK_LEN - 1, 0, (struct sockaddr *)&sender_address, &sender_address_len);
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
            // ssize_t final_len = recvfrom(udpsock, final_buf, PACK_LEN, 0, (struct sockaddr *)udpAddress, &final_addr_len);
            ssize_t final_len = recvfrom(udpsock, final_buf, PACK_LEN, 0, (struct sockaddr *)&sender_address, &sender_address_len);
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
                    tmp[n] = '\0'; // Null terminate the received data
                    printf("Full reply from secrete: '%s'\n", tmp);

                    // Find the last colon ':' in the message, the port number should follow
                    char* last_colon = strrchr(tmp, ':');
                    if (last_colon != NULL) {
                        // Move pointer past the colon and any whitespace
                        char* num_start = last_colon + 1;
                        while (*num_start == ' ') {
                            num_start++;
                        }
                        
                        long port = strtol(num_start, NULL, 10);
                        if (port > 0 && port <= 65535) {
                            printf("Successfully parsed secret port: %ld\n", port);
                            *out_port = (uint16_t)port;
                        } else {
                            printf("Failed to parse port from substring: '%s'\n", num_start);
                        }
                    } else {
                        printf("Could not find ':' in secrete reply.\n");
                    }
                }

            }
        }
    }
    
    
}

void checksum(int udpsock, struct sockaddr_in *udpAddress, char *buffer, socklen_t *address_length_ptr, uint32_t signature, uint16_t secret_port, char *out_phrase)
{
    struct sockaddr_in sender_address;  // create new sender address for the second message
	uint32_t net_signature = htonl(signature);   // signature needs to be network byte order before sent
    ssize_t sent = sendto(udpsock, &net_signature, 4, 0, (struct sockaddr *)udpAddress, sizeof(*udpAddress));

	// if sending fails
    if (sent != 4)
    {
        perror("sendto signature to checksum port failed");
    } 
    // successfully sent the signature
    else 
    {
        socklen_t sender_len = sizeof(sender_address);
        // recieve from port to get instructions
        ssize_t rlen = recvfrom(udpsock, buffer, PACK_LEN, 0, (struct sockaddr *)&sender_address, &sender_len);
        
        // recieving failed
        if (rlen < 0) {
            perror("recvfrom after sending signature to checksum port");
        } 
        else 
        {
            
			uint32_t ip_from_checksum;   // sender IP from the port
			memcpy(&ip_from_checksum, buffer + rlen - 4, 4);
			uint16_t checksum;    // checksum from the port that we need to match
			memcpy(&checksum, buffer + rlen - 6, 2);
			
			uint8_t headers[20 + 8 + 2] = {0};			// make sure to have 2 extra bytes so the checksum is correct
			struct iphdr *ip = (struct iphdr *)headers;		// make IP header
			struct udphdr *udp = (struct udphdr *)(headers + sizeof(struct iphdr));		// make UDP header
			uint8_t *pl  = headers + 20 + 8;		// for calculating the checksum later
			
			// Fill in the IP header information needed
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
			
			// Fill in the UDP header information needed
			udp->source = htons(secret_port);                  
			udp->dest   = udpAddress->sin_port;           
			udp->len    = htons(sizeof(struct udphdr) + 2);
			udp->check = 0; 
			
			// calculate the checksum
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
			uint16_t final = udp_checksum_ipv4(ip, udp, pl, 2);		// calculate the final checksum that matches what the port gave
			udp->check = final;
			
			// Send the headers inside the message
			ssize_t sent_2 = sendto(udpsock, headers, sizeof(headers), 0, (struct sockaddr *)udpAddress, sizeof(*udpAddress));
			// If it failed
			if (sent_2 != sizeof(headers))
			{
				perror("sending second message to checksum failed");
				exit(0);
			}
			else
			{
                ssize_t rlen2 = recvfrom(udpsock, buffer, PACK_LEN, 0, (struct sockaddr *)&sender_address, &sender_len); // recieve from port after sending checksum
				if (rlen2 < 0) {
					perror("recvfrom error after sending second message to checksum port");
				} 
				else 
				{
					// long way to do it but here we take the secret phrase and memcpy it to the char array in main
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

void knocking(int udpsock, struct sockaddr_in *udpAddress, char *buffer, socklen_t *address_length_ptr, uint32_t signature, uint16_t secret_port1, uint16_t secret_port2, char *out_phrase)
{
    struct sockaddr_in sender_address; // make sure the second address is not the same
    socklen_t sender_len = sizeof(sender_address);
	char ports[32];
    int n = snprintf(ports, sizeof(ports), "%u,%u", (unsigned)secret_port1, (unsigned)secret_port2); //change secret ports to char
	
	// if there is an error in changing secret ports to char
	if (n < 0 || n >= (int)sizeof(ports)) 
	{
		fprintf(stderr, "ports formatting failed/overflow\n");
		return;
	}
	
	// send ports as char to port
	ssize_t sent = sendto(udpsock, ports, n, 0, (struct sockaddr *)udpAddress, sizeof(*udpAddress));
	if (sent != n)
    {
        perror("sendto ports to knocking port failed");
    } 
    else 
    {
        
        // Reply
        socklen_t addrlen2 = sizeof(*udpAddress);
        ssize_t rlen = recvfrom(udpsock, buffer, PACK_LEN, 0, (struct sockaddr *)&sender_address, &sender_len); // recieve from socket
        if (rlen < 0) 
        {
            perror("recvfrom after sending signature to checksum port");
        } 
        else 
		{

			char number[5];		// remove?

			// Build the payload, signature and secret phrase
			char receive_buffer[1024];
			char bonus_message[PACK_LEN] = {0}; // for the bonus points
			char knock_payload[1024];
			uint32_t net_signature = htonl(signature);

			// Copy the 4-byte signature into the payload
			memcpy(knock_payload, &net_signature, 4);

			// Copy the secret phrase after the signature.
			// Skip the quote marks at the beginning and end.
			size_t phrase_len = strlen(out_phrase);
			size_t actual_phrase_len = 0;
			if (phrase_len > 2 && out_phrase[0] == '"') 
			{
				actual_phrase_len = phrase_len - 2;
				memcpy(knock_payload + 4, out_phrase + 1, actual_phrase_len);
			} 
			else 
			{
				actual_phrase_len = phrase_len;
				memcpy(knock_payload + 4, out_phrase, actual_phrase_len);
			}

			size_t total_payload_len = 4 + actual_phrase_len;

			// Perform the knocks
			char* knock_port_str = strtok(tmp, ",");
			while (knock_port_str != NULL)
			{
				uint16_t knock_port = (uint16_t)strtol(knock_port_str, NULL, 10);
				if (knock_port > 0)
				{
					// Set the destination to the correct port
					udpAddress->sin_port = htons(knock_port);

					// Send the payload
					sendto(udpsock, knock_payload, total_payload_len, 0, (struct sockaddr *)udpAddress, sizeof(*udpAddress));

					// Listen to the reply to the knock
					rlen = recvfrom(udpsock, receive_buffer, sizeof(receive_buffer) - 1, 0, (struct sockaddr *)&sender_address, &sender_len);
					if (rlen > 0) 
					{
						receive_buffer[rlen] = '\0';
						// Add the reply to bonus message
						strncat(bonus_message, receive_buffer, sizeof(bonus_message) - strlen(bonus_message) - 1);
					}
				}
			// Get the next port from the string
			knock_port_str = strtok(NULL, ",");
			}
			
			// recieve message
			rlen = recvfrom(udpsock, buffer, PACK_LEN - 1, 0, (struct sockaddr *)&sender_address, &sender_len);
			if (rlen < 0) 
			{
				perror("recvfrom (waiting for message)");
			} 
			else 
			{
				buffer[rlen] = '\0';
				printf("\n--- SERVER MESSAGE ---\n%s\n--------------------------\n", buffer);
				printf("\n--- BONUS MESSAGE ---\n%s\n---------------------\n", bonus_message);
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
    // uint16_t evil_port_num = 4010;          // old dummy data, use when you cant use sudo, like on the t-sam server
    uint16_t evil_port_num = 0;         // port from evil
    char the_secret_phrase[256] = {0};             // the secret phrase from checksum
    for (int i = 0; i < portCount; ++i)
    {
        // set up socket port number
        
        udpAddress.sin_family = AF_INET;
        udpAddress.sin_port = htons(portnrsord[i]);
        flush_socket(udpsock);

        if (i == 0)
        {   
            printf("Entering secret.\n");
            secrete(udpsock, &udpAddress, buffer, &address_length, &secret_signature, &secret_port);
            printf("After secrete: secret_signature=0x%08x, secret_port=%u\n", (unsigned)secret_signature, (unsigned)secret_port);
        }
        else if (i == 1)
        {
            printf("Entering evil.\n");
            evil(udpsock, &udpAddress, buffer, &address_length, secret_signature, &evil_port_num);
            printf("After evil: secret_port=%u\n", (unsigned)evil_port_num);
        }
        else if (i == 2)
        {
			printf("Entering checksum.\n");
			checksum(udpsock, &udpAddress, buffer, &address_length, secret_signature, secret_port, the_secret_phrase);
			printf("After checksum: secret phrase: '%s'\n", the_secret_phrase);
		}
        else if (i == 3)
        {
			printf("Entering EXPSTN.\n");
			knocking(udpsock, &udpAddress, buffer, &address_length, secret_signature, secret_port, evil_port_num, the_secret_phrase);
	    	printf("After EXPSTN: secret phrase: '%s'\n", the_secret_phrase);
		}
        // The bonus
        send_bonus_ping(19, "130.208.246.98");
    }
    close(udpsock);
}
