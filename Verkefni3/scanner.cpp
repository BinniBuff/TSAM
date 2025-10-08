#include <stdio.h>
#include <iostream>
#include <cstdio>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

using namespace std;

int main(int argc, char *argv[])
{
	if (argc != 4)			// Arguments need to be 4 including the program
	{
		cout << "The number of arguments needs to be 4! ./scanner <IP address> <low port> <high port>" << endl;
		exit(0);
	}
	
	int udpsock;
	
	if ((udpsock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)	// open the socket
    {
        perror("Failed to open socket");
        exit(0);
    }
	
	// Get IP address and ports
	char *ipAddress = argv[1];
    int port1 = atoi(argv[2]);
    int port2 = atoi(argv[3]);
    
	struct timeval timeout;
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	
	if (setsockopt(udpsock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
	{
		perror("timeout failed");
		close(udpsock);
		exit(0);
	}
    
    // try to reach all ports in the given range
    for (int i = port1; i <= port2; i++)
    {
		// set up socket port number
		struct sockaddr_in udpAddress;
		udpAddress.sin_family = AF_INET;
		udpAddress.sin_port = htons(i);

		// set IP address in socket
		if(inet_pton(AF_INET, ipAddress, &udpAddress.sin_addr) != 1)
		{
			cout << "Failed to set socket address" << endl;
			close(udpsock);
			exit(0);
		}
		
		const char *message = "hello UDP";			
		socklen_t address_length = sizeof(udpAddress);
		
		// try to connect to the socket
		if(sendto(udpsock, message, strlen(message), 0, (struct sockaddr *)&udpAddress, address_length) < 0)
		{
			perror("Could not connect");
			close(udpsock);
			exit(0);
		}
		
		char buffer[4096];
		
		if (recvfrom(udpsock, buffer, 4096, 0, (struct sockaddr *)&
		udpAddress, &address_length) >= 0)
		{
			printf("%d\n", ntohs(udpAddress.sin_port));
		}
	}
	close(udpsock);
}
