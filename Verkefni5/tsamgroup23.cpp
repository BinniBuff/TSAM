//
// Simple chat server for TSAM-409
//
// Command line: ./chat_server 4000 
//
// Author: Jacky Mallett (jacky@ru.is)
//
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <algorithm>
#include <map>
#include <vector>
#include <list>
#include <cstring>
#include <iostream>
#include <sstream>
#include <thread>
// #include <map>
#include <charconv>
// #include <sstream>
#include <ctime>

// #include <unistd.h>

// fyrir logger
#include <fstream>
#include <ctime>
#include <string>


// fix SOCK_NONBLOCK for OSX
#ifndef SOCK_NONBLOCK
#include <fcntl.h>
#define SOCK_NONBLOCK O_NONBLOCK
#endif

#define BACKLOG  5          // Allowed length of queue of waiting connections

// Simple class for handling connections from clients.
//
// Client(int socket) - socket to send/receive traffic from client.
class Client
{
  public:
    int sock;              // socket of client connection
    std::string name;           // Limit length of name of client's user
    char client_buffer[5000];           // Buffer for clients if stream sends more than one message

    Client(int socket) : sock(socket){
		memset(client_buffer, 0, sizeof(client_buffer)); // breytt úr 5000 yfir í stærð af client_buffer
		name = "";
	} 

    ~Client(){}            // Virtual destructor defined for base class
};

// Simple class for handling connections from servers.
//
// Server(int socket) - socket to send/receive traffic from server.
class Server
{
  public:
    int sock;              // socket of server connection
    std::string name;           // Limit length of name of server's user
    std::string IP;			// IP of server
    std::string port;		// port of server

    Server(int socket) : sock(socket){} 

    ~Server(){}            // Virtual destructor defined for base class
};

// Message class
class Message
{
  public:
    std::string from;           // Name of the sender of message
    std::string body;
    Message(const std::string& sender, const std::string& message_body)
        : from(sender), body(message_body) {}

    ~Message(){}            // Virtual destructor defined for base class
};

// Note: map is not necessarily the most efficient method to use here,
// especially for a server with large numbers of simulataneous connections,
// where performance is also expected to be an issue.
//
// Quite often a simple array can be used as a lookup table, 
// (indexed on socket no.) sacrificing memory for speed.

std::map<int, Client*> clients; // Lookup table for per Client information
std::map<std::string, Server*> servers; // Lookup table for servers information
std::map<int, Client*> instructors; // Lookup table for instructor servers information, makes it easier to throw out instructors when room is needed for new connections
// A global message box, to store messages  for groups
std::map<std::string, std::list<Message>> messageQueues;
// A reference to our IP so we don't connect to it
std::string myIP = "";
std::string myPort = "";
// A cache of last 5 connected IPs
//Server *last_five[5] = {nullptr};
// A cache of last 3 connected instructor IPs
//Server *last_instructors[3] = {nullptr};

fd_set openSockets;             // Current open sockets 
int maxfds;                     // Passed to select() as max fd in set

// Open socket for specified port.
//
// Returns -1 if unable to create the socket for any reason.

// logger
void log_lister(int clientSocket, const std::string& message)
{

    //tíma breytur fyrir name og events 
    std::time_t now = std::time(nullptr);
    std::tm* local = std::localtime(&now);

    // format á tímastimpil fyrir filename og fyrir innihalds *.log
    char date_buffer[32];
    std::strftime(date_buffer, sizeof(date_buffer), "%d-%m-%y", local);
    char time_buffer[32];
    std::strftime(time_buffer, sizeof(time_buffer), "%d-%m-%y_%H:%M:%S", local);

    // file name
    std::string filename = "events_" + std::string(date_buffer) + ".log";

    // output í *.log
    std::ofstream log(filename, std::ios::app); 
    if (clientSocket <= 0)
    {
		log << "[" << time_buffer << "] " << " Not from a server or client connection, probably error connecting: " << message << std::endl;
	}
    else if (log.is_open())
    {
		if (clients[clientSocket]->name != ""){
			log << "[" << time_buffer << "] " << clients[clientSocket]->name << " " << message << std::endl;
		}
		else{
			log << "[" << time_buffer << "] " << " from socket whose name has not been set" << " " << message << std::endl;
		}
    }

}

void removeServerBySocket(int sock) {
    // Remove from servers map
    for (auto it = servers.begin(); it != servers.end(); ) {
        if (it->second->sock == sock) {
            delete it->second; // free the Server object
            it = servers.erase(it);
        } else {
            ++it;
        }
    }

    // Remove from instructors
    for (auto it = instructors.begin(); it != instructors.end(); ) {
        if (it->second->sock == sock) {
            it = instructors.erase(it);
        } else {
            ++it;
        }
    }

    // Remove from last_five
    /*for (int i = 0; i < 5; i++) {
        if (last_five[i] && last_five[i]->sock == sock)
            last_five[i] = nullptr;
    }*/

    // Remove from last_instructors
    /*for (int i = 0; i < 3; i++) {
        if (last_instructors[i] && last_instructors[i]->sock == sock)
            last_instructors[i] = nullptr;
    }*/
}

int open_socket(int portno)
{
   struct sockaddr_in sk_addr;   // address settings for bind()
   int sock;                     // socket opened for this port
   int set = 1;                  // for setsockopt

   // Create socket for connection. Set to be non-blocking, so recv will
   // return immediately if there isn't anything waiting to be read.
#ifdef __APPLE__     
   if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
   {
      perror("Failed to open socket");
      return(-1);
   }
#else
   if((sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0)
   {
     perror("Failed to open socket");
    return(-1);
   }
#endif

   // Turn on SO_REUSEADDR to allow socket to be quickly reused after 
   // program exit.

   if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) < 0)
   {
      perror("Failed to set SO_REUSEADDR:");
   }
   set = 1;
#ifdef __APPLE__     
   if(setsockopt(sock, SOL_SOCKET, SOCK_NONBLOCK, &set, sizeof(set)) < 0)
   {
     perror("Failed to set SOCK_NOBBLOCK");
   }
#endif
   memset(&sk_addr, 0, sizeof(sk_addr));

   sk_addr.sin_family      = AF_INET;
   sk_addr.sin_addr.s_addr = INADDR_ANY;
   sk_addr.sin_port        = htons(portno);

   // Bind to socket to listen for connections from clients

   if(bind(sock, (struct sockaddr *)&sk_addr, sizeof(sk_addr)) < 0)
   {
      // added 
      log_lister(-1, "Binding socket to port failed.");

      perror("Failed to bind to socket:");
      return(-1);
   }
   else
   {
      // added
      log_lister(-1, "Socket bound successfully to port " + std::to_string(portno));
      return(sock);
   }
}

// Close a client's connection, remove it from the client list, and
// tidy up select sockets afterwards.

void closeClient(int clientSocket)
{

     printf("Closed connection: %d\n", clientSocket);
     log_lister(clientSocket, "Client closed connection");

     // If this client's socket is maxfds then the next lowest
     // one has to be determined. Socket fd's can be reused by the Kernel,
     // so there aren't any nice ways to do this.

     close(clientSocket);      

     if(maxfds == clientSocket)
     {
        for(auto const& p : clients)
        {
            maxfds = std::max(maxfds, p.second->sock);
        }
     }

     // And remove from the list of open sockets.

     FD_CLR(clientSocket, &openSockets);

}

void sentHelo(int serverSocket, std::string const& myGroup){

   std::string helo = "HELO," + myGroup;
   uint16_t total_length = 5 + helo.length();
   uint16_t network_length = htons(total_length);

   char packet[total_length];
   packet[0] = 0x01; // SOH
   memcpy(packet + 1, &network_length, 2);
   packet[3] = 0x02; // STX
   memcpy(packet + 4, helo.c_str(), helo.length());
   packet[total_length - 1] = 0x03; // ETX
   
   int nwrite = send(serverSocket, packet, total_length, 0);

   if(nwrite  == -1)
   {
	   perror("send() to server failed: ");
	   log_lister(serverSocket, "Send() HELO failed");
	   return;
   }
   
   log_lister(serverSocket, "Sent HELO: " + helo);

}

void connectServer(const char *IP, const char *port, const char *name)
{
   struct addrinfo hints, *svr;              // Network host entry for server
   struct sockaddr_in serv_addr;           // Socket address for server
   int serverSocket;                         // Socket used for server 
   int nwrite;                               // No. bytes written to server
   int nread;                                  // Bytes read from socket
   char buffer[5000];                        // buffer for writing to server
   char in_buffer[5000];                        // buffer for receiving from server
   int set = 1;                              // Toggle for setsockopt

   hints.ai_family   = AF_INET;            // IPv4 only addresses
   hints.ai_socktype = SOCK_STREAM;
   
   int int_port = atoi(port);
   
   if (int_port < 1 || int_port > 10000){
	   std::cout << "Port not valid" << std::endl;
	   log_lister(0, "Port not valid when connecting to " + std::string(IP) + " " + std::string(port));
	   return;
   }

   memset(&hints,   0, sizeof(hints));
   
   std::cout << "Trying to connect to: " << name << std::endl;

   if(getaddrinfo(IP, port, &hints, &svr) != 0)
   {
       perror("getaddrinfo failed: ");
       std::cout << IP << ":" << port << " - " << name << std::endl;
       log_lister(0, "getaddrinfo failed when connecting to " + std::string(IP) + " " + std::string(port));
       return;
   }
   

   struct hostent *server;
   server = gethostbyname(IP);

   bzero((char *) &serv_addr, sizeof(serv_addr));
   serv_addr.sin_family = AF_INET;
   bcopy((char *)server->h_addr,
      (char *)&serv_addr.sin_addr.s_addr,
      server->h_length);
   serv_addr.sin_port = htons(atoi(port));

   serverSocket = socket(AF_INET, SOCK_STREAM, 0);

   // Turn on SO_REUSEADDR to allow socket to be quickly reused after 
   // program exit.

   if(setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) < 0)
   {
       printf("Failed to set SO_REUSEADDR for port %s\n", port);
       perror("setsockopt failed: ");
       log_lister(0, "setsockopt failed when connecting to " + std::string(IP) + " " + std::string(port));
       return;
   }

   
   if(connect(serverSocket, (struct sockaddr *)&serv_addr, sizeof(serv_addr) )< 0)
   {
       // EINPROGRESS means that the connection is still being setup. Typically this
       // only occurs with non-blocking sockets. (The serverSocket above is explicitly
       // not in non-blocking mode, so this check here is just an example of how to
       // handle this properly.)
       if(errno != EINPROGRESS)
       {
         printf("Failed to open socket to server: %s on port: %s\n", IP, port);
         perror("Connect failed: ");
         log_lister(0, "Connect failed when connecting to " + std::string(IP) + " " + std::string(port));
         return;
       }
   }
   
   // Add new client to the list of open sockets
   FD_SET(serverSocket, &openSockets);

   // And update the maximum file descriptor
   maxfds = std::max(maxfds, serverSocket) ;
   
//    std::string helo = "HELO,A5_23";
//    uint16_t total_length = 5 + helo.length();
//    uint16_t network_length = htons(total_length);

//    char packet[total_length];
//    packet[0] = 0x01; // SOH
//    memcpy(packet + 1, &network_length, 2);
//    packet[3] = 0x02; // STX
//    memcpy(packet + 4, helo.c_str(), helo.length());
//    packet[total_length - 1] = 0x03; // ETX
   
//    nwrite = send(serverSocket, packet, total_length, 0);

//    if(nwrite  == -1)
//    {
// 	   perror("send() to server failed: ");
// 	   log_lister(0, "Send() HELO failed when connecting to " + std::string(IP) + " " + std::string(port));
//    }
   
   std::cout << "Connected to: " << name << " on socket: " << serverSocket << std::endl;
   
   clients[serverSocket] = new Client(serverSocket);
   servers[name] = new Server(serverSocket);
   clients[serverSocket]->name = name;
   servers[name]->name = name;
   servers[name]->IP = IP;
   servers[name]->port = port;
   log_lister(serverSocket, "Server connected after receiving HELO from our server");
   /*if (std::count(std::begin(last_five), std::end(last_five), servers[name]) == 0){
	   auto it = std::find(std::begin(last_five), std::end(last_five), nullptr);
	   if (it == std::end(last_five)){
	      for (int i = 0; i < 4; i++) last_five[i] = last_five[i + 1];
	      last_five[4] = servers[name];
	   }
	   else{
	   	   *it = servers[name];
	   }
   }*/
   if (name[0] == 'I'){
	   instructors[serverSocket] = clients[serverSocket];
	   /*if (std::count(std::begin(last_instructors), std::end(last_instructors), servers[name]) == 0){
		   auto it = std::find(std::begin(last_instructors), std::end(last_instructors), nullptr);
	       if (it == std::end(last_instructors)){
	         for (int i = 0; i < 2; i++) last_instructors[i] = last_instructors[i + 1];
	         last_instructors[2] = servers[name];
	       }
	       else{
		      *it = servers[name];
	       }
	   }*/
   }
   
   sentHelo(serverSocket, "A5_23");
}

void getMsgs(int serverSocket, const char* group_id){
	// Create a get msg
	std::string get_message = "GETMSGS,";
	std::string group = std::string(group_id);
	get_message += group;
	
	// Send packet to the server.
	uint16_t total_length = 5 + get_message.length();   // Calculate the lenght
	uint16_t network_length = htons(total_length);  // In network byte order

	// Assemlbing packet in (<SOH><length><STX><command><ETX>) format
	char packet[total_length];
	packet[0] = 0x01; // SOH
	memcpy(packet + 1, &network_length, 2);
	packet[3] = 0x02; // STX
	memcpy(packet + 4, get_message.c_str(), get_message.length());
	packet[total_length - 1] = 0x03; // ETX

	// Send packet
	send(serverSocket, packet, total_length, 0);
	
	log_lister(serverSocket, "Received GETMSGS from our server");
	std::cout << "We sent " << get_message << std::endl;
	// Receive from server
	// How many times to receive? When are we calling GETMSGS? maybe only after we call statusreq? so is then we know how many times to receive
	// recvMsg(serverSocket, group_id); ------------ SLEPPA? ---------------------
}

// SENDMSG is used from many other functions
void sendMsg(int serverSocket, const char *to_name){
	// Get group ID for servers map
	std::string serverGroupID = std::string(to_name);
	// Should sendMsg send all messages intended for group? or only one per call to it?
	while(!messageQueues[serverGroupID].empty()){
		
		// Create a send msg
		std::string message_to_send = "SENDMSG,";
		
		// TO_GROUP_ID
		message_to_send += serverGroupID + ",";
		
		// FROM_GROUP_ID and Message content
		Message message = messageQueues[serverGroupID].front();
		std::string from_group = message.from;
		std::string body = message.body;
		message_to_send += from_group + ",";
		message_to_send += body;
		
		// Send packet to the server.
		uint16_t total_length = 5 + message_to_send.length();   // Calculate the lenght
		uint16_t network_length = htons(total_length);  // In network byte order

		// Assemlbing packet in (<SOH><length><STX><command><ETX>) format
		char packet[total_length];
		packet[0] = 0x01; // SOH
		memcpy(packet + 1, &network_length, 2);
		packet[3] = 0x02; // STX
		memcpy(packet + 4, message_to_send.c_str(), message_to_send.length());
		packet[total_length - 1] = 0x03; // ETX

		// Send packet
		send(serverSocket, packet, total_length, 0);

		// Remove the message from the queue since it's been delivered
		messageQueues[serverGroupID].pop_front();
		log_lister(serverSocket, "Received SENDMSG from our server");
		std::cout << "We sent " << message_to_send << std::endl;
	}
}

void recvMsg(int serverSocket, const char *buffer){
	std::string line = std::string(buffer);
	// Find the position of the first, second and third commas
	size_t first_comma = line.find(',');
	size_t second_comma = line.find(',', first_comma + 1);
	size_t third_comma = line.find(',', second_comma + 1);

	// Ensure both commas were found
	if (third_comma != std::string::npos) 
	{
		// Get all the necessary data from the buffer
		std::string toGroupID = line.substr(first_comma + 1, second_comma - (first_comma + 1));
		std::string fromGroupID = line.substr(second_comma + 1, third_comma - (second_comma + 1));
		std::string messageBody = line.substr(third_comma +1);
		
		// Create the message
		Message newMessage(fromGroupID, messageBody);
		messageQueues[toGroupID].push_back(newMessage);
		
		// Viljum við senda beint ef message'ið er til einhvers sem við erum tengdir?
		if (servers.count(toGroupID)) sendMsg(servers[toGroupID]->sock, toGroupID.c_str());
	}
	log_lister(serverSocket, "sent " + line);
}

void outGoingStatusReq()
{
    // The command string
    std::string command_str = "STATUSREQ";

    // Assemble the framed packet just once, since it's the same for all peers.
    uint16_t total_length = 5 + command_str.length();
    uint16_t network_length = htons(total_length);

    char packet[total_length];
    packet[0] = 0x01; // SOH
    memcpy(packet + 1, &network_length, 2);
    packet[3] = 0x02; // STX
    memcpy(packet + 4, command_str.c_str(), command_str.length());
    packet[total_length - 1] = 0x03; // ETX
    
    // Loop through all connected peer servers and send them the packet.
    for (auto const& pair : servers)
    {
        Server* server = pair.second;
        
        // Send the request.
        send(server->sock, packet, total_length, 0);
        // Logit
        log_lister(server->sock, "Sent STATUSREQ to " + server->name);
        std::cout << "Sending STATUSREQ to: " << server->name << std::endl;
    }
}

// Process command from server to the server
// Make sure to read all commands from the buffer if there are more than one
void serverCommand(int serverSocket, 
                  const char *buffer, size_t message_len, std::list<Client *> *disconnectedClients) 
{
	//check if buffer has more than 5 bytes
	if (message_len < 5){
	  log_lister(serverSocket, "Did not send enough bytes");
	  return;
	}
	
	// Split buffer up by messages
	std::string stream(buffer, message_len);
	size_t start = stream.find('\x01');
    if (start == std::string::npos) {
		log_lister(serverSocket, "No SOH found");
		return;
	}
	std::string all_messages = stream.substr(start);
	std::string tmp;
	std::vector<std::string> messages;

	std::stringstream ss(all_messages);

	while (std::getline(ss, tmp, '\x01')){ //DEBUG: val 3 þarf að vera char eða strengur, breytti úr hex 0x001 í 'x01' því getline tekur(strem, string, delim char)
	   messages.push_back(tmp);
	}
	
	// Use for-loop to iterate through all messages
	for (int i = 1; i < messages.size(); i++){
		u_int16_t len = (u_int8_t)messages[i][0] << 8 | (u_int8_t)messages[i][1];
		if (messages[i][2] != '\x02'){
		  log_lister(serverSocket, "Did not send <STX>");
		  std::cout << "Missing STX" << std::endl;
		  continue;
		}

		if (len > 5000 || len < 5){
		  log_lister(serverSocket, "sent too long or too short message");
		  continue;
		}
		
		// If we did not receive the whole message, we need to store it and use it when we get the whole message
		if ((len - 1) > messages[i].size()){
            // here is performed a partial copy of the message that goes through the buffer
            // char* strncpy(char* destination, const char* source, size_t num)
            strncpy(clients[serverSocket]->client_buffer, messages[i].c_str(), sizeof(clients[serverSocket]->client_buffer) - 1);

            // ensures the null terminator is set; so what is copied is 4999 bytes with space for the null terminator so overflow does not occur
			clients[serverSocket]->client_buffer[sizeof(clients[serverSocket]->client_buffer) - 1] = '\0';  
			log_lister(serverSocket, "sent a message that has been split and the first part is in the buffer");
            return;
		}
		
		
		if (messages[i][len - 2] != '\x03' && messages[i][messages[i].size() - 1] != '\x03'){
		  log_lister(serverSocket, "Did not send <ETX>");
		  continue;
		}
		
		// Find the part that is just the command
		size_t etx = messages[i].find('\x03', 3);
		if (etx == std::string::npos || etx <= 3 || etx > messages[i].size()) {
			// malformed / no ETX — skip or resync
			continue;
		}
		size_t payload_len = (etx > 3) ? (etx - 3) : 0;
		std::string command = messages[i].substr(3, payload_len);
		std::cout << "Command: " << command << std::endl;
		
		// Commands
		if (command.rfind("HELO", 0) == 0){
			bool already_in = false;
			for (const auto& pair : servers){
				if (pair.second->sock == serverSocket) already_in = true;
			}
			if (!already_in){
				size_t comma = command.find(',');
				std::string server_name = command.substr(comma + 1);	// Everything after the comma should be the server name
				// only connect if there is room or instructor servers to kick out
				if (servers.size() >= 7){
					if (instructors.size() < 1){
						disconnectedClients->push_back(clients[serverSocket]);
						closeClient(serverSocket);
						removeServerBySocket(serverSocket);
						return;
					}
					// kick out instructor server
					Client *instructor = instructors.begin()->second;
					disconnectedClients->push_back(instructor);
					closeClient(instructor->sock);
					removeServerBySocket(instructor->sock);
				}
				clients[serverSocket]->name = server_name;
				sentHelo(serverSocket, "A5_23");
			}
			
			log_lister(serverSocket, "sent " + command);
			
			// Send back SERVERS
			std::string response = "SERVERS,";
			response += "A5_23," + myIP + "," + myPort + ";";
			for (auto const& pair : servers){
				Server *tmp = pair.second;
				response += tmp->name + ",";
				response += tmp->IP + ",";
				response += tmp->port;
				response += ";";
			}
			
            uint16_t total_length = 5 + response.length();   // Calculate the lenght
			uint16_t network_length = htons(total_length);  // In network byte order
			
			log_lister(serverSocket, "received from our server: " + response);

			// Assemlbing packet in (<SOH><length><STX><command><ETX>) format
			char packet[total_length];
			packet[0] = 0x01; // SOH
			memcpy(packet + 1, &network_length, 2);
			packet[3] = 0x02; // STX
			memcpy(packet + 4, response.c_str(), response.length());
			packet[total_length - 1] = 0x03; // ETX

			// Send packet
			send(serverSocket, packet, total_length, 0);
			std::cout << "We sent " << response << std::endl;
		}
		
		else if (command.rfind("GETMSGS", 0) == 0){
			// Get the group ID of the server for whom the message is
			size_t comma = command.find(',');
			std::string server_name = command.substr(comma + 1);
			
			log_lister(serverSocket, "sent " + command);
            // Check if group has any mail in their message box
            if (!server_name.empty() && messageQueues.count(server_name) && !messageQueues[server_name].empty())
            {
                sendMsg(serverSocket, server_name.c_str());
            }
		}
		
		else if (command.rfind("KEEPALIVE", 0) == 0){
			size_t comma = command.find(',');
			int nr_of_messages = atoi(command.substr(comma + 1).c_str());
            std::string groupId = "A5_23"; 
            
            log_lister(serverSocket, "sent " + command);
            
            if (nr_of_messages < 1) return;
            // Get the messages the server has for us
			getMsgs(serverSocket, groupId.c_str());
		}
		
		else if (command.rfind("STATUSREQ", 0) == 0){
			std::cout << "Received STATUSREQ from a peer." << std::endl;
            log_lister(serverSocket, "Received STATUSREQ from a peer.");

			// Start building the response string.
            std::string response_body = "STATUSRESP,";

            // Iterate through messageQueues map to find all the groups we are holding messages for.
            for (auto const& pair : messageQueues)
            {
                std::string group_id = pair.first;
                size_t msg_count = pair.second.size();

                // Only add an entry if there are actually messages for that group.
                if (msg_count > 0)
                {
                    response_body += group_id + "," + std::to_string(msg_count) + ",";
                }
            }
            // Remove the final trailing comma
            if (response_body.back() == ',')
            {
                response_body.pop_back();
            }
            
            // Frame and send the response packet back to the requesting server.
            uint16_t total_length = 5 + response_body.length();
            uint16_t network_length = htons(total_length);

            char packet[total_length];
            packet[0] = 0x01; // SOH
            memcpy(packet + 1, &network_length, 2);
            packet[3] = 0x02; // STX
            memcpy(packet + 4, response_body.c_str(), response_body.length());
            packet[total_length - 1] = 0x03; // ETX

            send(serverSocket, packet, total_length, 0);
            log_lister(serverSocket, "Sent STATUSRESP: " + response_body);
            std::cout << "Sent STATUSRESP: " << response_body << std::endl;
		}
		
		else if (command.rfind("SENDMSG", 0) == 0){
			recvMsg(serverSocket, command.c_str());
		}
		
		else if (command.rfind("SERVERS", 0) == 0){
			// parse the message, see if it is SERVERS,GROUP_NAME,IP,PORT
			
		   size_t comma = command.find(',');
		   std::string in_servers = command.substr(comma + 1);
		   std::cout << "before while loop in servers, incoming servers: " << in_servers << std::endl;
		   std::string tmp;
		   std::vector<std::string> parts;
		   
		   std::stringstream ss(in_servers);
		   while (std::getline(ss, tmp, ';')){
			   std::cout << "Inside while loop, tmp: " << tmp << std::endl;
			   parts.push_back(tmp);
		   }
		   
		   // Add name
		   std::string server_name;
		   std::string server_ip;
		   std::string server_port;
		   std::stringstream this_server(parts[0]);
		   std::vector<std::string> this_server_split;
		   while (std::getline(this_server, tmp, ',')){
			   std::cout << "Inside while loop for this server, tmp: " << tmp << std::endl;
			   this_server_split.push_back(tmp);
		   }
		   
		   std::cout << "This server name: " << this_server_split[0] << ", this server IP: " << this_server_split[1] << ", this server port:" << this_server_split[2] << std::endl;
		   
		   server_name = this_server_split[0];
		   if ((this_server_split.size() == 3) && (servers.count(server_name) == 0)) {
			    server_ip = this_server_split[1];
			    server_port = this_server_split[2];
			    servers[server_name] = new Server(serverSocket);
				servers[server_name]->name = server_name;
				servers[server_name]->IP = server_ip;
				servers[server_name]->port = server_port;
				clients[serverSocket]->name = server_name;
				
				/*if (std::count(std::begin(last_five), std::end(last_five), servers[server_name]) == 0){
					auto it = std::find(std::begin(last_five), std::end(last_five), nullptr);
					if (it == std::end(last_five)){
					   for (int i = 0; i < 4; i++) last_five[i] = last_five[i + 1];
					   last_five[4] = servers[server_name];
					}
					else{
						*it = servers[server_name];
					}
				}*/
				
				// Add server to instructor list if it is an instructor server
				if (server_name[0] == 'I'){
					instructors[serverSocket] = clients[serverSocket];
					/*if (std::count(std::begin(last_instructors), std::end(last_instructors), servers[server_name]) == 0){
						auto it = std::find(std::begin(last_instructors), std::end(last_instructors), nullptr);
						if (it == std::end(last_instructors)){
						   for (int i = 0; i < 2; i++) last_instructors[i] = last_instructors[i + 1];
						   last_instructors[2] = servers[server_name];
						}
						else{
							*it = servers[server_name];
						}
					}*/
				}
		   }
		
		   // Do a DFS for other servers through this one
		   for (int i = 1; i < parts.size(); i ++){
			   if (servers.size() >= 7){
				   return;
			   }
			   
			   std::stringstream nested_ss(parts[i]);
			   std::vector<std::string> nested_parts;
			   while (std::getline(nested_ss, tmp, ',')){
				   std::cout << "Inside nested while loop, tmp: " << tmp << std::endl;
				   nested_parts.push_back(tmp);
			   }
			   if (nested_parts.size() < 3) {
				   std::cout << "Skipping malformed server entry: " << parts[i] << std::endl;
			   	   continue;
			   }
			   std::string new_name = nested_parts[0];
			   std::string new_IP = nested_parts[1];
			   std::string new_port = nested_parts[2];
			   if (new_IP == myIP && new_port == myPort) continue;
			   if (servers.count(new_name) == 0) connectServer(new_IP.c_str(), new_port.c_str(), new_name.c_str());
			   std::cout << "end of connect for loop" << std::endl;
			   /*std::cout << "Connected servers: " << std::endl;
				for (auto const& srvrs : servers)
				{
					std::cout << " - " << srvrs.second->sock << ":" << srvrs.second->name << " - " << srvrs.second->IP << ":" << srvrs.second->port << std::endl;
				}*/
		   }
		   std::cout << "after connect for loop" << std::endl;
		}

        else if (command.rfind("STATUSRESP,", 0) == 0)
		{
            log_lister(serverSocket, "Received STATUSRESP: " + command);

            // Parse the response. Get the data part after sending "STATUSRESP,"
            // Expected data example: "A5_4,20,A5_71,2"
            std::string data = command.substr(11); 
            std::stringstream ss(data);
            std::string part;
            std::vector<std::string> parts;
            while(std::getline(ss, part, ','))
            {
                parts.push_back(part);
            }

            // Loop through the pairs of (group_id, msg_count) and take action.
            // The vector will look like: ["A5_4", "20", "A5_71", "2"]
            for(size_t i = 0; i < parts.size(); i += 2)
            {
                // Ensure we do not read past the end of the vector
                if (i + 1 >= parts.size()) continue;

                std::string group_id = parts[i];
                if (group_id == clients[serverSocket]->name) continue;
                int msg_count = 0;
                try {
                    msg_count = std::stoi(parts[i+1]);
                } catch(const std::exception& e) {
                    log_lister(serverSocket, "Invalid message count in STATUSRESP for group " + group_id);
                    continue; // Skip to the next pair
                }
                
                // Decide whether to retrieve the messages.
                std::string our_group_id = "A5_23"; // Our group ID
                
                // Check if the messages are for us OR for a peer we are directly connected to.
                if(group_id == our_group_id || servers.count(group_id))
                {
                    log_lister(serverSocket, "Peer has " + std::to_string(msg_count) + " messages for " + group_id + ". Retrieving them.");
                    
                    // Request each message by calling getMsg function.
                    for(int j = 0; j < msg_count; j++)
                    {
                        getMsgs(serverSocket, group_id.c_str());
                    }
                }
            }
        }
	}
}

// Process command from client on the server

void clientCommand(int clientSocket,  
                  char *buffer, size_t message_len, std::list<Client *> *disconnectedClients) 
{
	// Make sure there is nothing left from this socket from before
  if (clients[clientSocket]->client_buffer[0] != 0){
	  // see if there are leftover messages in the buffer. if so we need to finish those before addressing new ones
	  std::string line(clients[clientSocket]->client_buffer);
	  // empty the client_buffer by creating a new one
	  memset(clients[clientSocket]->client_buffer, 0, sizeof(clients[clientSocket]->client_buffer));
	  
	  log_lister(clientSocket, "sent a message that got split and we have gotten the first part from the client and added to the second part just received");
	  
	  line += std::string(buffer);
	  serverCommand(clientSocket, line.c_str(), message_len, disconnectedClients);
	  return;
  }
  
  // If the first byte is SOH then the client is a server
  if (buffer[0] == '\x01' || clients[clientSocket]->name[0] == 'A' || clients[clientSocket]->name[0] == 'I'){
	  log_lister(clientSocket, "first byte is correct <SOH>, got into servermessage");
	  serverCommand(clientSocket, buffer, message_len, disconnectedClients);
	  return;
  }
  std::string line(buffer);
  
    size_t end = line.find_last_not_of(" \n\r\t");

    if (end != std::string::npos)
    {
        line = line.substr(0, end + 1);
    }

    // Commands (PLEASE use this method if white-space is a factor like in "SENDMSG,GROUP ID,<message contents>")
    if (line.rfind("SENDMSG,", 0) == 0) 
    {
        // Find the position of the first and second commas
        size_t first_comma = line.find(',');
        size_t second_comma = line.find(',', first_comma + 1);

        // Ensure both commas were found
        if (second_comma != std::string::npos) 
        {
            // Get sender group id (assumes the NAME command used groups id)
            std::string senderGroupID = clients[clientSocket]->name;

            // Extract the group id, between the first and second comma
            std::string resieverGroupID = line.substr(first_comma + 1, second_comma - (first_comma + 1));

            // Extract the message, everything after the second comma
            std::string msg_body = line.substr(second_comma + 1);

            // Create a new Message object
            Message newMessage(senderGroupID, msg_body);

            // Add the message to the recievers message queue
            messageQueues[resieverGroupID].push_back(newMessage);

            // Log the event
            log_lister(clientSocket, "Queued message from " + senderGroupID + " to " + resieverGroupID);

            // Send an acknowledgment back
            std::string ack = "Message for " + resieverGroupID + " has been queued.\n";
            send(clientSocket, ack.c_str(), ack.length(), 0);
            
            std::cout << "We sent " << ack << std::endl;
            
            // TODO: 
            // If we are connected to the server we are sending to, send to them, else send to random
        }
    }
        // Check for GETMSG command
        else if (line == "GETMSG") 
        {

            // Get the group ID of the client asking for a message
            // (Assumes the client has used "CONNECT <groupID>" beforehand)
            std::string clientGroupID = clients[clientSocket]->name;
            // Check if group has any mail in their message box
            if (!clientGroupID.empty() && messageQueues.count(clientGroupID) && !messageQueues[clientGroupID].empty())
            {
				// Missing headers
				
                // Get the oldest message from the front of the queue
                Message oldestMessage = messageQueues["A5_23"].front();

                // Format message
                std::string formatted_message = "FROM " + oldestMessage.from + ": " + oldestMessage.body + "\n";
                
                // Send it to the client.
                send(clientSocket, formatted_message.c_str(), formatted_message.length(), 0);

                // Remove the message from the queue since it's been delivered
                messageQueues["A5_23"].pop_front();

                // Log event
                log_lister(clientSocket, "Delivered message from " + oldestMessage.from);
                std::cout << "We sent " << formatted_message << std::endl;
            }
            else
            {
                // If there are no messages, tell the client
                const char* no_msg = "No new messages.\n";
                send(clientSocket, no_msg, strlen(no_msg), 0);
                std::cout << "We sent " << no_msg << std::endl;
            }
        }
        // Check for LISTSERVERS command
        // TODO: Update to list other servers, not clients
        // The server is not connected  to other servers as is
        else if (line == "LISTSERVERS") 
        {
            std::cout << "Command: LISTSERVERS" << std::endl;

            std::string client_list_msg = "Connected clients:\n";
            if (clients.empty())
            {
                client_list_msg = "No clients connected.\n";
            }
            else
            {
                for (auto const& pair : clients)
                {
                    Client* client = pair.second;
                    // Assuming client->name stores the group id from a "CONNECT" command
                    // Might want to remove the socket part, but it will stay for now
                    client_list_msg += "  - Group: " + client->name + " (Socket: " + std::to_string(client->sock) + ")\n";
                }
            }
            send(clientSocket, client_list_msg.c_str(), client_list_msg.length(), 0);
        }
        // Set myIP so we don't connect to our machine
        // MY_IP,<IP number>,<Socket number>
        else if (line.rfind("MY_IP", 0) == 0)
        {
            size_t first_comma = line.find(',');
            size_t second_comma = line.find(',', first_comma + 1);
            std::string IP = line.substr(first_comma + 1, second_comma - (first_comma + 1));
            std::string port = line.substr(second_comma + 1);
            myIP = IP;
            myPort = port;
        }
        // Connect to server using IP, port and name
   	   else if(line.rfind("CONNECT", 0) == 0)
	   {
		  size_t first_comma = line.find(',');
 		  size_t second_comma = line.find(',', first_comma + 1);
 		  size_t third_comma = line.find(',', second_comma + 1);
		  std::string IP = line.substr(first_comma + 1, second_comma - (first_comma + 1));
		  std::string port = line.substr(second_comma + 1, third_comma - (second_comma + 1));
		  std::string name = line.substr(third_comma + 1);
		  connectServer(IP.c_str(), port.c_str(), name.c_str());
	   }
	   else if(line == "LEAVE")
	   {
		   // Close the socket, and leave the socket handling
		   // code to deal with tidying up clients etc. when
		   // select() detects the OS has torn down the connection.
	 
		   closeClient(clientSocket);
	   }
	   else if(line.rfind("NAME", 0) == 0)
	   {
		   size_t comma = line.find(',');
		   std::string name = line.substr(comma + 1);
		   clients[clientSocket]->name = name;
	   }
       else 
       {
  
           std::cout << "Unknown command from client:" << buffer << std::endl;
           log_lister(clientSocket, "Unknown command from client: " + std::string(buffer));
     
       }
}

// Sends other servers we are connected to the number of msg in their inbox
void keepAlive()
{
    for (auto const& pair : servers)
    {
        std::string serverName = pair.first;    // Server name
        Server* server = pair.second;  // The value is the pointer to the Server object

        // The number of messages for the server
        int message_count = 0;
        if (messageQueues.count(serverName)) {
            message_count = messageQueues[serverName].size();
        }

        std::string command_str = "KEEPALIVE," + std::to_string(message_count);

        uint16_t total_length = 5 + command_str.length();   // Calculate the lenght
        uint16_t network_length = htons(total_length);  // In network byte order

        // Assemlbing packet in (<SOH><length><STX><command><ETX>) format
        char packet[total_length];
        packet[0] = 0x01; // SOH
        memcpy(packet + 1, &network_length, 2);
        packet[3] = 0x02; // STX
        memcpy(packet + 4, command_str.c_str(), command_str.length());
        packet[total_length - 1] = 0x03; // ETX

        // Send packet
        send(server->sock, packet, total_length, 0);

        std::cout << "Sending KEEPALIVE to " << server->name << " on socket " << server->sock << std::endl;
}
}

int main(int argc, char* argv[])
{
    bool finished;
    int listenSock;                 // Socket for connections to server
    int clientSock;                 // Socket of connecting client
    fd_set readSockets;             // Socket list for select()        
    fd_set exceptSockets;           // Exception socket list
    struct sockaddr_in client;
    socklen_t clientLen;
    char buffer[5000];              // buffer for reading from clients
    time_t lastKeepAliveTime = 0;   // Timer to make sure keepAlive does not run more than once a minute

    if(argc != 2)
    {
        printf("Usage: chat_server <ip port>\n");
        exit(0);
    }

    // Setup socket for server to listen to

    listenSock = open_socket(atoi(argv[1])); 
    printf("Listening on port: %d\n", atoi(argv[1]));
    log_lister(0, "Server started listening on port " + std::to_string(atoi(argv[1])));

    if(listen(listenSock, BACKLOG) < 0)
    {
        printf("Listen failed on port %s\n", argv[1]);
        exit(0);
    }
    else 
    // Add listen socket to socket set we are monitoring
    {
        FD_ZERO(&openSockets);
        FD_SET(listenSock, &openSockets);
        maxfds = listenSock;
    }

    finished = false;

    while(!finished)
    {
        // Get modifiable copy of readSockets
        readSockets = exceptSockets = openSockets;
        memset(buffer, 0, sizeof(buffer));

        // A timeout for select() so it does not wait forever for network activity
        struct timeval tv;
        tv.tv_sec = 5;  // Wait 5 seconds
        tv.tv_usec = 0;

        // Look at sockets and see which ones have something to be read()
        int n = select(maxfds + 1, &readSockets, NULL, &exceptSockets, &tv);

        // Check if it is time to run keepAlive
        time_t currentTime = time(NULL);
        if(currentTime - lastKeepAliveTime >= 60)
        {
            keepAlive();
            outGoingStatusReq();
            lastKeepAliveTime = currentTime;
        }
        
        /*std::cout << "Connected servers: " << std::endl;
        for (auto const& srvrs : servers)
        {
			std::cout << " - " << srvrs.second->sock << ":" << srvrs.second->name << std::endl;
		}*/

        if(n < 0)
        {
            perror("select failed - closing down\n");
            finished = true;
        }
        else
        {
            // First, accept  any new connections to the server on the listening socket
            if(FD_ISSET(listenSock, &readSockets))
            {
				clientLen = sizeof(client);
               clientSock = accept(listenSock, (struct sockaddr *)&client,
                                   &clientLen);
				if (servers.size() >= 7 && instructors.size() < 1)
				{
					close(clientSock);
					n--;
					std::cout << "Denied socket as we are full" << std::endl;
					log_lister(0, "Denied socket as we are full");
				}
				else
				{
				   printf("accept***\n");
				   // Add new client to the list of open sockets
				   FD_SET(clientSock, &openSockets);

				   // And update the maximum file descriptor
				   maxfds = std::max(maxfds, clientSock) ;

				   // create a new client to store information.
				   clients[clientSock] = new Client(clientSock);

				   // Decrement the number of sockets waiting to be dealt with
				   n--;

				   printf("Client connected on server: %d\n", clientSock);
				   log_lister(clientSock, "Client connected to server");
			   }
            }
            // Now check for commands from clients
            std::list<Client *> disconnectedClients;
            if(n > 0)
            {
               for(auto const& pair : clients)
               {
                  Client *client = pair.second;

                  if(FD_ISSET(client->sock, &readSockets))
                  {
                      // recv() == 0 means client has closed connection
                      ssize_t message_len = recv(client->sock, buffer, sizeof(buffer), MSG_DONTWAIT);
                      if( message_len == 0)
                      {
						  printf("Client closed connection: %d\n", client->sock);
                            log_lister(client->sock, "client disconnected.");
                            disconnectedClients.push_back(client);
                            closeClient(client->sock);
                            removeServerBySocket(client->sock);

                      }
                      // We don't check for -1 (nothing received) because select()
                      // only triggers if there is something on the socket for us.
                      else
                      {
                          clientCommand(client->sock, buffer, (size_t)message_len, &disconnectedClients);
                          log_lister(client->sock, "Recived data: " + std::string(buffer));
                      }
                  }
               }
                // Remove client from the clients list  // TODO: Delete?, DONE
                for(auto const& c : disconnectedClients)
                {
                    delete clients[c->sock];
                    clients.erase(c->sock);
                }
                if (servers.size() > 1 && servers.size() < 3){

                    for (auto const& pair : servers){

                        Server* s = pair.second;

                        sentHelo(s->sock, "A5_23");

                        std::cout << " -> Sent HELO to server " << s->name << " at " << s->IP << ": " << s->port << std::endl;

                        log_lister(s->sock, "Sent HELO to " + s->name + " - " + s->IP + ":" + s->port);
				    }
                }
            }
        }
    }
}
