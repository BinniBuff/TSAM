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
    if (log.is_open())
    {
        log << "[" << time_buffer << "]" << socket  << message << std::endl;
    }

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

void closeClient(int clientSocket, fd_set *openSockets, int *maxfds)
{

     printf("Client closed connection: %d\n", clientSocket);

     // If this client's socket is maxfds then the next lowest
     // one has to be determined. Socket fd's can be reused by the Kernel,
     // so there aren't any nice ways to do this.

     close(clientSocket);      

     if(*maxfds == clientSocket)
     {
        for(auto const& p : clients)
        {
            *maxfds = std::max(*maxfds, p.second->sock);
        }
     }

     // And remove from the list of open sockets.

     FD_CLR(clientSocket, openSockets);

}

void connectServer(const char *IP, const char *port, const char *name)
{
   struct addrinfo hints, *svr;              // Network host entry for server
   struct sockaddr_in serv_addr;           // Socket address for server
   int serverSocket;                         // Socket used for server 
   int nwrite;                               // No. bytes written to server
   int nread;                                  // Bytes read from socket
   char buffer[1025];                        // buffer for writing to server
   char in_buffer[5000];                        // buffer for receiving from server
   int set = 1;                              // Toggle for setsockopt

   hints.ai_family   = AF_INET;            // IPv4 only addresses
   hints.ai_socktype = SOCK_STREAM;

   memset(&hints,   0, sizeof(hints));

   if(getaddrinfo(IP, port, &hints, &svr) != 0)
   {
       perror("getaddrinfo failed: ");
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
   }

   
   if(connect(serverSocket, (struct sockaddr *)&serv_addr, sizeof(serv_addr) )< 0)
   {
       // EINPROGRESS means that the connection is still being setup. Typically this
       // only occurs with non-blocking sockets. (The serverSocket above is explicitly
       // not in non-blocking mode, so this check here is just an example of how to
       // handle this properly.)
       if(errno != EINPROGRESS)
       {
         printf("Failed to open socket to server: %s\n", IP);
         perror("Connect failed: ");
         return;
       }
   }
   
   memset(buffer, 0, sizeof(buffer));
   strcpy(buffer, "HELO,FROM_GROUP_23"); // líka hægt að ger char* fyrir message og assign'a það í send message.c_str() og message.size() 
   nwrite = send(serverSocket, buffer, strlen(buffer),0);

   if(nwrite  == -1)
   {
	   perror("send() to server failed: ");
   }
   
   memset(in_buffer, 0, sizeof(in_buffer));
   nread = read(serverSocket, in_buffer, sizeof(in_buffer));
   
   if(nread < 0)
   {
	   perror("read() from server failed: ");
   }
   // parse the message, see if it is SERVERS,GROUP_NAME,IP,PORT
   std::string message = (std::string)(in_buffer + 4);
   std::string tmp;
   std::vector<std::string> parts;
   
   std::stringstream ss(message);
   
   while (std::getline(ss, tmp, ',')){
	   parts.push_back(tmp);
   }
   
   if (parts[0] != "SERVERS"){
	   return;
   }
   
   clients[serverSocket] = new Client(serverSocket);
   servers[name] = new Server(serverSocket);
   clients[serverSocket]->name = name;
   servers[name]->name = name;
   servers[IP]->name = IP;
   servers[port]->name = port;
   
   // Do a DFS for other servers through this one
   for (int i = 1; i < parts.size(); i += 3){
	   if (servers.size() >= 7){
		   return;
	   }
	   std::string new_name = parts[i];
	   std::string new_IP = parts[i+1];
	   std::string new_port = parts[i+2];
	   if (!servers[new_name]) connectServer(new_IP.c_str(), new_port.c_str(), new_name.c_str());
   }
}

void recMsg(int serverSocket, const char *group_id){
	char buffer[5000];
	memset(buffer, 0, 5000);
	// get message from socket and add to queue
	// recv() == 0 means client has closed connection
	size_t rec_bytes = recv(serverSocket, buffer, sizeof(buffer), MSG_DONTWAIT);
	if(rec_bytes == 0)
	{
		return;
	}
	// We check for -1 (nothing received)
	else if (rec_bytes < 0){

        std::string name_ = std::string(group_id) + " from: " + clients[serverSocket]->name; 
		log_lister(serverSocket, "No message for: " + name_);
	
    }
	// Create message from what we received
	else
	{
		
	}
}

void getMsg(int serverSocket, const char* group_id){
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
	
	// Receive from server
	recMsg(serverSocket, group_id);
}

// SENDMSG is used from many other functions
void sendMsg(int serverSocket, const char *to_name){
	// Create a send msg
	std::string message_to_send = "SENDMSG,";
	
	// TO_GROUP_ID
	std::string serverGroupID = std::string(to_name);
	message_to_send += serverGroupID + ",";
	
	// FROM_GROUP_ID and Message content
	Message *message = messageQueues[serverGroupID].front();
	std::string from_group = message->from;
	std::string body = message->body;
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
}

// Process command from server to the server
// Make sure to read all commands from the buffer if there are more than one
void serverCommand(int serverSocket, fd_set *openSockets, int *maxfds, 
                  const char *buffer, std::list<Client *> *disconnectedClients) 
{
	//check if buffer has more than 5 bytes
	if (sizeof(buffer) < 5){
	  std::cout << "Not enough bytes received" << std::endl;
	  return;
	}
	
	// Split buffer up by messages
	std::string stream = (std::string)(buffer);
	size_t start = stream.find(0x001);
	std::string all_messages = (std::string)(buffer + start);
	std::string tmp;
	std::vector<std::string> messages;

	std::stringstream ss(all_messages);

	while (std::getline(ss, tmp, '\x01')){ //DEBUG: val 3 þarf að vera char eða strengur, breytti úr hex 0x001 í 'x01' því getline tekur(strem, string, delim char)
	   messages.push_back(tmp);
	}
	
	// Use for-loop to iterate through all messages
	for (int i = 0; i < messages.size(); i++){
		u_int16_t len = (u_int8_t)messages[i][1] << 8;   // þarf að vera buffer[1 og 2]
		len += (u_int8_t)messages[i][0];
		len = ntohs(len);
		if (messages[i][2] != 0x002){
		  std::cout << "Missing <STX>" << std::endl;
		  continue;
		}

		if (len > 5000){
		  std::cout << "Message too long" << std::endl;
		  continue;
		}
		
		// If we did not receive the whole message, we need to store it and use it when we get the whole message
		if (len > messages[i].size()){
            // here is performed a partial copy of the message that goes through the buffer
            // char* strncpy(char* destination, const char* source, size_t num)
            strncpy(clients[serverSocket]->client_buffer, messages[i].c_str(), sizeof(clients[serverSocket]->client_buffer) - 1);

            // ensures the null terminator is set; so what is copied is 4999 bytes with space for the null terminator so overflow does not occur
			clients[serverSocket]->client_buffer[sizeof(clients[serverSocket]->client_buffer) - 1] = '\0';  
            return;
		}
		
		if (messages[i][len - 1] != 0x003 && messages[i][messages[i].size() - 1] != 0x003){
		  std::cout << "Missing <ETX>" << std::endl;
		  continue;
		}
		
		// Find the part that is just the command
		size_t etx = messages[i].find(0x003);
		std::string command = messages[i].substr(3, etx);
		
		// Commands
		if (command.rfind("HELO", 0) == 0){
			size_t comma = command.find(',');
			std::string server_name = command.substr(comma);	// Everything after the comma should be the server name
			// only connect if there is room or instructor servers to kick out
			if (clients.size() > 7){
				if (instructors.size() < 1){
					disconnectedClients->push_back(clients[serverSocket]);
					closeClient(serverSocket, openSockets, maxfds);
					return;
				}
				// kick out instructor server
				Client *instructor = instructors.begin()->second;
				disconnectedClients->push_back(instructor);
				closeClient(instructor->sock, openSockets, maxfds);
				servers.erase(instructor->name);
				instructors.erase(instructor->sock);
			}
			// Add name
			servers[server_name] = new Server(serverSocket);
			servers[server_name]->name = server_name;
			clients[serverSocket]->name = server_name;
			
			// Add server to instructor list if it is an instructor server
			if (server_name[0] == 'I') instructors[serverSocket] = clients[serverSocket];
			
			// Send back SERVERS
			std::string response = "SERVERS,";
			for (auto const& pair : servers){
				Server *tmp = pair.second;
				response += tmp->name + ",";
				response += tmp->IP + ",";
				response += tmp->port + ",";
				response += ";";
			}
			
            uint16_t total_length = 5 + response.length();   // Calculate the lenght
			uint16_t network_length = htons(total_length);  // In network byte order

			// Assemlbing packet in (<SOH><length><STX><command><ETX>) format
			char packet[total_length];
			packet[0] = 0x01; // SOH
			memcpy(packet + 1, &network_length, 2);
			packet[3] = 0x02; // STX
			memcpy(packet + 4, response.c_str(), response.length());
			packet[total_length - 1] = 0x03; // ETX

			// Send packet
			send(serverSocket, packet, total_length, 0);
		}
		
		else if (command.rfind("GETMSGS", 0) == 0){
			// Get the group ID of the server for whom the message is
			size_t comma = command.find(',');
			std::string server_name = command.substr(comma);
            // Check if group has any mail in their message box
            if (!server_name.empty() && messageQueues.count(server_name) && !messageQueues[server_name].empty())
            {
                sendMsg(serverSocket, server_name.c_str());
            }
		}
		
		else if (command.rfind("KEEPALIVE", 0) == 0){
			size_t comma = command.find(',');
			int nr_of_messages = atoi(command.substr(comma).c_str());
            std::string groupId = "A5_23"; 
			for (int i = 0; i < nr_of_messages; i++) getMsg(serverSocket, groupId.c_str());
		}
		
		else if (command.rfind("STATUSREQ", 0) == 0){
			
		}
		
	}

}

// Process command from client on the server

void clientCommand(int clientSocket, fd_set *openSockets, int *maxfds, 
                  char *buffer, std::list<Client *> *disconnectedClients) 
{
	// Make sure there is nothing left from this socket from before
  if (clients[clientSocket]->client_buffer[0] != 0){
	  std::string line(buffer);
	  // see if there are leftover messages in the buffer. if so we need to finish those before addressing new ones
  }
  
  // If the first byte is SOH then the client is a server
  if (buffer[0] == 0x001 || clients[clientSocket]->name[0] == 'A' || clients[clientSocket]->name[0] == 'I'){
	  std::cout << "tokens got into servermessage" << std::endl;
	  serverCommand(clientSocket, openSockets, maxfds, buffer, disconnectedClients);
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
        }
    }
        // Check for GETMSG command
        else if (line == "GETMSG") 
        {
            std::cout << "Command: GETMSG" << std::endl;

            // Get the group ID of the client asking for a message
            // (Assumes the client has used "CONNECT <groupID>" beforehand)
            std::string clientGroupID = clients[clientSocket]->name;
            // Check if group has any mail in their message box
            if (!clientGroupID.empty() && messageQueues.count(clientGroupID) && !messageQueues[clientGroupID].empty())
            {
                // Get the oldest message from the front of the queue
                Message oldestMessage = messageQueues[clientGroupID].front();

                // Format message
                std::string formatted_message = "FROM " + oldestMessage.from + ": " + oldestMessage.body + "\n";
                
                // Send it to the client.
                send(clientSocket, formatted_message.c_str(), formatted_message.length(), 0);

                // Remove the message from the queue since it's been delivered
                messageQueues[clientGroupID].pop_front();

                // Log event
                log_lister(clientSocket, "Delivered message from " + oldestMessage.from);
            }
            else
            {
                // If there are no messages, tell the client
                const char* no_msg = "No new messages.\n";
                send(clientSocket, no_msg, strlen(no_msg), 0);
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
        else 
        {
  std::vector<std::string> tokens;
  std::string token;

  // Split command from client into tokens for parsing
  std::stringstream stream(buffer);

  while(stream >> token)
      tokens.push_back(token);
  
  // Connect to server using IP, port and name
  if((tokens[0].compare("CONNECT") == 0) && (tokens.size() == 4))
  {
	 connectServer(tokens[1].c_str(), tokens[2].c_str(), tokens[3].c_str());
  }
  else if(tokens[0].compare("LEAVE") == 0)
  {
      // Close the socket, and leave the socket handling
      // code to deal with tidying up clients etc. when
      // select() detects the OS has torn down the connection.
 
      closeClient(clientSocket, openSockets, maxfds);
  }
  else if(tokens[0].compare("WHO") == 0)
  {
     std::cout << "Who is logged on" << std::endl;
     std::string msg;

     for(auto const& names : clients)
     {
        msg += names.second->name + ",";

     }
     // Reducing the msg length by 1 loses the excess "," - which
     // granted is totally cheating.
     send(clientSocket, msg.c_str(), msg.length()-1, 0);

  }
  // This is slightly fragile, since it's relying on the order
  // of evaluation of the if statement.
  else if(tokens[0].compare("NAME") == 0)
  {
      clients[clientSocket]->name = tokens[1];
  }
  else
  {
      std::cout << "Unknown command from client:" << buffer << std::endl;
  }
     
}
}

// Sends other servers we are connected to the number of msg in their inbox
void keepAlive()
{
    for (auto const& pair : servers)
    {
<<<<<<< Updated upstream
        std::string sock = pair.first;         // The key is the socket number... Fixed, changed from int to const std::string because pair.first is a string... std::map<std::string, Server*> servers;
=======
        std::string serverName = pair.first;    // Server name
>>>>>>> Stashed changes
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
    fd_set openSockets;             // Current open sockets 
    fd_set readSockets;             // Socket list for select()        
    fd_set exceptSockets;           // Exception socket list
    int maxfds;                     // Passed to select() as max fd in set
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
    log_lister(4, "Server started listening on port " + std::to_string(atoi(argv[1])));

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
            lastKeepAliveTime = currentTime;
        }

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
               clientSock = accept(listenSock, (struct sockaddr *)&client,
                                   &clientLen);
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
            // Now check for commands from clients
            std::list<Client *> disconnectedClients;
            while(n-- > 0)
            {
               for(auto const& pair : clients)
               {
                  Client *client = pair.second;

                  if(FD_ISSET(client->sock, &readSockets))
                  {
                      // recv() == 0 means client has closed connection
                      if(recv(client->sock, buffer, sizeof(buffer), MSG_DONTWAIT) == 0)
                      {
                          disconnectedClients.push_back(client);
                          servers.erase(client->name);
                          if (client->name[0] == 'I') instructors.erase(client->sock);
                          closeClient(client->sock, &openSockets, &maxfds);
                          log_lister(clientSock, "client disconnected.");

                      }
                      // We don't check for -1 (nothing received) because select()
                      // only triggers if there is something on the socket for us.
                      else
                      {
                          clientCommand(client->sock, &openSockets, &maxfds, buffer, &disconnectedClients);
                          log_lister(client->sock, "Recived data: " + std::string(buffer));
                      }
                  }
               }
                // Remove client from the clients list
                for(auto const& c : disconnectedClients)
                    clients.erase(c->sock);
            }
        }
    }
}
