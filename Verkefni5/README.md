# ASSIGNMENT 5
## GROUP 23
## GROUP MEMBERS: BRYNJÓLFUR; SIGURJÓN BREKI; ÞÓRÐUR.

## Table of content
- [DESCRIPTION of CHANGES](#changes)
- [DESCRIPTION of USAGE](#commands)
- [DESCRIPTION of WIRESHARK FILE](#trace)
- [EXPECTED POINTS](#expectation)



# DESCRIPTION of CHANGES:
We got the foundation of our code from examples.tar, and have implemented changes to the server from the assignment description from our best of knowledge. The changes in the client code were minimal, we changed the buffer size and added a date stamp from when client commands are sent to the server.
Newest changes in our project is that we setup a HOME SERVER running under one of the group members internet setup. He setup a second router and connected his old PC to the second router... lets call it router B. Router b was then completely isolated from the main router and is in a DMZ. 

Below you can read the following changes.

- ## CHANGES:
    Previous changes
    1. SERVER: What was implemented was the following: Client commands under the function client_commands(). 
    The commands created was; NAME, SENDMSG, GETMSG, LISTSERVERS, CONNECT.
        - NAME: Name command is for identifying the connected dvice.
        - SENDMSG: Send message lets the server deliver a message to a chosen group id. 
        - GETMSG: Get a single message from the server to your group.
        - LISTSERVERS: Lets you list all the servers you are connected to. 
        - CONNECT: We are still working on implementing this command, this command will be what connects us to other servers.
        Usage CONNECT <ip> <port>.

    2. CLIENT: You get full date after sending messages, changed size for buffer from 1024B to 5000B.

    New changes
    1. HOME SERVER: Our server is running alone under its own ip completely isolated from the TSAM server. For security we set up a DMZ to protect the internal network from potentionl malicious actors. The server is running on a Linux Ubuntu OS that we booted, it was previously Windows 8. To work on the personal server we set up tunnels from all of our personal devices to the server so we could do changes on the server away from the server network. The server was setup to be able to run 24/7.
    2. SERVER CODE: 
        - COMMANDS: clientCommand(), the server is remotely operated through a connected client, the client sends commands to the server to act on.  serverCommand(), the server commands respond to requests by other servers connected.
        - Functionalities: When we first connect to server we send HELO command seperated with our group Id, and we expect that other servers send HELO back to us when a connection is trying to be estabilished. If we lack connections, we try to connect to other servers through current connections.



# DESCRIPTION of USAGE:
Under usage you will see how you compile the files and how to use the machine code to run the functionalities.

- ## COMMANDS:
    Server Commands: 
        - "HELO,<FROM_GROUP_ID>" The first message that is sent to a server when a connection is made.
        - "SERVERS" is the respone to "HELO", and sends the recieving server, the servers you are connected to, starting with yourself
        - "KEEPALIVE,<No. of Messages>" on 1 min interval the server senda this out to all conneceted servers.
        - "GETMSG,<GROUP_ID>" Gets all messages in queue spcified for individual group Id.
        -"SENDSMSG,<To_GROUP_IF>, <FROM_GROUP_ID>,<MESSAGE_CONTENT>" Sends an individual message to a specified group
        -"STATUSREQ" Replies with STATUSRESP
        -"STATUSRESP,<SERVER_NAME_1>,<NO_MESSAGES>,<SERVER_NAME_1>,<NO_MESSAGES>,<SERVER_NAME_N>,<NO_MESSAGES>" Replies with comma seperated list of server names and the number of messages ther server running has for those groups.
    
    Client Commands:
        -"GETMSG" Gets a single message from the server for the server running.
        -"SENDMSG,<GROUP_ID>,<MESSAGE_CONTENT>" Lets the server deliver a message to group GROUP_ID
        -"LISTSERVERS" Lists servers that the running server is connected to.


- ## COMPILING:

    1. MAKE: To compile, type make in the terminal; 

    ```bash make```

    (You will get successfull make output like this) 
    g++ -o client client.cpp g++ -o tsamgroup23 tsamgroup23.cpp
    Then you will notice the compiles files client, tsamgroup23.

- ## MACHINE CODE:
    1. SERVER: To run the server, enter these arguments; 

    ```bash -$ ./tsamgroupid23 <portNr>```

    (The successfull example output will look like this.)
    Listening on port: <portNr>
    accept***
    Client connected on server: 4
    
    Example of usage:
    ./tsamgroup23 4023
    Listening on port: 4023
    accept***
    Client connected on server: 4
    Client closed connection: 4
    accept***
    Client connected on server: 4
    Command: SENDMSG
    Group ID: 23
    Message: 'A test message for testing'
    Command: GETMSG
    Command: LISTSERVERS
    Client closed connection: 4

        

    2. CLIENT: To run the client, enter theses arguments;

    ```bash -$ ./client <ipNr> <portNr>```

    (The successfull example output will look like this.)
    Over and out 
    Eample of command usage:
        ./client <redacted> 4023
        NAME 23
        CLIENT:
        Mon Oct 13 13:41:34 2025
        NAME 23

        SENDMSG,23,A test message for testing
        CLIENT:
        Mon Oct 13 13:42:03 2025
        SENDMSG,23,A test message for testing

        SERVER:
        Mon Oct 13 13:42:03 2025
        Message for 23 has been queued.

        GETMSG
        CLIENT:
        Mon Oct 13 13:42:11 2025
        GETMSG

        SERVER:
        Mon Oct 13 13:42:11 2025
        A test message for testing
        LISTSERVERS
        CLIENT:
        Mon Oct 13 13:42:19 2025
        LISTSERVERS

        SERVER:
        Mon Oct 13 13:42:19 2025
        Connected clients:
        - Group: 23 (Socket: 4)

        LEAVE
        CLIENT:
        Mon Oct 13 13:53:07 2025
        LEAVE

        Over and Out


    3. To connect to our server:
        Our server IP and port is 100.85.220.16,4023.
        - The server will be running so to connect your client to our server do the following.
            1. After compiling run the client and use our ip and port: 
            ```bash -$ ./client 100.85.220.16 4023```.

        Use of commands for client: 
          ```bash MY_IP,<your ip>,<your port>```
          ```bash CONNECT,130.208.246.98,5001,Instr_1 ```
          ```bash  SENDMSG,<some groupid>,"The message!" ```


# WIRESHARK

## DESCRIPTIION of WIRESHARK FILE:
In the folder you can see there is a file called client-server-trace.pcapng, there is the ouput of the trace while we did the example of communication between the server and client. To open the file you must set up WIRESHARK on your own computer. Enter the following url in your internet browser and follow the installation process ( https://github.com/wireshark/wireshark ). Once it is done, come back and open the file, client-server-trace.pcapng 

- ## TRACE:
    In the file you can see the communication from the clients point of view. 
    In the output you can view the header payload when testers ran the commands. 
    If you right cick any packet and click (follow TCP stream), 
    1.
    a) We expect 40 points for implmenting client and server as described in project description.

    b) For early bot we handed in a trace of the wireshark output of commu nication between our client and server (See early bot handin).

    c) We expect to get 10 points for someone elses server connecting to ours, proof:
    from "events_23-10-25.log" ([23-10-25_16:30:26] A5_29 sent HELO,A5_29). Group A5_29 initiates connection.
    
    d) We expect to get 10 points for successfully getting messages from two other groups, proof: 
    from "events_23-10-25.log" ( 
     [23-10-25_16:30:31] A5_27 first byte is correct <SOH>, got into servermessage 
     [23-10-25_16:30:31] A5_27 sent SENDMSG,A5_23,A5_27,[31mH[33me[32ml[36ml[34mo[35m [91mW[93mo[92mr[94ml[95md[0mA5_27 
     [23-10-25_16:32:19] A5_60 first byte is correct <SOH>, got into servermessage
     [23-10-25_16:32:19] A5_60 sent SENDMSG,A5_23,A5_28,Hello from A5_28!A5_28
    )
    
    e) We expect to get 10 points for successfully send a message to atleast two other groups (log).
    
    f) We expect to get 10 points for correctly handing in the server.
    
    g) We expect to get 10 points for structuring the code well and documenting the code and serer produces readable *.log file.

    2.
    
    a) We already successfully gathered the extra points for early bot.
    
    b) We did not succeed doing ready bot.
    
    c) We
    
    d) We did not succeed doing inderect bot.
    
    e) We expect 10 points for our server being connected to atleast 5 peers at 5 different times.
    
    f) We expect 20 points for setting up our personal network successfully implementing external bot.



# EXPECTED POINTS:

## EXPECTATION:
    1.
    a) We expect 40 points for implmenting client and server as described in project description.

    b) For early bot we handed in a trace of the wireshark output of commu nication between our client and server (See early bot handin).

    c) We expect to get 10 points for someone elses server connecting to ours, proof:
    from "events_23-10-25.log" ([23-10-25_16:30:26] A5_29 sent HELO,A5_29). Group A5_29 initiates connection.
    
    d) We expect to get 10 points for successfully getting messages from two other groups, proof: 
    from "events_23-10-25.log" ( 
     [23-10-25_16:30:31] A5_27 first byte is correct <SOH>, got into servermessage 
     [23-10-25_16:30:31] A5_27 sent SENDMSG,A5_23,A5_27,[31mH[33me[32ml[36ml[34mo[35m [91mW[93mo[92mr[94ml[95md[0mA5_27 
     [23-10-25_16:32:19] A5_60 first byte is correct <SOH>, got into servermessage
     [23-10-25_16:32:19] A5_60 sent SENDMSG,A5_23,A5_28,Hello from A5_28!A5_28
    )
    
    e) We expect to get 10 points for successfully send a message to atleast two other groups (log).
    
    f) We expect to get 10 points for correctly handing in the server.
    
    g) We expect to get 10 points for structuring the code well and documenting the code and serer produces readable *.log file.

    2.
    
    a) We already successfully gathered the extra points for early bot.
    
    b) We did not succeed doing ready bot.
    
    c) We
    
    d) We did not succeed doing inderect bot.
    
    e) We expect 10 points for our server being connected to atleast 5 peers at 5 different times.
    
    f) We expect 20 points for setting up our personal network successfully implementing external bot.





                





