# ASSIGNMENT 5
## GROUP 23
## GROUP MEMBERS: BRYNJÓLFUR; SIGURJÓN BREKI; ÞÓRÐUR.

## Table of content
- [DESCRIPTION of CHANGES](#changes)
- [DESCRIPTION of USAGE](#compiling)
- [DESCRIPTION of USAGE](#machine-code)
- [DESCRIPTION of WIRESHARK FILE](#trace)





# DESCRIPTION of CHANGES:
We got the foundation of our code from examples.tar, and have implemented changes to the server file.
Below you can read the following changes.

- ## CHANGES:

    1. SERVER: What was implemented was the following: Client commands under the function client_commands(). 
    The commands created was; NAME, SENDMSG, GETMSG, LISTSERVERS.
        - NAME: Name command is for identifying the connected dvice.
        - SENDMSG: Send message lets the server deliver a message to a chosen group id. 
        - GETMSG: Get a single message from the server to your group.
        - LISTSERVERS: Lets you list all the servers you are connected to. 

    2. CLIENT: You get full date after sending messages, changed size for buffer from 1024B to 5000B.




# DESCRIPTION of USAGE:
Under usage you will see how you compile the files and how to use the machine code to run the functionalities.

- ## COMPILING:

    1. MAKE: To compile, type make in the terminal; 

    ```bash make```

    (You will get successfull make output like this) 
    g++ -o client client.cpp g++ -o tsamgroup23 tsamgroup23.cpp
    Then you will notice the compiles files client, tsamgroup23.

- ## MACHINE CODE:
    1. SERVER: To run the server, enter these arguments; 

    ```bash -$ ./tsamgroupid23 <portNr>```

    (The successfull output will look like this.)
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

    (The successfull output will look like this.)
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




# WIRESHARK

## DESCRIPTIION of WIRESHARK FILE:
In the folder you can see there is a file called client-server-trace.pcapng, there is the ouput of the trace while we did the example of communication between the server and client. To open the file you must set up WIRESHARK on your own computer. Enter the following url in your internet browser and follow the installation process ( https://github.com/wireshark/wireshark ). Once it is done, come back and open the file, client-server-trace.pcapng 

- ## TRACE:
    In the file you can see the communication from the clients point of view. 
    In the output you can view the header payload when testers ran the commands. 
    If you right cick any packet and click (follow TCP stream), 
    you can see the comunication in plane text from console point of view.



                





