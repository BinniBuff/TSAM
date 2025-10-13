# ASSIGNMENT 5
## GROUP 23
## GROUP MEMBERS: BRYNJÓLFUR; SIGURJÓN BREKI; ÞÓRÐUR.

## Table of content
- [DESCRIPTION of CHANGES](#changes)
- [DESCRIPTION of USAGE](#compiling)
- [DESCRIPTION of USAGE](#machine-code)


# DESCRIPTION of CHANGES:
We got the foundation of our code from examples.tar, and have implemented changes to the server file. Below you can read the following changes.

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
        ./tsamgroupid23 <portNr>
        Listening on port: <portNr>
        accept***
        Client connected on server: 4
        number of tokens: 2
        Command: GETMSG
        Command: SENDMSG
        Group ID: 23
        Message: 'HELLO I AM EXAMPLE MESSAGE'
        Command: GETMSG
        Command: LISTSERVERS
        number of tokens: 2
        Command: LISTSERVERS
        Client closed connection: 4
        number of tokens: 1

        

    2. CLIENT: To run the client, enter theses arguments;

    ```bash -$ ./client <ipNr> <portNr>```

    (The successfull output will look like this.)
    Over and out 
    Eample of command usage:
        ./client <ipNr> <portNr>
        NAME 23
        GETMSG  
        No new messages.

        here
        SENDMSG,23,HELLO I AM EXAMPLE MESSAGE
        Message for 23 has been queued.

        here
        GETMSG
        HELLO I AM EXAMPLE MESSAGE
        here
        LISTSERVERS
        Connected clients:
        - Group: 23 (Socket: 4)

        here
        NAME 0
        LISTSERVERS
        Connected clients:
        - Group: 0 (Socket: 4)

        here
        LEAVE
        Over and Out
        





