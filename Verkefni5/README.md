ASSIGNMENT 5
GROUP 23
GROUP MEMBERS: BRYNJÓLFUR; SIGURJÓN BREKI; ÞÓRÐUR.


DESCRIPTION:
We got the foundation of our code from examples.tar, and have implemented changes to the server file. Below you can read the following changes.

- CHANGES:

    1. SERVER: What was implemented was the following: Client commands under the function client_commands(). 
    The commands created was; SENDMSG, GETMSG, LISTSERVERS.
        - SENDMSG: Send message lets the server deliver a message to a chosen group id. 
        - GETMSG: Get a single message from the server to your group.
        - LISTSERVERS: Lets you list all the servers you are connected to. 


    2. CLIENT: At the moment the client file remains unchanged...


USAGE

DESCRIPTION:
Under usage you will see how you compile the files and how to use the machine code to run the functionalities.

- COMPILING:

    1. MAKE: To compile, type make in the terminal; -$ make. 
    (You will get successfull make output like this) 
    g++ -o client client.cpp g++ -o tsamgroup23 tsamgroup23.cpp
    Then you will notice the compiles files client, tsamgroup23.

- MACHINE CODE:
    1. SERVER: To run the server, enter these arguments; -$ ./tsamgroupid23 <portNr>
    (The successfull output will look like this.)
    Listening on port: <portNr>
    accept***
    Client connected on server: 4
    
    Example of usage:
    ./tsamgroupid23 <portNr>

        

    2. CLIENT: To run the client, enter theses arguments; -$ ./client <ipNr> <portNr>
    (The successfull output will look like this.)
    Over and out 
    Eample of command usage:
        ./client <ipNr> <portNr>
        





