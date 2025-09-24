In this folder there are two projects coded in C++.
To build them you only need to write 'make' in the terminal,
as there is a Makefile.

To run the first project, you need to begin with the command:
'./scanner 130.208.246.98 4000 4100'.
You need to use 130.208.246.98 for this project
but you can put in any valid IP address.
This should return 4 open ports between ports 4000 and 4100
that you need to use to run the second project.

To run the second project, begin with the command:
'./puzzlesolver 130.208.246.98 [port number 1] [port number 2] [port number 3] [port number 4]'.
Using the 4 ports from the first project.
