all: client server

server: server.cpp
	g++ -o $@ server.cpp
client: client.cpp
	g++ -o $@ client.cpp

clean:
	rm server client
