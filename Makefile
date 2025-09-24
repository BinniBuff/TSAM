all: puzzlesolver scanner

scanner: scanner.cpp
	g++ -o $@ scanner.cpp
puzzlesolver: puzzlesolver.cpp
	g++ -o $@ puzzlesolver.cpp

clean:
	rm scanner puzzlesolver
