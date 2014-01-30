SRC := \
netsuspend.cpp

LIB := \
toolbox/libtoolbox.a

netsuspend: $(SRC) $(LIB)
	g++ -Wall -g2 -Itoolbox/networking -Itoolbox/logging -o $@ $^
