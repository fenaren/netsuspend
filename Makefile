SRC := \
netsuspend.cpp

LIB := \
log/liblog.a \
socket/libsocket.a

netsuspend: $(SRC) $(LIB)
	g++ -Wall -g2 -Isocket -Inetstructs -Ilog -o $@ $^
