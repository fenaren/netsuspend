netsuspend: netsuspend.cpp toolbox/libtoolbox.a
	g++ -Wall -g2 -Itoolbox/networking -Itoolbox/logging -o $@ $^

toolbox/libtoolbox.a:
	make -C toolbox libtoolbox.a
