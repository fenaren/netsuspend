netsuspend: netsuspend.cpp toolbox/libtoolbox.a
	@g++ -Wall -g2 -Itoolbox/networking -Itoolbox/misc -o $@ $^

clean:
	@rm -f netsuspend

toolbox/libtoolbox.a:
	make -C toolbox libtoolbox.a
