Source = src/pbc_inshort.c src/hui-cui.c main.c
Target = out
Object = pbc_inshort.o hui-cui.o main.o

DIR_I = /usr/local/include/pbc
DIR_L = /usr/local/lib
FLAG = -I $(DIR_I) -L $(DIR_L) -Wl,-rpath $(DIR_L) -lpbc -lgmp

$(Target):$(Object)
	gcc -o $@ $^ $(FLAG)
	@echo "Succeed!"

$(Object):$(Source)
	gcc -c $^ $(FLAG)
clean:
	rm $(Object)
	rm $(Target)
