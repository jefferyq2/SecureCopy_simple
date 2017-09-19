CC = gcc
CFLAG = `libgcrypt-config --cflags` -lstdc++
LIBS = `libgcrypt-config --libs`
OBJS = suncrypt.o suncrypt sundec.o sundec

all: $(OBJS)

suncrypt.o: suncrypt.cpp
	$(CC) -c -o suncrypt.o suncrypt.cpp $(CFLAG)
suncrypt: suncrypt.o
	$(CC) -o suncrypt suncrypt.o $(CFLAG) $(LIBS)
sundec.o: sundec.cpp
	$(CC) -c -o sundec.o sundec.cpp $(CFLAG)
sundec: sundec.o
	$(CC) -o sundec sundec.o $(CFLAG) $(LIBS)

clean:
	rm $(OBJS)
