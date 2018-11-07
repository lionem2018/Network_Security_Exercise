.SUFFIXES : .c .o
CC = gcc

INC =
LIBS = -lcrypto -lssl
CFLAGS = 

OBJS = server.o
TARGET = server

all : 
	$(CC) $(CFLAGS) -o server *.c  $(LIBS)

clean :
	rm -rf $(TARGET) core
new : 
	$(MAKE) clean 
	$(MAKE) 

