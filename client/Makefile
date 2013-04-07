CC     := gcc
CFLAGS := 
TARGET := thclient
OBJS   := main.o interface.o dhcp.o socket.o

all: $(TARGET)

$(TARGET) : $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET)

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

clean :
	rm -f $(TARGET)
	rm -f *.o
