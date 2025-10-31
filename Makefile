CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = simulaPOS

# Lista de arquivos fonte e objetos
SRCS =testa_iso8583_comSend.c myIso8583.c
OBJS = $(SRCS:.c=.o)

# Regra principal
all: $(TARGET)

# Como construir o executável
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET)

# Regra genérica para compilar .c em .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Limpar tudo
clean:
	rm -f $(OBJS) $(TARGET)

