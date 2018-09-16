INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all:
	gcc -Wall -Wextra -I$(INC) -L$(LIB) -o enc online.c -lcrypto -ldl
