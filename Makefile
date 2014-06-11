CC = gcc
all: pfreader-ssl

pfreader-simple:
	$(CC)  pfreader.c -o  pfreader

pfreader-ssl:
	$(CC) pfreader.c -lssl -lcrypto -DOPENSSL_EN -o pfreader 

pfreader-osx:
	$(CC) pfreader.c -lssl -lcrypto -DOPENSSL_EN -w -o pfreader 

pfreader-MiniGW:
	i686-w64-mingw32-gcc  pfreader.c -lssl -lcrypto -DOPENSSL_EN  -o pfreader 

pfreader-Simple-MiniGW:
	i686-w64-mingw32-gcc -DMINIGWPATH pfreader.c  -o pfreader 

clean:
	rm pfreader	

