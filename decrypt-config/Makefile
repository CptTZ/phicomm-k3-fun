#
# Phicomm K3 crypto utility
#

BASE := .
BCMBASE := $(BASE)/bcmcrypto

CC := gcc

CFLAGS += -I$(BASE)/include -lcrypto
CFLAGS += -g -DDEBUG -ffunction-sections
CFLAGS += -O2 -Wall -Werror

PROGS := phi_aes phi_chksum phi_base64

all: phi_chksum

dbg: $(PROGS)

clean:
	rm -f *.o *.obj $(PROGS) *.exe


phi_aes: $(BASE)/phi_aes.c
	$(CC) $(CFLAGS) -DAES_DEBUG -o $@ $^ $(LDFLAGS)

phi_chksum: $(BASE)/phi_chksum.c $(BASE)/phi_aes.c $(BASE)/phi_base64.c $(BCMBASE)/prf.c $(BCMBASE)/hmac.c $(BCMBASE)/md5.c $(BCMBASE)/sha1.c
	$(CC) $(CFLAGS) -DBCMCCX -o $@ $^ $(LDFLAGS)

phi_base64: $(BASE)/phi_base64.c
	$(CC) $(CFLAGS) -DBASE64_DEBUG -o $@ $^ $(LDFLAGS)
