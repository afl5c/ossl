
test: ossl.h ossl.c test.c cacerts.h
	gcc -o test -O2 test.c ossl.c
	#root should be valid:
	./test https://example.com/
	./test https://axm.dev/
	./test https://arena.aaronliu.dev/
	#root should be invalid, but still show response:
	./test https://self-signed.badssl.com/

server: ossl.h ossl.c server.c cacerts.h
	gcc -o server -O2 server.c ossl.c
	./server 9443

# Embed the system CA bundle plus Let's Encrypt intermediates/roots.
# Uses /etc/ssl/certs/ca-certificates.crt as the base and appends
# locally-stored Let's Encrypt certs for full chain verification.
cacerts.h:
	ls -lthr /etc/ssl/certs/ca-certificates.crt
	update-ca-certificates
	ls -lthr /etc/ssl/certs/ca-certificates.crt
	# Fetch Let's Encrypt intermediate/root certs (needed for chain building
	# when servers only send the leaf cert). ISRG Root X1 is already on the
	# system; the rest are downloaded from Let's Encrypt's AIA endpoints.
	wget -qO- http://yr1.i.lencr.org/ | openssl x509 -inform der -out lets-encrypt-yr1.pem
	wget -qO- http://yr.i.lencr.org/  | openssl x509 -inform der -out isrg-root-yr.pem
	wget -q https://letsencrypt.org/certs/2024/r10.pem -O lets-encrypt-r10.pem
	wget -q https://letsencrypt.org/certs/2024/r11.pem -O lets-encrypt-r11.pem
	@echo '#ifndef CACERTS_H' > $@
	@echo '#define CACERTS_H' >> $@
	@echo '' >> $@
	@echo 'const char cacerts[] =' >> $@
	@cat /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ISRG_Root_X1.pem lets-encrypt-yr1.pem isrg-root-yr.pem lets-encrypt-r10.pem lets-encrypt-r11.pem 2>/dev/null | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/.*/"&\\n"/' >> $@
	@echo ';' >> $@
	@echo '' >> $@
	@echo '#endif' >> $@

# Cross compilation
mac:
	mac-gcc -o ossl.mac.o -O2 -c ossl.c

win:
	win-gcc -o ossl.win.o -O2 -c ossl.c

linux: 
	gcc -o ossl.linux.o -O2 -c ossl.c

arm: 
	arm-gcc -o ossl.arm.o -O2 -c ossl.c

rpi:
	rpi-gcc -o ossl.rpi.o -O2 -c ossl.c -std=c99

android:
	and-gcc -o ossl.android.o -O2 -c ossl.c

all: mac win linux arm rpi android

clean:
	rm -f *.o test server cacerts.h *pem
