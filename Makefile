test:
	gcc -o test.linux -O2 test.c ossl.c
	./test.linux https://example.com/
	./test.linux https://axm.dev/
	./test.linux https://self-signed.badssl.com/
	./test.linux https://arena.aaronliu.dev/

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

update:
	ls -lthr /etc/ssl/certs/ca-certificates.crt
	update-ca-certificates
	ls -lthr /etc/ssl/certs/ca-certificates.crt

cacerts.h: /etc/ssl/certs/ca-certificates.crt
	@echo '#ifndef CACERTS_H' > $@
	@echo '#define CACERTS_H' >> $@
	@echo '' >> $@
	@echo 'const char cacerts[] =' >> $@
	@sed -e 's/\\\\/\\\\\\\\/g' -e 's/"/\\"/g' -e 's/.*/"&\\n"/' $< >> $@
	@echo ';' >> $@
	@echo '' >> $@
	@echo '#endif' >> $@