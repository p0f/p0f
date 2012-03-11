#
# p0f - passive OS fingerprinting
# (C) Copyright 2000, 2001 by Michal Zalewski <lcamtuf@coredump.cx>
# (C) Copyright 2001 by William Stearns <wstearns@pobox.com>
#

CC      = gcc
CLIBS	= -lpcap -I/usr/include/pcap
MYSQLCLIBS	= -L/usr/local/mysql/lib -lmysqlclient -lpcap -I/usr/include/pcap -I/usr/local/mysql/include
SUNLIBS	= -lsocket -lnsl -D_SUN_=1
STRIP	= strip
CFLAGS  = -O3 -Wall
FILE	= p0f
VERSION = 1.8.3

DISTRO  = COPYING CREDITS ChangeLog Makefile README README.windows mysql/db.sql mysql/p0f-mysql.conf p0f.1 p0f.c p0f.fp p0f.init p0f.spec p0frep tcp.h

all: $(FILE) strip	

$(FILE): p0f.c
	$(CC) $(CFLAGS) -DVER=\"$(VERSION)\" -o $@ p0f.c $(CLIBS) \
	`uname|egrep -i 'sunos|solar' >/dev/null && echo "$(SUNLIBS)"`

p0f-mysql: p0f.c
	$(CC) $(CFLAGS) -DVER=\"$(VERSION)\" -o $@ p0f.c $(MYSQLCLIBS) \
	`uname|egrep -i 'sunos|solar' >/dev/null && echo "$(SUNLIBS)"` -D__MYSQL__
	mv -f p0f-mysql p0f

strip:
	strip $(FILE) || true

clean:
	rm -f core *.o $(FILE)
	rm -rf p0f-$(VERSION)

tgz: clean
	mkdir -m 755 p0f-$(VERSION)
	cp $(DISTRO) p0f-$(VERSION)/
	chmod 644 p0f-$(VERSION)/*
	tar cfvz /tmp/$(FILE).tgz p0f-$(VERSION)
	chmod 644 /tmp/$(FILE).tgz
	#rm -rf p0f-$(VERSION)

publish: tgz
	#scp /tmp/p0f.tgz lcamtuf@dione.ids.pl:public_html/p0f.tgz
	#scp /tmp/p0f.tgz lcamtuf@dione.ids.pl:public_html/p0f-$(VERSION).tgz
	#rm -f /tmp/p0f.tgz
	

install: $(FILE)
	mkdir -p $(DESTDIR)/usr/bin
	mkdir -p $(DESTDIR)/usr/sbin
	mkdir -p $(DESTDIR)/usr/share/doc/p0f-$(VERSION)
	mkdir -p $(DESTDIR)/usr/share/man/man1
	cp -p p0f.fp $(DESTDIR)/etc
	cp -p p0f.init $(DESTDIR)/etc/init.d/p0f
	cp -p COPYING CREDITS ChangeLog README README.windows $(DESTDIR)/usr/share/doc/p0f-$(VERSION)
	cp -p p0f $(DESTDIR)/usr/sbin
	cp -p p0frep $(DESTDIR)/usr/bin
	cp -p p0f.1 p0f.1.orig
	rm -f p0f.1.gz
	gzip -9 p0f.1
	mv p0f.1.orig p0f.1
	mv p0f.1.gz $(DESTDIR)/usr/share/man/man1
	chmod 755 $(DESTDIR)/etc/init.d/p0f $(DESTDIR)/usr/sbin/p0f $(DESTDIR)/usr/bin/p0frep

distribs:
	@echo This should only need to be used by the author in 
	@echo packing up the p0f package.
	cd .. \
	&& tar cf - p0f-$(VERSION)/ | \
	gzip -9 > p0f-$(VERSION).tgz \
	&& rm -f p0f-current \
	&& ln -sf p0f-$(VERSION) p0f-current \
	&& tar cf - p0f-current/* | \
	gzip -9 > p0f-current.tgz \
	&& cp p0f-$(VERSION).tgz /usr/src/redhat/SOURCES/ \
	&& cd p0f-$(VERSION) \
	&& cp -f p0f.spec /usr/src/redhat/SPECS/ \
	&& rpm --sign -ba /usr/src/redhat/SPECS/p0f.spec \
	&& mv /usr/src/p0f-*.tgz /home/wstearns/dist/pubroot/p0f/ \
	&& mv /usr/src/redhat/RPMS/i386/p0f-*.i386.rpm /home/wstearns/dist/pubroot/p0f/ \
	&& mv /usr/src/redhat/SRPMS/p0f-*.src.rpm /home/wstearns/dist/pubroot/p0f/ \
	&& chown -R wstearns.wstearns /home/wstearns/dist/pubroot/p0f/
	@echo Please run distall, thanks.


