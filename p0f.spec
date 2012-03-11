%define version 1.8.3
Name:				p0f
Summary:			passive OS fingerprinting tool
Version:			%{version}
Release:			0
Copyright:			GPL
Packager:			William Stearns <wstearns@pobox.com>
Group:				Applications/Networking
Source:				http://www.stearns.org/p0f/p0f-%{version}.tgz
#Source1:			p0f.init
Prereq:				/sbin/chkconfig
Vendor:				Michal Zalewski <lcamtuf@coredump.cx>
URL:				http://www.stearns.org/p0f/
BuildRoot:			/tmp/p0f-broot


%description
p0f performs passive OS fingerprinting technique bases on information coming
from remote host when it establishes connection to our system. Captured
packets contains enough information to determine OS - and, unlike
active scanners (nmap, queSO) - it is done without sending anything to 
this host.


%changelog
* Thu Feb  6 2003 William Stearns <wstearns@pobox.com>
- README.windows
- 1.8.3 source

* Mon Jan 21 2002 William Stearns <wstearns@pobox.com>
- Minor fixes and updates
- Addition of p0frep log reporting tool

* Mon Jan 21 2002 William Stearns <wstearns@pobox.com>
- Updated to 1.8 final sources

* Sat Nov 17 2001 William Stearns <wstearns@pobox.com>
- Updated to 1.8 test sources

* Wed Aug 13 2000 William Stearns <wstearns@pobox.com>
- first rpm from 1.7 sources.
- addition of a SysV init file


%prep
%setup


%build
make all


%install
if [ "$RPM_BUILD_ROOT" = "/tmp/p0f-broot" ]; then
	rm -rf $RPM_BUILD_ROOT

	install -d $RPM_BUILD_ROOT/etc
	install -d $RPM_BUILD_ROOT/etc/rc.d/init.d
	install -d $RPM_BUILD_ROOT/usr/bin
	install -d $RPM_BUILD_ROOT/usr/sbin
	install -d $RPM_BUILD_ROOT/usr/share/man/man1
	cp -p p0f.fp $RPM_BUILD_ROOT/etc
	cp -p p0f $RPM_BUILD_ROOT/usr/sbin
	cp -p p0frep $RPM_BUILD_ROOT/usr/bin
	cp -p p0f.init $RPM_BUILD_ROOT/etc/rc.d/init.d/p0f
        cp -p p0f.1 p0f.1.orig
	rm -f p0f.1.gz
	gzip -9 p0f.1
	mv p0f.1.orig p0f.1
	mv p0f.1.gz $RPM_BUILD_ROOT/usr/share/man/man1
else
	echo Invalid Build root
	exit 1
fi

						
%clean
if [ "$RPM_BUILD_ROOT" = "/tmp/p0f-broot" ]; then
	rm -rf $RPM_BUILD_ROOT
else
	echo Invalid Build root
	exit 1
fi


%files
%defattr(-,root,root)
					%doc	COPYING CREDITS ChangeLog README README.windows
%attr(644,root,root)				/etc/p0f.fp
%attr(755,root,root)				/etc/rc.d/init.d/p0f
%attr(755,root,root)				/usr/bin/p0frep
%attr(755,root,root)				/usr/sbin/p0f
%attr(644,root,root)				/usr/share/man/man1/p0f.1.gz


%post
if [ ! -f /var/log/p0f ]; then
	touch /var/log/p0f
	chown root.root /var/log/p0f
	chmod 600 /var/log/p0f
fi
if [ "$1" = "1" ]; then         #This package is being installed for the first time
	/sbin/chkconfig --add p0f
fi


%preun
if [ "$1" = "0" ]; then		#This is being completely erased, not upgraded
	/sbin/chkconfig --del p0f
fi
