#!/sbin/sh

### This script allows to run the p0f program with preset options, i.e.
### for integration with Solaris SMF or default poking on command-line.
### Instructions for SMF integration are in the manifest file p0f-daemon.xml.
### It may also be used as the init-script for the service (tested only under
### Solaris, and suffers from its limited system shell syntax requirements).

###	=== LICENSE
###	This script is distributed under the following MIT License terms:
###
###	Copyright (c) 2013-2014 by Jim Klimov, JSC COS&HT
###	Published at:
###		https://github.com/jimklimov/p0f
###
###	Permission is hereby granted, free of charge, to any person
###	obtaining a copy of this software and associated documentation
###	files (the "Software"), to deal in the Software without
###	restriction, including without limitation the rights to use,
###	copy, modify, merge, publish, distribute, sublicense, and/or sell
###	copies of the Software, and to permit persons to whom the
###	Software is furnished to do so, subject to the following
###	conditions:
###
###	The above copyright notice and this permission notice shall be
###	included in all copies or substantial portions of the Software.
###
###	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
###	EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
###	OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
###	NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
###	HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
###	WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
###	FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
###	OTHER DEALINGS IN THE SOFTWARE.

### Overridables (via config file)
### OS User to run the daemon as:
[ x"$P0F_RUNAS" = x ] && P0F_RUNAS=p0f

### Data directory which contains the log and UNIX-socket files (below).
### While the default "/var/tmp" should do the trick and let the service
### run with little hassle, it is probably insecure and should be changed
### to a dedicated directory in a particular installation.
# [ x"$P0F_DATADIR" = x ] && P0F_DATADIR="/var/p0f"
[ x"$P0F_DATADIR" = x ] && P0F_DATADIR="/var/tmp"

[ x"$P0F_BINDIR" = x ] && P0F_BINDIR="`dirname "$0"`"

### The binary to use (should be in the PATH defined below):
[ x"$P0F_BIN" = x ] && P0F_BIN=p0f
# [ x"$P0F_BIN" = x ] && P0F_BIN=p0f-debug

### The set of options and BPF filter definition for per-installation tweaking:
# P0F_OPTIONS="-i e1000g0 -f /etc/p0f.fp"
# P0F_OPTIONS="-i /dev/net/vnic1"
# P0F_BPF="'(src net not 192.168.0.0/16 and src net not 172.16.0.0/12 and src net not 10.0.0.0/8)'"
P0F_OPTIONS=""
P0F_BPF=""

### Source the config file(s), unless called from a shell with P0F_OVERRIDE=no
### (the override switch for debugging the option set, etc.). Provisions are
### made for a distribution/site-provided default config as well as its local
### overrides for a particular host.
if [ x"$P0F_OVERRIDE" != xno ]; then
	for F in /etc/default/p0f.packaged /etc/default/p0f "$P0F_CONFIG"; do
	    [ x"$F" != x ] && [ -s "$F" ] && \
		echo "Sourcing p0f config file: '$F'" && . "$F"
	done
fi

### The basic set of options as provided in the package:
P0F_OPTIONS_PKG="-u ${P0F_RUNAS} -o ${P0F_DATADIR}/p0f.log -s ${P0F_DATADIR}/p0f.sock"

[ x"$DEBUG" != x ] && echo "=== Running as: `id`"
chown -R root:root ${P0F_DATADIR}/p0f*

PATH="`dirname $0`:$P0F_BINDIR:/usr/local/bin:$PATH"
LD_LIBRARY_PATH="/usr/ucblib:$LD_LIBRARY_PATH"
export PATH LD_LIBRARY_PATH

case "$1" in
	start)	"$P0F_BIN" $P0F_OPTIONS_PKG $P0F_OPTIONS -d \
		    ${P0F_BPF:+"$P0F_BPF"}
		;;
	stop|restart)
		_PID=`ps -ef | egrep -v 'grep|tail' | grep "$P0F_BIN" | awk '{ if ( $1 == "'${P0F_RUNAS}'" ) { print $2 } }'`
		RES=0
		if [ x"$_PID" != x ]; then
			echo "Stopping p0f process PID(s): $_PID ..."
			kill -15 $_PID
    		        RES=$?
		fi
                if [ x"$1" = xrestart ]; then
			echo "Restarting p0f process..."
                        "$P0F_BIN" $P0F_OPTIONS_PKG $P0F_OPTIONS -d \
			    ${P0F_BPF:+"$P0F_BPF"}
                        RES=$?
                fi
                exit $RES
                ;;
        state|status)
		[ -x /bin/svcs ] && /bin/svcs -p p0f-daemon
                ps -ef | egrep -v 'grep|tail' | \
            	    awk '{ if ( $1 == "'"$P0F_RUNAS"'" ) { print $0 } }' | \
		    grep "$P0F_BIN"
		RES=$?
		if [ "$RES" = 0 ]; then
		    echo "Status: [--OK--]"
		else
		    echo "Status: [-FAIL-]"
		fi
		exit $RES
                ;;
        *)	if echo "$*" | egrep -i '(^| |\()(tcp|udp|src|dst|host|net|port)($| |\))' >/dev/null; then
		    # Packet filtering rule is on command-line, override config
		    "$P0F_BIN" $P0F_OPTIONS_PKG $P0F_OPTIONS "$@"
		    RES=$?
		else
		    # Process command-line and use config default packet filter
		    "$P0F_BIN" $P0F_OPTIONS_PKG $P0F_OPTIONS \
			"$@" ${P0F_BPF:+"$P0F_BPF"}
		    RES=$?
		fi
		exit $RES
		;;
esac

### NOTE: To specify a BPF expression if one is in the config file already,
### use the override switch, i.e.
###	P0F_OVERRIDE=no /usr/local/bin/p0f.sh 'host 4.2.2.4'
### To daemonize use "-d" (or start as the single parameter)...
