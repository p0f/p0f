#
# Some sample SYN+ACK signatures. Those signatures work only with
# p0f -A, and will not work otherwise. This file is hardly maintained at
# the moment, but if there are any volunteers, I'm open :-)
#
# READ p0f.fp NOTES BEFORE MAKING ANY CHANGES TO THE FILE. ALL INFORMATION
# POSTED THERE STILL APPLIES TO THIS DATABASE.
#
# Submit any additions to the authors. Run p0f -A -C after making any
# modifications.
#
# Note that A quirk should show up on every signature here, and T
# on all signatures for systems implementing RFC1323. This is only
# unusual for SYN packets, not SYN|ACK. SYN|ACK must have ACK number
# set, of course, and the second timestamp is now an echo of the
# one from the SYN packet.
#

32736:64:0:44:M*:A:Linux:2.0
5792:64:1:60:M*,S,T,N,W0:ZAT:Linux:2.4

# Whatever they run. EOL boys...
S6:128:1:48:M1460:EPA:@Slashdot:???


