#
# p0f - RST+ signatures
# ---------------------
#
# .-------------------------------------------------------------------------.
# | The purpose of this file is to cover signatures for reset packets       |
# | (RST and RST+ACK). This mode of operation can be enabled with -A option |
# | and is considered to be least accurate. Please refer to p0f.fp for more |
# | information on the metrics used and for a guide on adding new entries   |
# | to this file. This database is looking for a caring maintainer.         |
# `-------------------------------------------------------------------------'
#
# (C) Copyright 2000-2003 by Michal Zalewski <lcamtuf@coredump.cx>
#
# Submit all additions to the authors. Read p0f.fp before adding any
# signatures. Run p0f -R -C after making any modifications. This file is
# NOT compatible with SYN or SYN+ACK modes. Use only with -R option.
#
# IMPORTANT
# ---------
#
# There are several types of RST packets you will surely encounter.
# Some systems, including most reputable ones, are severily brain-damaged
# and generate some illegal combinations from time to time. Be prepared
# to handle it. P0f will give you a hint on new RST signatures, but it
# is your duty to diagnose the problem and append the proper description
# when adding the signature. "Signature quirks" is a combination of
# K, 0 and A quirks characteristic to this traffic.
#
# - RST+ACK, SEQ number zero, ACK number set to zero or non-zero. This
#   is the typical response to an unexpected packet without ACK flag set.
#   From your perspective, this is usually the message generated to say
#   "Connection refused" in response to a SYN packet, although some brain-
#   dead systems might use RST+ACK for just about anything.
#
#   The sequence number for the response is calculated based on the sequence
#   number of the original packet. RFC does not specify the value of ACK
#   field that should be used. P0f will mark systems with ACK set to
#   zero with "(refused)", and "(refused 2)" for non-zero ACK fields.
#   Signature quirk combination: K0A or K0.
#
#   K0 is specific to NMAP OS fingerprinting, but the rest of the signature
#   depends on who is replying.
#
# - RST+ACK, SEQ number non-zero, ACK zero or non-zero. This is, by all means,
#   an illegal response. Some brain-damaged systems might generate it, though,
#   and I will try to mention them here. This might be anything. Reported as 
#   "(illegal-K)" or "(illegal-KA)", depending on ACK value. Quirk
#   combination is K or KA.
#
#   FreeBSD is known to send KA on a sunny day, so does Linux.
#   Not only it's insane to drop a connection with RST+ACK, but non-zero
#   SEQ number is plain incorrect.
#
# - RST, SEQ set, ACK zero. This is the proper RST ("unexpected traffic")
#   response that occurs whenever the remote host is not recognizing the
#   connection you're sending in. Happens after timeouts, network snafus,
#   dial-up reconnect, etc. You can trigger this kind of traffic by
#   using test/sendack.c. Reported as "(dropped)", signature quirks: empty.
#
# - RST, SEQ zero or ACK non-zero (or both). Once again, illegal but
#   often spotted. Reported as "(invalid-A)", "(invalid-0)", "(invalid-A0)".
#   Signature quirks: A, 0 or A0.
#
#   Windows is notorious for non-zero ACK on vanilla RST. Shoot on sight.
#
# Ok. That's it. RFC793 does not get much respect nowadays.
#
# Differences in comparison to p0f.fp data:
#
# - A new quirk, 'K', is introduced to denote RST+ACK packets (as opposed
#   to plain RST). This quirk is only compatible with this mode.
#
# - A new quirk, 'Q', is used to denote SEQ number equal to ACK number.
#   This happens from time to time in RST and RST+ACK packets, but 
#   is practically unheard of in other modes.
#
# - A new quirk, '0', is used to denote packets with SEQ number set to 0.
#   This happens on some RSTs, and is once again unheard of in other modes.
#
# - 'D' quirk is not a bug; some devices send verbose text messages
#   describing why a connection got dropped; it's actually suggested
#   by RFC1122.
#
#   NOTE: FreeBSD stack and some other implementations tend to quote
#   entire packets without a good reason in their RST responses. Gah!
#
# - 'A' quirk may show on RST+ACK ('K') signatures. Of course, Windows
#   would have non-zero ACK and no ACK flag, why not?
#

################################
# Connection refused - RST+ACK #
################################

0:255:0:40:.:K0A:Linux:2.0/2.2 (refused)
0:64:1:40:.:K0A:FreeBSD:4.8 (refused)
0:64:1:40:.:K0ZA:Linux:recent 2.4 (refused)
0:128:0:40:.:K0A:Windows:XP/2000 (refused)
0:128:0:40:.:K0UA:-Windows:XP/2000 while browsing (refused)

######################################
# Connection dropped / timeout - RST #
######################################

0:64:1:40:.:.:FreeBSD:4.8 (dropped)
0:255:0:40:.:.:Linux:2.0/2.2 (dropped)
0:64:1:40:.:Z:Linux:recent 2.4 (dropped)

# Freaks of nature:

0:128:1:40:.:QA:Windows:XP/2000 (dropped, lame)
0:128:1:40:.:A:-Windows:XP/2000 while browsing (1) (dropped, lame)
0:128:1:40:.:QUA:-Windows:XP/2000 while browsing (2) (dropped, lame)

S43:64:1:40:.:KA:AOL:proxy (dropped, very lame)
57456:64:1:40:.:KA:FreeBSD:4.8 (dropped, very lame)
*:64:1:52:N,N,T:KAT:Linux:2.4 (dropped, very lame)

