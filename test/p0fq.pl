#!/usr/bin/perl

# p0fq.pl - sample p0f query interface
# ------------------------------------
# 
# Just to show how things should be done, and perhaps to provide
# a truly ineffective way of querying p0f from shell scripts and
# such.
# 
# If you want to query p0f from a production application, just
# implement the same functionality in your code. It's perhaps 10
# lines.
# 
# Copyright (C) 2004 by Aurelien Jacobs <aurel@gnuage.org>

use strict;
use IO::Socket;
use Net::IP;

my $QUERY_MAGIC = 0x0defaced;
my $QTYPE_FINGERPRINT = 1;

die "usage: p0fq.pl p0f_socket src_ip src_port dst_ip dst_port"
  unless $#ARGV == 4;

# Convert the IPs and pack the request message
my $src = new Net::IP ($ARGV[1]) or die (Net::IP::Error());
my $dst = new Net::IP ($ARGV[3]) or die (Net::IP::Error());
my $query = pack("L L L N N S S", $QUERY_MAGIC, $QTYPE_FINGERPRINT, 0x12345678,
                 $src->intip(), $dst->intip(), $ARGV[2], $ARGV[4]);

# Open the connection to p0f
my $sock = new IO::Socket::UNIX (Peer => $ARGV[0],
                                 Type => SOCK_STREAM);
die "Could not create socket: $!\n" unless $sock;

# Ask p0f
print $sock $query;
my $response = <$sock>;
close $sock;

# Extract the response from p0f
my ($magic, $id, $type, $genre, $detail, $dist, $link, $tos, $fw,
    $nat, $real, $score, $mflags, $uptime) =
  unpack ("L L C Z20 Z40 c Z30 Z30 C C C s S N", $response);
die "Bad response magic.\n" if $magic != $QUERY_MAGIC;
die "P0f did not honor our query.\n" if $type == 1;
die "This connection is not (no longer?) in the cache.\n" if $type == 2;

# Display result
print "Genre    : " . $genre . "\n";
print "Details  : " . $detail . "\n";
print "Distance : " . $dist . " hops\n";
print "Link     : " . $link . "\n";
print "Uptime   : " . $uptime . " hrs\n";
