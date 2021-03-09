#!/usr/bin/perl

# This software is Copyright (c) 2011 Didier ARENZANA <darenzana-at-gmail.com>,
# and it is hereby released to the general public under the following terms:
# Redistribution and use in source and binary forms, with or without modification, are permitted, as long as the original
# author is referenced.

# Utility to bruteforce RADIUS shared-secret
# Usage: perl rad2john.pl <pcap files>
#
# application of two  methods described in http://www.untruth.org/~josh/security/radius/radius-auth.html :
# "3.3 User-Password Attribute Based Shared Secret Attack" and
# "3.1 "Response Authenticator Based Shared Secret Attack"

# For attack 3.3 :
# we try authentications using a known password, and sniff the radius packets to a pcpap file.
# This script reads access-request in the pcap file, and dumps the md5(RA+secret) and RA, in a john-friendly format.
# The password must be always the same, be less then 16 bytes long, and entered in the $PASSWORD variable below.
# The user names used during this attack must be entered in @LOGINS below.

# For attack 3.1:
# we don't need to try authentications. Just sniff the radius packets in a pcap file.
# This script reads the pcap file, matches radius responses with the corresponding requests,
# and dumps md5 and salt as needed.

# This script assumes there is one radius secret per client IP, that does not change during the whole time of packet dump.
# so it will only dump one couple of matching (salt, md5) for each distinct client IP adress.
# attack 3.3 takes precedence to attack 3.1, because the salt will be shorter.
# set variable $UNIQUE to 0 to disable this behavior.

use warnings ;
use strict ;

use Net::Pcap ;
use NetPacket::IP qw(:protos);
use NetPacket::UDP;
use NetPacket::Ethernet;

use Net::Radius::Dictionary ;
use Net::Radius::Packet ;

use Data::Dumper ;
$Data::Dumper::Useqq = 1 ;

# The password used during the attack
my $PASSWORD = '1' ;
# The user logins used during the attack
my @LOGINS = ( 'crack', 'toto') ;
# Set to 0 to disable unicity of client IPs in the output file
my $UNIQUE = 1 ;

my %VALID_LOGIN ;
$VALID_LOGIN{$_} = 1 foreach (@LOGINS) ;

# storage for Access-Requests. keys: srcip-ID, values: Request Auth.
my %requests ;
my %dumped_ips ;

my $dict  = new Net::Radius::Dictionary "dictionary.rfc2865" ;

foreach my $filename ( @ARGV ) {
    %requests = () ; #comment this line if request and matching responses can be in different files
    read_file($filename) ;
}

sub read_file {
    my ($filename) = @_ ;
    my ($err, $object,$filter) ;

    $object = Net::Pcap::open_offline($filename, \$err) ;
    if (defined $object ) {
        print STDERR "Processing $filename\n" ;
    } else {
        print STDERR "unable to read file $filename - $err\n" ;
        return ;
    }

    Net::Pcap::compile( $object,
        \$filter,'udp port 1812',
        0, 0
        ) && die 'Unable to compile packet capture filter';

    Net::Pcap::setfilter($object, $filter) &&
        die 'Unable to set packet capture filter';

    Net::Pcap::loop($object, -1, \&process_packet, Net::Pcap::datalink($object)) ; # || die "Unable to read packet : " . Net::Pcap::geterr($object) ;

    Net::Pcap::close($object) ;
}

sub process_packet {
    my ($linktype, $header, $packet) = @_ ;
    my ($iner_data, $protocol) ;

    #print join (" ", $header->{len}, $header->{tv_sec}, $header->{tv_usec}) . "\n" ;
    #print Dumper($header, $packet) ;

    if ($linktype==0) {
        # loopback - check if it's IP protocol
        $protocol = unpack("V", substr($packet, 0, 4)) ;
        if ($protocol != 2) {
            print STDERR "loopback protocol $protocol not supported.\n" ;
            return ;
        }
        $iner_data=substr($packet, 4) ;
    } elsif ($linktype==1) {
        # ethernet
        my $ether = NetPacket::Ethernet->decode($packet) ;
        $protocol = $ether->{'type'} ;
        if ( $protocol != 0x800 ) {
            print STDERR "ethernet protocol $protocol not supported.\n" ;
            return ;
        }

        $iner_data = NetPacket::Ethernet::strip($packet);
    } elsif ($linktype == 113) {
        # LINUX_SLL "cooked capture"
        $protocol = unpack("n", substr($packet, 14, 2));
        if ($protocol == 0x0800) {
            $iner_data = substr($packet, 16);
        } else {
            print STDERR "cooked capture with protocol $protocol not supported.\n";
            return;
        }
    } else {
        print STDERR "Link type $linktype not supported.\n" ;
        return ;
    }

    # we should have an IP packet in $iner_data
    my $ip  = NetPacket::IP->decode($iner_data);
    if ($ip->{proto} != 17) {
        # the filter should have sent only UDP packets... what is going on?
        print STDERR "IP protocol field is not 17! file format error?\n" ;
        print STDERR Dumper(\$ip) ;
        die ;
    }

    # We now have an UDP packet in $ip->{data}
    my $udp = NetPacket::UDP->decode($ip->{'data'});

    my $radius= new Net::Radius::Packet($dict, $udp->{'data'});
    $radius->show_unknown_entries(0) ;

    process_radius($ip, $radius, $udp->{'data'}) ;
}


sub process_radius {
    my ($ip, $rad, $udpdata) = @_ ;

    local $_= $rad-> code ;

    if ( /Access-Request/ ) {
        dump_access_request(
            $ip->{'src_ip'},
            $rad->attr('User-Name'),
            $rad->authenticator(),
            $rad->attr('User-Password')
        ) if defined($VALID_LOGIN{$rad->attr('User-Name')}) ;

        $requests{$ip->{'src_ip'}. '-' . $rad->identifier()} = $rad->authenticator() ;
    }
    elsif (/Access-Accept/ || /Access-Challenge/ || /Access-Reject/) {
        my $key=$ip->{'dest_ip'}. '-' . $rad->identifier() ;
        print STDERR $_." ".($key)."\n";
        return unless defined($requests{$key}) ;
        dump_response($ip->{'dest_ip'}, $requests{$key}, $rad, $udpdata) ;
    }
}

sub dump_response {
    # Extract md5 hash from the response packet,
    # and build salt from the response packet and the corresponding request authenticator
    my ($ip, $req_ra, $rad, $udpdata) = @_ ;

    return if ($UNIQUE && defined ($dumped_ips{$ip})) ;

    # extract the hash
    my $hash = $rad->authenticator() ;

    #extract the packet raw data to get the salt
    my $salt= $udpdata;
    #replace Response Authenticator with the Request Authenticator
    substr($salt, 4, 16)=$req_ra ;

    my $type = '1009';
    if (length($salt) > 16) { $type = '1017'; }
    print $ip . ':$dynamic_' . $type . '$' .
        unpack('H*', $hash) .
        '$HEX$' . unpack('H*', $salt) .
        "\n" ;

    $dumped_ips{$ip} = 'reply' ;
}

sub dump_access_request {
    # Extract the md5 hash and salt from the packet
    # and dump them in 'joomla' form.
    my ($ip, $login, $ra, $hashed) = @_ ;

    return if ($UNIQUE && defined ($dumped_ips{$ip}) && ($dumped_ips{$ip} eq 'request')) ;

    print $ip . ':$dynamic_1008$' .
        # the RADIUS User-Password attribute contains MD5(RA+secret) XOR password
        # we need to xor it to get back MD5(RA+secret)
        unpack("H*", $hashed ^ $PASSWORD) .
        '$HEX$' . unpack("H*", $ra) .
        "\n" ;

    $dumped_ips{$ip} = 'request' ;
}
