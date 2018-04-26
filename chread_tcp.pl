#!/usr/bin/perl
#
# chread_tcp.pl -D <some-very-short-only-tcp-PCAP>-chr-i-H-r.d/ \
#		-i -H -r <some-very-short-only-tcp-PCAP>.pcap
#	or similar. See orig Chaosreader script for Help
#
#				Copyright (c) 2018 Miroslav Rovis
#
#	Derived from Chaosreader.
#	15-Jun-2014, ver 0.96		https://github.com/brendangregg/Chaosreader
#	(by: Brendan Gregg, Indian Larry, Jens Lechtenbörger, Pavel Hančar, Pex)
#
#	According to original's license, this derived work is best released also
#	under same license:
#				GNU GPLv3 or later
#
#	This is my (Miroslav Rovis) Perl practicing copy. Learning Perl. Lots of
#	dirt and noise. You have been warned.
#
#	But this could be useful for other (hardworking) newbies to Perl... Along
#	with lots of plain perldoc pages reading where necessary. And it also could
#	be useful in learning about the TCP-related networking matters.
#
#	Why am I doing this? Because I need to identify perl code of Chaosreader
#	suitable to be modified, or my new work based on it, that can work on
#	extracted SSL TCP streams. Because Chaosreader can't extract SSL streams,
#	only plain HTTP TCP streams.
#	My tshark-streams program:
#	https://github.com/miroR/tshark-streams
#	can extract TCP streams, both plain and SSL. But extracting the streams,
#	that Bash script deploying Tshark, is all it does. I want to create a
#	script (based on Chaosreader code) which would then extract data, i.e.
#	mainly files of all kinds, from SSL streams (and only maybe present them
#	with HTML like Chaosreader does for plain HTTP traffic).
#
#	And to be able to understand the needed Chaosreader code, I've removed a
#	lot of code that wouldn't serve my future script.
#
#	The following is logs kept as I was reading and removing the code. Too
#	dirty to have been put into own git versions, but it was a lot of tries and
#	versions.
#	X11 VNC all removed, Bench all removed.
#	Standalone all removed. Various replay/playback all removed.
#	Remove sub Set_MIME_Types? Now when finds "application/atom+xml" saves w/
#	.xml, previously w/ .html. How to change extension in this perl script.
#	Where?
#	Removed subs: Load_Etc_Services and Set_IP_Protocols. Getting:
#	"Unkown Content-Type text/html;.  May want to extend MIME types."
#	"Unkown Content-Type application/ocsp-response.  May want to extend MIME types."
#	Removed: Set_ICMP_Types, Read_Snoop_Record
#	Removed all snoop.
#	Removed Print_Welcome
#	Somewere not long before the last line above I started inserting new,
#		mostly "print..." often after unpack(...", lines, to understand the
#		code. Will make this copy available, may help some other new explorer
#		of Perl.  (Practice by running it on (very) small traces first.)
#	Removed Wireless
#	Apparently the $llc_<something> were all wireless-related too. Removed.
#	Set "$Arg{debug} = 1;" (default 0)
#	NOTE: in some testing I revert it to default 0, my (kind of) debugging
#		tells me way more, from commit d5a188567eccfdce18f9d8987b8d88cff2d86bb6
#		(chread_tcp.pl of tag v0.10 onwards, until possibly I convert this
#		sript into something else or I create something new with the knowledge
#		gained)
#
#	Removed code related to Net::DNS::Packet.
#	Removed UDP, ICMP
#	Removed Save_FTP_File, Save_SMTP_Emails
#	Removed most (all) previous "print..." often after unpack(...". lines. A
#	few are left (but commented out) so the method I deployed for studying the
#	code may be used by others.
#	
#	Re-pasted __END__ and %IP and %TCP data types cheatsheet
#	Created a sub logger into which to print %IP and %IP
#	And a binner (for binary snippets) for, e.g. $header_rec. Very clumsy
#	but explains some for me, upon manual comparisons/inspections on results.
#
#	Replaced chaotic spaces with (possibly) proper indentation tabbing.
#

#	If these placed and uncommented in Chaosreader proper, that orig script
#	won't work either. I (hopefully) haven't introduced more
#	errors/inconsistencies... (Could it be just obsolete code in Chaosreader?)
#use strict;
#use warnings;
use Getopt::Long;
use IO::Uncompress::Gunzip qw(gunzip $GunzipError);
use IO::Uncompress::Inflate qw(inflate $InflateError) ;
use IO::Uncompress::RawInflate qw(rawinflate $RawInflateError) ;
# needed for logger/binner unique filename creation
use Time::HiRes qw( clock_gettime usleep TIMER_ABSTIME );

#
$integerSize = length(pack('I',0));	# can make a difference for tcpdumps
$the_date = scalar localtime();		# this is printed in the reports
$WRAP = 108;						# wordwrap chars
$| = 1;								# flush output

#
# --- Arguments ---
#
&Process_Command_Line_Arguments();

#
#  Load some lookup tables for number -> name translations.
#
&Set_Result_Names();

############################
# --- MODE only Normal --- #
############################

#
#  Process log files,
#
if ($Arg{normal}) {
	#
	#  Initial values
	#
	$frame = 0; $number = 0;
	%IP = (); %TCP = (); %Hex = ();
	
	### Print version
	#&Print_Welcome();
	
	######################################
	# --- INPUT - Read Packet Log(s) ---
	#
	
	foreach $filename (@{$Arg{infiles}}) {
		#
		#  Check input file type and Open
		#
		&Open_Input_File($filename);
		
		#
		#  Read though the entire input file, saving all packet
		#  data in memory (mainly %TCP).
		#
		&Read_Input_File();
	}
	
	
	#############################################
	# --- OUTPUT - Process TCP Sessions ---
	#
	
	### cd to output
	&Chdir($Arg{output_dir});
	
	### Determine Session and Stream time order
	%Index = (); %Image = (); %ExtImage = (); %GETPOST = ();
	&Sort_Index_By_Time();
	
	#
	#  Process %TCP and create session* output files, write %Index
	#
	&Process_TCP_Sessions();
	
}



#####################
# --- SUBROUTINES ---

# (Most of these subroutines are used as shortcuts to code, not traditional
#  scoped subroutines as with other languages)



# Open_Input_File - open the packet trace specified. This checks the header
#	of the file to determine whether it is a tcpdump/libpcap
#	trace (including several styles of tcpdump/libpcap).
#
	
sub Open_Input_File {
	
	my $infile = shift;
	my ($length,$size);
	
	# subs logger and binner are placed after this function because their
	# naming is based on $infile, and this is non-expert preparation of context
	# for them
	my $s;
	$s = clock_gettime();
	$s =~ /(\d*)\.\d*/ ;
	$s = $1 ;
	my $my_log ;
	my $my_bin ;
	$my_log = "" ;
	$my_log_dir = "" ;
	$my_bin = "" ;
	$my_log .= "$infile-" ;
	$my_log =~ s/\.pcap// ;			# Needs to be adapted for traces w/
									# other extensions
	$my_log .= $s ;
	$my_log_dir .= $my_log ;
	$my_log_dir .= ".d" ;
	mkdir $my_log_dir ;
	$my_log_dir .= "/" ;
	$my_log .= ".log" ;

	&logger("This log ($my_log) created for printing %IP and %TCP");
	&logger("\tfor own understanding of the core functionality of this script,");
	&logger("\tfor text, with sub logger.");
	&logger("There can also be dir $my_log_dir");
	&logger("\tfor binary snippets/data, with sub binner");
	&logger("==================================================");

	
	print "Opening, $infile\n\n" unless $Arg{quiet};
	
	#
	#  Open packet trace
	#
	open(INFILE,$infile) || die "Can't open $infile: $!\n";
	binmode(INFILE);	# for backward OSs
	#
	#  Fetch header
	#
	$length = read(INFILE,$header,8);
	&logger("\$length = read(INFILE,\$header,8");
	&binner("$header");
	
	### Print status
	print "Reading file contents,\n" unless $Arg{quiet};
	$SIZE = -s $infile;
	
	#
	#  Try to determine if this is a tcpdump file
	#
	($ident) = unpack('a8',$header);
	&logger("\$ident = the_unpack('a8',\$header)");
	&binner("$ident");
	
	if ($ident =~ /^\241\262\303\324|^\324\303\262\241/ ||
		$ident =~ /^\241\262\315\064|^\064\315\262\241/) {
		
		$TYPE = "tcpdump";
		$ident = unpack('a4',$header);  # try again
		# standard/modified defines style, 1/2 defines endian
		if ($ident =~ /^\241\262\303\324/) { $STYLE = "standard1"; }
		if ($ident =~ /^\324\303\262\241/) { $STYLE = "standard2"; }
		if ($ident =~ /^\241\262\315\064/) { $STYLE = "modified1"; }
		if ($ident =~ /^\064\315\262\241/) { $STYLE = "modified2"; }
		if ($STYLE =~ /1$/) {
			# reread in big-endian
			($ident,$major,$minor) = unpack('a4nn',$header);
		} else {
			# reread in little-endian
			($ident,$major,$minor) = unpack('a4vv',$header);
			&logger("\$STYLE: $STYLE, \$major: $major, \$minor: $minor");
		}
		
		#
		#  Check tcpdump header carefully to ensure this is ver 2.4.
		#
		if ($major != 2 && $minor != 4) {
			#
			#  Die if this is an unknown version. (there could
			#  be new vers of tcpdump/libpcap in the future).
			#
			print STDERR "ERROR09: Wrong tcpdump version ";
			print STDERR "($version.$type).\n(expected 2.4).\n";
			exit 1;
		}
		#
		#  Nudge the filehandle past the rest of the header...
		#
		$length = read(INFILE,$header_rest,16);
		&logger("\$length = read(INFILE,\$header_rest,16");
		&logger("$length = read(INFILE,\$header_rest,16)");
		&binner("$header_rest");
	
	} else {
		#
		#  Die - unknown file format
		#
		print STDERR "ERROR10: Input doesn't look like a tcpdump ";
		print STDERR "output file.\n\tIf it is tcpdump, it ";
		print STDERR "may be a wrong or new version.\n";
		exit 1;
	}
	
	### Record the filename into the global %Arg
	$Arg{infile} = $infile;
}

sub logger {
	if ( $my_log_dir =~ /\.\.\// ) {
		$my_log_dir =~ /\.\.\/(\S*)/ ;
		$my_log = $1;
	}
	$my_log = $my_log_dir;
	$my_log =~ s/\.d\/// ;
	$my_log .= ".log" ;
	if ( stat($my_log_dir) ) {
		# nothing to do
	} else {
		my $up_chdir = "..";
		$my_log_tmp = $up_chdir ;
		$my_log_tmp .= "/" ;
		$my_log_tmp .= $my_log ;
		$my_log = $my_log_tmp ;
	}
	$s = clock_gettime();
	$s =~ /\d*\.(\d*)/ ;
	$usec=$1;
	my $logmessage = shift;
	open my $logfile, ">>", "$my_log" or die "Could not open $my_log: $!";
	say $logfile $logmessage;
}

sub binner {	# logger above was initially from perlintro, and binner was
				# copy-paste-n-modify on it, with a pun ending in -er.
				# From version v0.10, binner works to usec level
				# filenaming, with inclusion of tcpdump timestamps.
				# From version v0.11 all their snippets/data is placed in a
				# dir named as the logger log, just s/.log/.d/ .
	( $my_log_dir ) ? $my_bin = $my_log_dir : ( $my_bin =~ s/($my_log_dir)/..\/\1/ ) ;
	$s = clock_gettime();
	$s =~ /\d*\.(\d*)/ ;
	$usec=$1;
	$my_bin .= $usec;
	if ( $tcpdump_seconds ) {
		$my_bin .= ".";
		$my_bin .= $tcpdump_seconds ; 
	} else {
		if ( $packet ) {
			$my_bin .= ".";
			$my_bin .= $packet ; 
		}
	} 
	if ( $tcpdump_msecs ) {
		$my_bin .= ".";
		$my_bin .= $tcpdump_msecs ;
	} else {
		#print "no \$tcpdump_seconds yet/or undefined (no harm)\n";
	} 
	$my_bin .= ".bin";
	my $binmessage = shift;
	open my $binfile, ">>", "$my_bin" or
		$my_bin =~ s/(\S*)/\.\.\/$1/ ;
		open my $binfile, ">>", "$my_bin"
		or die "Could not open $my_bin: $!";
	print $binfile $binmessage;
	&logger("created $my_bin");
}


# Read_Input_File - this subroutine loops through the records in the packet
#  log, storing all the TCP into %TCP. (see the end
#  of the program for the structure of these data types).
#
sub Read_Input_File {
	my ($trailers,$pppoe_verNtype,$pppoe_code,$pppoe_id,$pppoe_length,
	 $ppp_protocol,$bytes,$counter,$packets);
	
	local $packet = 0;			# counter
	# if it is not snoop (is snoop around at all nowadays?), it's tcpdump, and
	# then, as per the orig:
	$bytes = 24;
	
	#
	# --- Pass #1, Store IP data in memory (%IP) --
	#
	while (1) {
		#
		# --- Read Record from Log ---
		#
		&Read_Tcpdump_Record();		# will "last" on error
		$packet_data = $tcpdump_data;
		$packet_time = $tcpdump_seconds;
		$packet_timefull = $tcpdump_seconds + $tcpdump_msecs/1000000;
		$record_size = $tcpdump_length + ($integerSize * 2 + 8);
		&logger("\$record_size = \$tcpdump_length + (\$integerSize * 2 + 8);");
		&logger("$record_size = $tcpdump_length + ($integerSize * 2 + 8);");
		
		### Print status summary
		unless ($Arg{quiet}) {
			$bytes += $record_size;
			if (($packet % 16) == 0) {
				printf("%s %2.0f%% (%d/%d)","\b"x24,
				 (100*$bytes/$SIZE),$bytes,$SIZE); print "\n";
			}
		}
		
		#
		# --- Parse TCP/IP layers (a little ;) ---
		#
		#-------------------------------------------------------------------
		#  Wireless, 802.11b
		#
		#$decoded = 0;		# this flag is true if wireless was found
		#	[...]
		#	$decoded = 1;	# remember we did this
		
		#-------------------------------------------------------------------
		#
		#  Ethernet, 802.3
		#
		
		### Unpack ether data
		($ether_dest,$ether_src,$ether_type,$ether_data) =
			unpack('H12H12H4a*',$packet_data) unless $decoded;
		&logger("\$ether_dest,\$ether_src,\$ether_type = the_unpack('H12H12H4a*',\$packet_data)");
		&logger("$ether_dest,$ether_src,$ether_type ...");
		
		#
		#  Process extended Ethernet types (PPPoE; wireless and VLAN removed)
		#
		
		### PPPoE
		if ($ether_type eq "8864") {
			($pppoe_verNtype,$pppoe_code,$pppoe_id,$pppoe_length,
			 $ppp_protocol,$ether_data) = unpack("CCnnna*",$ether_data);
			
			### Skip anything but data (we just want data - code 0)
			next if $pppoe_code != 0;
			
			# (May like to add code here later to process $ppp_protocol,
			# eg, to process LCP).
		}
		### VLAN tagged
		elsif ($ether_type eq "8100") {
			($vlan_PCP, $orig_ether_type, $ip_rest) = unpack('H4H4a*', $ether_data);
			$ether_data = $ip_rest;
		}
		
		elsif (($ether_type ne "0800") && ($ether_type ne "86dd")) {
			# JL: Try linux cooked capture
			($lptype,$lladdr_type,$lladdr_len,
			$ether_src,$ll_dummy,$ether_type,$ether_data) =
			unpack('nnnH12nH4a*',$packet_data) unless $decoded;
			&logger("\$lptype,\$lladdr_type,\$lladdr_len,\$ether_src,\$ll_dummy,\$ether_type");
			&logger("the_unpack('nnnH12nH4a*',\$packet_data");
			&logger("$lptype,$lladdr_type,$lladdr_len,$ether_src,$ll_dummy,$ether_type");
			&logger("\$ether_data:");
			&binner("$ether_data");
			&logger("--------------------------------------------------");
			if ($ether_type ne "0800") {
			next;
			}
		}
		
		#-------------------------------------------------------------------
		#
		#  IP
		#
		
		### Check for IP ver
		($ip_verNihl,$ip_rest) = unpack('Ca*',$ether_data);	# ihl: ip header length
		&logger("\$ip_verNihl: $ip_verNihl");
		$ip_ver = $ip_verNihl & 240;
		&logger("$ip_verNihl & 240");
		&logger("\$ip_ver: $ip_ver");
		&logger("\$ip_ver = \$ip_ver shift 4:");
		&logger("$ip_ver = $ip_ver >> 4");
		$ip_ver = $ip_ver >> 4;
		&logger("\$ip_ver: $ip_ver");
		
		if ($ip_ver == 4) {
		
			#-----------------------------------------------------------
			#
			#  IPv4
			#
			
			### Unpack IP data
			($ip_verNihl,$ip_tos,$ip_length,$ip_ident,$ip_flagNfrag,
				$ip_ttl,$ip_protocol,$ip_checksum,@ip_src[0..3],
				@ip_dest[0..3],$ip_data) = unpack('CCnnnCCa2CCCCCCCCa*',
				$ether_data);
			&logger("\$ip_verNihl,\$ip_tos,\$ip_length,\$ip_ident,\$ip_flagNfrag,\$ip_ttl,");
			&logger("\$ip_protocol,\$my_ip_checksum,\ at ip_src[0..3],at ip_dest[0..3],\$ip_data");
			&logger("= the_unpack(CCnnnCCa2CCCCCCCCa*,\$ether_data");
			my $my_ip_checksum = unpack('H*', $ip_checksum);
			&logger("$ip_verNihl,$ip_tos,$ip_length,$ip_ident,$ip_flagNfrag,$ip_ttl,");
			&logger("$ip_protocol,$my_ip_checksum,@ip_src[0..3],@ip_dest[0..3],\$ip_data");
			
			### Get frag and flag data
			&logger("\$ip_flagNfrag: $ip_flagNfrag");
			&logger("\$ip_frag = \$ip_flagNfrag and 8191");
			$ip_frag = $ip_flagNfrag & 8191;
			&logger("$ip_flagNfrag & 8191");
			&logger("\$ip_frag: $ip_frag");
			&logger("\$ip_flag = \$ip_flagNfrag and 57344");
			&logger("$ip_flagNfrag & 57344");
			$ip_flag = $ip_flagNfrag & 57344;
			&logger("\$ip_flag: $ip_flag");
			&logger("\$ip_flag = \$ip_flag shift 13");
			$ip_flag = $ip_flag >> 13;
			&logger("\$ip_flag: $ip_flag");
			&logger("\$ip_MF = \$ip_flag and 1");
			&logger("$ip_flag & 1");
			$ip_MF = $ip_flag & 1;					# MF: more fragments
			&logger("\$ip_MF: $ip_MF");
			### Strip off IP options if present
			&logger("\$ip_ihl = \$ip_verNihl: and 15");
			&logger("$ip_verNihl & 15");
			$ip_ihl = $ip_verNihl & 15;
			&logger("\$ip_ihl = $ip_ihl");
			&logger("\$ip_ihl = \$ip_ihl left shift 2");
			&logger("$ip_ihl << 2");
			$ip_ihl = $ip_ihl << 2;
			&logger("\$ip_ihl = $ip_ihl");
			&logger("\$ip_options_num = \$ip_ihl - 20");
			&logger("$ip_ihl - 20");
			$ip_options_num = $ip_ihl - 20;
			&logger("\$ip_options_num = $ip_options_num");
			if ($ip_options_num > 0) {
				($ip_options,$ip_data) =
				unpack("a${ip_options_num}a*",$ip_data);
			}
			
			### Strip off Ethernet trailers
			$ip_dlength = $ip_length - $ip_options_num - 20;
			($ip_data,$trailers) = unpack("a${ip_dlength}a*",$ip_data);
			&logger("\$ip_dlength = \$ip_length - \$ip_options_num - 20");
			&logger("$ip_dlength = $ip_length - $ip_options_num - 20");
			&logger("(\$ip_data,\$trailers) = the_unpack (a\${ip_dlength}a*,\$ip_data);");
			&logger("\$ip_data:");
			&binner("$ip_data");
			&logger("--------------------------------------------------");
			
			### Build text strings of IP addresses
			$ip_src = sprintf("%u.%u.%u.%u",@ip_src);
			$ip_dest = sprintf("%u.%u.%u.%u",@ip_dest);
			&logger("\$ip_src,\$ip_dest: $ip_src,$ip_dest");
			
		} elsif ($ip_ver == 6) {
			
			#-----------------------------------------------------------
			#
			#  IPv6
			#
			($ip_verNihl,$ip_flow,$ip_length,$ip_next,$ip_hop,
			 @ip_src[0..15],@ip_dest[0..15],$ip_data) =
			 unpack('Ca3nCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCa*',
			 $ether_data);
			$ip_protocol = $ip_next;
			
			### Build text strings of IP addresses
			$ip_src = sprintf("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x",
			 @ip_src);
			$ip_dest = sprintf("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x",
			 @ip_dest);
			
			### Compress IPv6 text Address
			$ip_src =~ s/:00:/:0:/g;
			$ip_src =~ s/:00:/:0:/g;
			$ip_dest =~ s/:00:/:0:/g;
			$ip_dest =~ s/:00:/:0:/g;
			$ip_src =~ s/(:0)+/::/;
			$ip_dest =~ s/(:0)+/::/;
			
			
			#
			#  Check for IPv6 Fragmentation (embedded)
			#
			if ($ip_protocol == 44) {
				($ip_next,$ip_reserved,$ip_fragNmf,$ip_ident,$ip_data)
				 = unpack('CCnNa*',$ip_data);
				 $ip_protocol = $ip_next;
				$ip_MF = $ip_fragNmf & 1;
				$ip_frag = $ip_fragNmf >> 3;
			} else {
				$ip_MF = 0;
				$ip_ident = 0;
				$ip_frag = 0;
			}
		
		} else {
			### Not IPv4 or IPv6 - could be LCP (skip for now)
			next;
		}
		
		### Generate unique IP id (not just the ident)
		$ip_id = &Generate_IP_ID($ip_src,$ip_dest,$ip_ident);
		&logger("\$ip_id: $ip_id");
		#
		#  Store IP data in %IP so we can do frag reassembly next
		#
		if (! defined $IP{id}{$ip_id}{StartTime}) {
			$IP{time}{$packet_timefull}{ver} = $ip_ver;
			$IP{time}{$packet_timefull}{src} = $ip_src;
			$IP{time}{$packet_timefull}{dest} = $ip_dest;
			$IP{time}{$packet_timefull}{protocol} = $ip_protocol;
			$IP{time}{$packet_timefull}{frag}{$ip_frag} = $ip_data;
			if ($tcpdump_drops) {
				$IP{time}{$packet_timefull}{drops} = 1;
			}
			#
			#  If there are more fragments, remember this starttime
			#
			unless (($ip_MF == 0) && ($ip_frag == 0)) {
				$IP{id}{$ip_id}{StartTime} = $packet_timefull;
				#&logger("\$IP{id}{\$ip_id}{StartTime} = \$packet_timefull: \
				#	$IP{id}{$ip_id}{StartTime} = $packet_timefull");
			}
			if (($ip_MF == 1) || ($ip_frag > 0)) {
				$IP{time}{$packet_timefull}{fragged} = 1;
			}
			&logger("\$IP{id}{\$ip_id}{StartTime} = \$packet_timefull: \
				$IP{id}{$ip_id}{StartTime} = $packet_timefull");
			&logger("\$IP{id}{$ip_id}{StartTime}: $IP{id}{$ip_id}{StartTime}");
		} else {
			$start_time = $IP{id}{$ip_id}{StartTime};
			&logger("\$start_time = \$IP{id}{\$ip_id}{StartTime}: \
				$start_time = $IP{id}{$ip_id}{StartTime}");
			$IP{time}{$start_time}{frag}{$ip_frag} = $ip_data;
			if ($tcpdump_drops) {
				$IP{time}{$packet_timefull}{drops} = 1;
			}
			if ($ip_MF == 0) {
				#
				#  Complete this IP packet. This assumes that the
				#  last frag arrives last.
				#
				undef $IP{ident}{StartTime}{$ip_id};
			}
		}
		$packet++;
	}
	
	close INFILE;
	
	### Print status summary
	unless ($Arg{quiet}) {
	printf("%s %2.0f%% (%d/%d)","\b"x24,
	 100,$bytes,$SIZE);
	print "\nReassembling packets,\n";
	}
	
	
	
	###################################################################
	#  --- Pass #2, Reassemble IP data in %IP; create %TCP ---
	#
	
	&Print_Header1() if $Arg{debug};
	$packets = $packet;
	$packet = 0;
	# sub Read_Tcpdump_Record already run, these are at the last values
	# of the loop, binner(,_d) filename creation had better take the
	# number of the packet instead:
	undef $tcpdump_seconds;
	undef $tcpdump_msecs;
	
	@Times = sort { $a <=> $b } ( keys(%{$IP{time}}) );
	foreach $time (@Times) {
		
		### Print status summary
		unless ($Arg{quiet}) {
			if (($packet % 16) == 0) {
				printf("%s %2.0f%% (%d/%d)","\b"x32,
				 (100*$packet/$packets),$packet,$packets); print "\n";
			}
		}
		
		#
		#  Get IP data from %IP
		#
		$ip_ver = $IP{time}{$time}{ver};
		$ip_src = $IP{time}{$time}{src};
		$ip_dest = $IP{time}{$time}{dest};
		$ip_protocol = $IP{time}{$time}{protocol};
		$drops = $IP{time}{$time}{drops};
		undef $ip_data;
		# Try 'n print %IP. The hash is %{$IP{time}} (see 20 lines above)?
		# But this goes on based on "Store IP data in %IP so..." some 60 lines
		# above. Uncomment for testing/learning/figuring out.
		if (! defined $IP_time_hash_printed ) {
			for my $time ( sort { $a <=> $b } ( keys(%{$IP{time}})) ) {
				&logger("\$time: $time");
				&logger("\$time => \$IP{time}{\$time}{ver}");
				&logger("$time => $IP{time}{$time}{ver}");
				&logger("\$time => \$IP{time}{\$time}{src}");
				&logger("$time => $IP{time}{$time}{src}");
				&logger("\$time => \$IP{time}{\$time}{dest}");
				&logger("$time => $IP{time}{$time}{dest}");
				&logger("\$time => \$IP{time}{\$time}{protocol}");
				&logger("$time => $IP{time}{$time}{protocol}");
				&logger("\$time => \$IP{time}{\$time}{frag}{\$ip_frag}");
				&binner("$IP{time}{$time}{frag}{$ip_frag}");
				&logger("--------------------------------------------------");
			}
			$IP_time_hash_printed = 1;
		}

		#
		#  Reassemble IP frags
		#
		if (defined $IP{time}{$time}{fragged}) {
			@IP_Frags = sort {$a <=> $b} (keys(%{$IP{time}{$time}{frag}}));
			# Again, that's defined at "Store IP data in %IP so..." some 130
			# lines above with the line:
			# $IP{time}{$packet_timefull}{frag}{$ip_frag} = $ip_data;
			# However on the way to here there's also line:
			# undef $ip_data;
			# Also, we're in the loop "foreach $time (@Times) { ..."
			# But we may not reach here:
			print "##################################################";
			print "INSIDE AT IP_Frags = sort ... \n\n\n";
			print "##################################################";
            
			### If never recieved the start of the packet, skip
			if ($IP_Frags[0] != 0) { next; }
		
			foreach $ip_frag (@IP_Frags) {
				$ip_data .= $IP{time}{$time}{frag}{$ip_frag};
			}
		} else {
			$ip_data = $IP{time}{$time}{frag}{0};
			#print "We're at else outside at IP_Frags = sort ... \n\n\n";
			&logger("\$ip_data = \$IP{time}{\$time}{frag}{0}");
			&logger("\$ip_data:");
			&binner("$ip_data");
		}
		$length = length($ip_data);
		&logger("\$length = length(\$ip_data): $length");
		
		#
		# --- TCP ---
		#
		if ($ip_protocol == 6 && $Arg{output_TCP}) {
			&Process_TCP_Packet($ip_data,$ip_src,$ip_dest,$time,$drops);
		}
		
		#
		#  Skip packet if it isn't TCP (protocol = 6). (Will add routines for
		#  ARP, RARP later on)...
		#
		
		$packet++;
		
		### Memory Cleanup
		delete $IP{time}{$time};
		
	}
	
	### Memory Cleanup
	undef %IP;
	
	### Print status summary
	unless ($Arg{quiet}) {
		printf("%s %2.0f%% (%d/%d)\n","\b"x24,
			100,$packet,$packets);
	}
}



# Process_TCP_Packet - process a TCP packet and store it in memory. It takes
#	the raw ip data and populates the data structure %TCP. (and %Count).
#
sub Process_TCP_Packet {
	
	my $ip_data = shift;
	my $ip_src = shift;
	my $ip_dest = shift;
	my $time = shift;
	my $drops = shift;
	#my $copy;
	
	#-------------------------------------------------------------------
	#
	#  TCP
	#
	
	### Unpack TCP data
	($tcp_src_port,$tcp_dest_port,$tcp_seq,$tcp_ack,$tcp_offset,$tcp_flags,
		$tcp_header_rest,$tcp_data) = unpack('nnNNCCa6a*',$ip_data);
	&logger("\$tcp_src_port,\$tcp_dest_port");
	&logger("\$tcp_seq,\$tcp_ack,\$tcp_offset,\$tcp_flags");
	&logger("= the_unpack(nnNNCCa6a*,\$ip_data");
	&logger("$tcp_src_port,$tcp_dest_port");
	&logger("$tcp_seq,$tcp_ack,$tcp_offset,$tcp_flags");
	&logger("\$tcp_header_rest:");
	&binner("$tcp_header_rest");
	&logger("\$tcp_data:");
	&binner("$tcp_data");
	&logger("--------------------------------------------------");
	
	
	### Strip off TCP options, if present
	$tcp_offset = $tcp_offset >> 4;		# chuck out reserved bits
	&logger("\$tcp_offset = \$tcp_offset shift 4");
	&logger("\$tcp_offset: $tcp_offset");
	$tcp_offset = $tcp_offset << 2;		# now times by 4
	&logger("\$tcp_offset = \$tcp_offset shift left 2");
	&logger("\$tcp_offset: $tcp_offset");
	$tcp_options_num = $tcp_offset - 20;
	&logger("\$tcp_options_num = \$tcp_offset - 20");
	&logger("\$tcp_options_num = $tcp_options_num");
	if ($tcp_options_num > 0) {
		($tcp_options,$tcp_data) =
		 unpack("a${tcp_options_num}a*",$tcp_data);
	}
	
	### Fetch length and FIN,RST flags
	# It's not used at all, not even in the orig.
	#$tcp_length_data = length($tcp_data);
	$tcp_fin = $tcp_flags & 1;
	if ($tcp_fin != 0 ) {
		&logger("\$tcp_fin = $tcp_flags & 1");
		&logger("\$tcp_fin = $tcp_fin");
		}
	$tcp_syn = $tcp_flags & 2;
	if ($tcp_syn != 0 ) {
		&logger("\$tcp_syn = $tcp_flags & 2");
		&logger("\$tcp_syn = $tcp_syn");
	}
	$tcp_rst = $tcp_flags & 4;
	if ($tcp_rst != 0 ) {
		&logger("\$tcp_rst = $tcp_flags & 4");
		&logger("\$tcp_rst = $tcp_rst");
	}
	$tcp_ack = $tcp_flags & 16;
	if ($tcp_ack != 0 ) {
		&logger("\$tcp_ack = $tcp_flags & 16");
		&logger("\$tcp_ack = $tcp_ack");
	}
	
	#
	#  Generate $session_id as a unique id for this stream
	#  (this is built from host:port,host:port - sorting on port).
	#
	($session_id,$from_server) = &Generate_SessionID($ip_src,$tcp_src_port,
	 $ip_dest,$tcp_dest_port,"TCP");
	
	### Record direction if single SYN was seen
	if ($tcp_syn && ! $tcp_ack) {
		$TCP{id}{$session_id}{source} = $ip_src;
		$TCP{id}{$session_id}{source_port} = $tcp_src_port;
		# better repeat this,
		($session_id,$from_server) = &Generate_SessionID($ip_src,
			$tcp_src_port,$ip_dest,$tcp_dest_port,"TCP");
		# no harm, but number of finds times more lines
		#&logger("\$session_id: $session_id, \$from_server: $from_server");
	}
	
	#
	#  Flag this session as a Partial if tcpdump
	#  confesses to dropping packets.
	#
	$TCP{id}{$session_id}{Partial}++ if $drops;
	
	### Store size
	$TCP{id}{$session_id}{size} += length($tcp_data);
	&logger("\$TCP{id}{$session_id}{size}: $TCP{id}{$session_id}{size}");
	&logger("--------------------------------------------------");
	
	### Store the packet timestamp for the first seen packet
	if (! defined $TCP{id}{$session_id}{StartTime}) {
		$TCP{id}{$session_id}{StartTime} = $time;
		&logger("\$TCP{id}{\$session_id}{StartTime}: $TCP{id}{$session_id}{StartTime}");
		
		### Store other info once
		if ($from_server) {
			$TCP{id}{$session_id}{src} = $ip_dest;
			$TCP{id}{$session_id}{dest} = $ip_src;
			$TCP{id}{$session_id}{src_port} = $tcp_dest_port;
			$TCP{id}{$session_id}{dest_port} = $tcp_src_port;
		} else {
			$TCP{id}{$session_id}{src} = $ip_src;
			$TCP{id}{$session_id}{dest} = $ip_dest;
			$TCP{id}{$session_id}{src_port} = $tcp_src_port;
			$TCP{id}{$session_id}{dest_port} = $tcp_dest_port;
			&logger("\$TCP{id}{\$session_id}{src}: $TCP{id}{$session_id}{src}");
			&logger("\$TCP{id}{$session_id}{src}: $TCP{id}{$session_id}{src}");
			&logger("\$TCP{id}{\$session_id}{dest}: $TCP{id}{$session_id}{dest}");
			&logger("\$TCP{id}{$session_id}{dest}: $TCP{id}{$session_id}{dest}");
			&logger("\$TCP{id}{\$session_id}{src_port}: $TCP{id}{$session_id}{src_port}");
			&logger("\$TCP{id}{$session_id}{src_port}: $TCP{id}{$session_id}{src_port}");
			&logger("\$TCP{id}{\$session_id}{dest_port}: $TCP{id}{$session_id}{dest_port}");
			&logger("\$TCP{id}{$session_id}{dest_port}: $TCP{id}{$session_id}{dest_port}");
			&logger("\$TCP{id}{\$session_id}{size}: $TCP{id}{$session_id}{size}");
			&logger("\$TCP{id}{$session_id}{size}: $TCP{id}{$session_id}{size}");
		}
	}
	
	### Store the packet timestamp in case this is the last packet
	$TCP{id}{$session_id}{EndTime} = $time;
	#&logger("\$TCP{id}{\$session_id}{EndTime} = \$time: \
	#	$TCP{id}{$session_id}{EndTime} = $time");
	
	### Print status line
	printf "%6s  %-45s  %s\n",$packet,$session_id,$length
	 if $Arg{debug};
	
	
	#
	# --- Store Session Data in Memory ---
	#
	# Since TCP is usually the bulk of the data, we minimise
	# the number of copies of data in memory.
	
	if ($from_server) {
		#
		#  Populate %TCP{id}{}{time} with raw traffic by time.
		#  This is the master structure to store the data.
		#
		$TCP{id}{$session_id}{time}{$time}{data} .= $tcp_data;
		$TCP{id}{$session_id}{time}{$time}{dir} .= "A";
		&logger("A dir Process_TCP_Packet \$tcp_data:");
		&binner("$tcp_data");
		
		#
		#
		#  Populate %TCP{id}{}{Aseq} with server to client
		#  1-way raw traffic, with the TCP sequence number as
		#  the key (for future reassembly).
		#
		#  This is a pointer to the time structure above,
		#  to save on memory used (originally stored a
		#  duplicate copy of the data).
		#
		if ((! defined $TCP{id}{$session_id}{Aseq}{$tcp_seq}) ||
			(length(${$TCP{id}{$session_id}{Aseq}{$tcp_seq}}) <
			length($tcp_data))) {
			$TCP{id}{$session_id}{Aseq}{$tcp_seq} =
			 \$TCP{id}{$session_id}{time}{$time}{data};
		}
		
	} else {
		#
		#  Populate %TCP{id}{}{Btime} with raw 1-way traffic by time.
		#  This is the master structure to store the data.
		#
		$TCP{id}{$session_id}{time}{$time}{data} .= $tcp_data;
		$TCP{id}{$session_id}{time}{$time}{dir} .= "B";
		&logger("B dir Process_TCP_Packet \$tcp_data:");
		&binner("$tcp_data");
		
		#
		#
		#  Populate %TCP{id}{}{Bseq} with client to server
		#  1-way raw traffic, with the TCP sequence number as
		#  the key (for future reassembly).
		#
		#  This is a pointer to the time structure above,
		#  to save on memory used (originally stored a
		#  duplicate copy of the data).
		#
		if ((! defined $TCP{id}{$session_id}{Bseq}{$tcp_seq}) ||
		 (length(${$TCP{id}{$session_id}{Bseq}{$tcp_seq}}) <
		 length($tcp_data))) {
			$TCP{id}{$session_id}{Bseq}{$tcp_seq} =
			 \$TCP{id}{$session_id}{time}{$time}{data};
		}
	}
	#
	#  Populate %Hex{TCP}{} with data necessary to generate coloured HTML 2-way
	#  traffic, if needed.
	#
	if ($Arg{output_hex}) {
		push(@{$Hex{"TCP"}{$session_id}}, [$from_server, $tcp_data]);
	}
}



# Process_TCP_Sessions - this subroutine processes %TCP, saving the
# 	sessions to various "session*" files on disk. It populates %Index
#	with information on files that it has created. It also checks
#	the application port numbers and triggers further processing -
#	eg telnet replay files. Min/Max size checks are also done here.
#
sub Process_TCP_Sessions {
	
	my ($filename,$id_text,$id_html,$rawboth,$time,$raw);
	my @Time;
	
	#
	#  Loop through all TCP sessions
	#
	foreach $session_id (keys %{$TCP{id}}) {
		$number = $Index{Sort_Lookup}{"TCP:$session_id"};
		# Would print in Arg{the_dir}, so $my_log adapted.
		#&logger("\$my_log: $my_log");
		&logger("\$session_id: $session_id");
		&logger("\$number: $number");
		
		#
		#  Determine the service - usually by the lowest numbered port, eg,
		#  ports 51321 and 23 would give 23 (telnet).
		#
		$ip_src = $TCP{id}{$session_id}{src};
		$ip_dest = $TCP{id}{$session_id}{dest};
		$tcp_src_port = $TCP{id}{$session_id}{src_port};
		$tcp_dest_port = $TCP{id}{$session_id}{dest_port};
		&logger("\$ip_src = \$TCP{id}{$session_id}{src};");
		&logger("$ip_src = $TCP{id}{$session_id}{src};");
		&logger("\$ip_dest = \$TCP{id}{$session_id}{dest};");
		&logger("$ip_dest = $TCP{id}{$session_id}{dest};");
		&logger("\$tcp_src_port = \$TCP{id}{$session_id}{src_port};");
		&logger("$tcp_src_port = $TCP{id}{$session_id}{src_port};");
		&logger("\$tcp_dest_port = \$TCP{id}{$session_id}{dest_port};");
		&logger("$tcp_dest_port = $TCP{id}{$session_id}{dest_port};");
		($service,$client) = &Pick_Service_Port("TCP",$session_id,
			$tcp_src_port,$tcp_dest_port);
		
		### Fetch text name for this port
		$service_name = $Services_TCP{$service} || $service || "0";
		&logger("\$service_name: $service_name");

		#
		#  Don't actually save any files if CLI args say not to
		#
		if ($Arg{port_reject} && $Arg{Port_Rejected}{$service}) { next; }
		if ($Arg{port_accept} && !$Arg{Port_Accepted}{$service}) { next; }
		if ($Arg{ip_reject}) {
			if ($Arg{IP_Rejected}{$ip_src} || $Arg{IP_Rejected}{$ip_dest}) {
				next;
			}
		}
		if ($Arg{ip_accept}) {
			unless ($Arg{IP_Accepted}{$ip_src} ||
			 $Arg{IP_Accepted}{$ip_dest}) {
				next;
			}
		}

		#
		# --- Fetch RawBoth ---
		#
		# rawboth will contain the raw data in time order.
		$rawboth = "";
		foreach $time (sort {$a <=> $b}
			(keys (%{$TCP{id}{$session_id}{time}}))) {
				# gets: 1501068174.74363 => HASH(0x5c5d9ba8b8
				#&binner("$time => $TCP{id}{$session_id}{time}");
				# gets: 1501068174.74363 => 
				#&binner("$time => $TCP{id}{$session_id}{$time}");
				# gets: 1501068174.74363 => 
				#&binner("$time => $TCP{id}{$session_id}{$time}{data}");
				# This does it:
				&binner("$time => $TCP{id}{$session_id}{time}{$time}{data}");
				# Well, it's what's in the orig code :( and it took me time.
				# Problem is, I read (a lot) perldoc perlref. Still vague.
		}
		
		print STDOUT "FAKE-1";
		$response = <STDIN> // next ;

		foreach $time (sort {$a <=> $b}
			(keys (%{$TCP{id}{$session_id}{time}}))) {
			$rawboth .= $TCP{id}{$session_id}{time}{$time}{data};
		}
		$length = length($rawboth);
		&logger("\$length(\$rawboth)");
		&logger("\$rawboth:");
		&binner("$rawboth");
		
		#
		# --- Check for Min and Max size ---
		#
		next if $length < $Arg{minbytes};
		next if (($Arg{maxbytes} != 0) && ($length > $Arg{maxbytes}));
		
		### Print status line
		$numtext = sprintf("%04d",$number);
		printf "%6s  %-45s  %s\n",$numtext,$session_id,$service_name
			unless $Arg{quiet};
		
		print STDOUT "FAKE00";
		$response = <STDIN> // next ;
		
		#
		# --- Save Info File to Disk ---
		#
		if ($Arg{output_info}) {
			$filename = "session_${numtext}.info";
			$firsttime = localtime($TCP{id}{$session_id}{StartTime});
			$lasttime = localtime($TCP{id}{$session_id}{EndTime});
			$duration = ($TCP{id}{$session_id}{EndTime} -
				$TCP{id}{$session_id}{StartTime});
			$duration = sprintf("%.0f",$duration);
			&logger("\$duration: $duration");
			if ($TCP{id}{$session_id}{Partial}) { $partial = "yes"; }
				else { $partial = "no"; }
			
			### Build output text
			$outtext = "$numtext===$session_id===$service===" .
			 "$service_name===$length\n\n" .
			 "Source addr : $ip_src\n" .
			 "Source port : $tcp_src_port\n" .
			 "Dest addr   : $ip_dest\n" .
			 "Dest port   : $tcp_dest_port\n" .
			 "Dest service: $service_name\n" .
			 "Length bytes: $length\n" .
			 "First time  : $firsttime\n" .
			 "Last time   : $lasttime\n" .
			 "Duration    : $duration seconds\n" .
			 "Partial     : $partial\n";
			
			### Write info file
			open (OUT,">$filename") ||
				die "ERROR11: creating $filename $!\n";
			print OUT $outtext;
			close OUT;
		}
		
		print STDOUT "FAKE01";	# by this point created: session_NNNN.info
		$response = <STDIN> // next ;
		
		#
		# --- Save Index data to Memory ---
		#
		
		## Fetch times
		$starttime = scalar localtime($TCP{id}{$session_id}{StartTime});
		$duration = ($TCP{id}{$session_id}{EndTime} -
		 $TCP{id}{$session_id}{StartTime});
		$duration = sprintf("%.0f",$duration);
		&logger("\$starttime: $starttime");
		&logger("\$duration: $duration");
		
		### Generate session strings
		($id_text,$id_html) = &Generate_TCP_IDs($session_id);
		
		print STDOUT "FAKE02";
		$response = <STDIN> // next ;
		
		#
		# --- Save Raw Sessions to Disk ---
		#
		
		if ($Arg{output_raw}) {
			
			#
			#  Save ".raw" file, all raw 2-way data time-sorted.
			#
			$filename = "session_${numtext}.${service_name}.raw";
			open (OUT,">$filename") ||
			 die "ERROR12: creating $filename $!\n";
			binmode(OUT);		# for backward OSs
			print OUT $rawboth;
			close OUT;
			
		print STDOUT "FAKE03";	# by this point created: session_NNNN_PORT.raw
		$response = <STDIN> // next ;
		
			#
			#  Save ".raw1" file, server->client 1-way data assembled.
			#
			$filename = "session_${numtext}.${service_name}.raw1";
			open (OUT,">$filename") ||
			 die "ERROR13: creating $filename $!\n";
			binmode(OUT);		# for backward OSs
			print OUT &TCP_Follow_RawA($session_id);
			close OUT;
			
		}
			
		print STDOUT "FAKE04";	# by this point created: session_NNNN_PORT.raw1
		$response = <STDIN> // next ;
		
		next unless $Arg{output_apps};
		
		#
		# --- Process Application Data ---
		#
		if ($service == 80 or $service == 8080 or
			$service == 3127 or $service == 1080 or
			# JL: 8118 is HTTP(S) via polipo.
			#     9050 is Tor (socks4a, but works good enough for me).
			$service == 8118 or $service == 9050)  {
				&Save_HTTP_Files($session_id,$number,$service_name);
			
		print STDOUT "FAKE05";	# by this point created: session_NNNN_part_NN.data
								# by this point created: session_NNNN_part_NN.html
		$response = <STDIN> // next ;

				&Process_HTTP($session_id,$number);
		}
			
		print STDOUT "FAKE06";
		$response = <STDIN> // next ;
	}
}


# Process_HTTP - HTTP processing. Looks for GETs and POSTs, and process them
#		into %GETPOST. Constructs a HTTP log in %HTTPlog.
# JL: Added host parameter
#
sub Process_HTTP {
	my ($junk,$var,$value,$term,$data,$request,$host,$site,$post,$get,$reply);
	my ($start,$src,$num,$req,$recv,$type,$status,$time1,$duration,$dest);
	my @Terms;
	my $index = 0;
	my $indexA = 0;
	my $indexB = 0;
	
	### Input
	my $session_id = shift;
	my $number = shift;
	my $partnum = 0;
	
	$src = $TCP{id}{$session_id}{src};
	$dest = $TCP{id}{$session_id}{dest};
	
	#
	#  Process
	#
	
	### Get packet times (may need to use seqs instead)
	@Times = sort{$a <=> $b} (keys(%{$TCP{id}{$session_id}{time}}));
	
	### Step through each packet
	for ($i=0; $i <= $#Times; $i++) {
		
		### Fetch data from mem
		$time = $Times[$i];
		$request = $TCP{id}{$session_id}{time}{$time}{data};
		$request =~ s/^\0\0*//;
		
		#
		# --- Do HTTPlog Processing ---
		#
		
		next unless $request =~ /^(GET|POST)\s/; # speed
		
		### Calc duration
		$time1 = $Times[$i+1] || $time;
		$duration = $time1 - $time;
		&logger("\$duration = \$time1 - \$time");
		&logger("$duration = $time1 - $time");
		
		# some magic
		$reply = "";
		foreach $inc (1..16) {
			$next = $TCP{id}{$session_id}{time}{$Times[$i+$inc]}{data};
			$next =~ s/^\0\0*//;
			if ($next =~ /^U*\0*HTTP/) {
				$reply = $next;
				$time1 = $Times[$i+$inc] || $time;
					$duration = $time1 - $time;
				last;
			} else {
				$request .= $next;
			}
			&binner("$request");
		}
		$i++; # speed
		$partnum++;
		if ($request =~ /^GET \S* HTTP/) {
			
			### JL: Get the host string, referer, and cookies.
			($host) = $request =~ /\sHost:\s(\S*)\s/is;
			($referer) = $request =~ /\sReferer:\s(\S*)/is;
			($cookie) = $request =~ /\sCookie:\s(\S*)/is;
			($setcookie) = $reply =~ /\sSet-Cookie:\s(\S*)/is;
			&logger("\$request: $request");
			&logger("\$host: $host");
			&logger("\$referer: $referer");
			&logger("\$cookie: $cookie");
			&logger("\$setcookie: $setcookie");
			
		print STDOUT "FAKE07";
		$response = <STDIN> // next ;
			
			### Get the site string
			($site) = $request =~ /^GET (\S*)\s/;
			if ($site =~ m:^/:) {
				# assume this was a http, missing the "http://host"
				# JL: Prefer hostname over IP address
				if ($Arg{httplog_html}) {
				$site = "http://${host}$site";
				} else {
				    $site = "http://${dest}$site";
				}
			}
			
			### Get the status and mime type from reply
			($status)  = $reply =~ /HTTP\/\S*\s(\S*)/s;
			# JL: Be careful to use case insensitive matching
			($type) = $reply =~ /Content-Type:\s(\S*)/is;
			($size) = $reply =~ /Content-Length:\s(\S*)/is;
			$type = "-" if $type eq "";
			$size = 0 if $size eq "";
			
			$result = $Result_Names{$status} || "TCP_HIT";
			
			### JL: External image data.
			if ( defined $ExtImage{HTML}[$number]{parts}[$partnum] ) {
				$ExtImage{HTML}[$number]{links} .= "<img src=\"$site\"> ";
			}
		} elsif ($request =~ /^POST .* HTTP/) {
		### Get the site string
		($site) = $request =~ /^POST (\S*)\s/;
		if ($site =~ m:^/:) {
			# assume this was a http, missing the "http://host"
			$site = "http://${dest}$site";
		}
		### JL: Get the host string, referer, and cookies.
		($host) = $request =~ /\sHost:\s(\S*)\s/is;
		($referer) = $request =~ /\sReferer:\s(\S*)/is;
		($cookie) = $request =~ /\sCookie:\s(\S*)/is;
		($setcookie) = $reply =~ /\sSet-Cookie:\s(\S*)/is;
		
		### Get the status and mime type
		($status)  = $reply =~ /HTTP\/\S*\s(\S*)/s;
		($type) = $reply =~ /Content-Type:\s(\S*)/is;
		($size) = $reply =~ /Content-Length:\s(\S*)/is;
		$type = "-" if $type eq "";
		$size = length($TCP{id}{$session_id}) if $size eq "";
		$result = $Result_Names{$status} || "TCP_HIT";
		}
			
		print STDOUT "FAKE08";
		$response = <STDIN> // next ;
		
		#
		# --- Do GETPOST Processing ---
		#
		# JL: chaosreader 0.94 includes only URIs containing a question
		# mark.  Why?  Go for all instead.
		#if ($request =~ /^GET \S*\?\S* HTTP/) CURLY [opening curly confounds Vim]
		# was at place of string "CURLY" above, has been removed.
		if ($request =~ /^GET \S* HTTP/) {
				
				### Get the GET string
				($site,$get) = $request =~ /^GET (\S*)\?(\S*)\s/;
				if ($site eq "") {
				($site) = $request =~ /^GET (\S*)\s/;
				}
				# check it looks like a GET,
				# JL: Why only those with parameters?
			
		} elsif ($request =~ /^POST .* HTTP/) {
		
		### Get the POST strings
		($junk,$post,$junk1) = split(/\n\n|\r\n\r\n/,$request);
		
		}
			
		print STDOUT "FAKE09";
		$response = <STDIN> // next ;
	}
			
		print STDOUT "FAKE10";
		$response = <STDIN> // next ;
}


# Sort_Index_By_Time - this calculates an appropriate order for the index
#	files based on session start time.
#
sub Sort_Index_By_Time {
	my ($session_id,$time,$number);

	#
	#  Determine Session and Stream time order
	#
	foreach $session_id (keys %{$TCP{id}}) {
		$Index{Time_Order}{"TCP:$session_id"} =
		 $TCP{id}{$session_id}{StartTime};
	}
	$number = 0;
	foreach $session (sort {$Index{Time_Order}{$a} <=>
	 $Index{Time_Order}{$b}} keys %{$Index{Time_Order}}) {
		$number++;
		$Index{Sort_Lookup}{$session} = $number;
	}
}


# Chdir - change directory with error
#
sub Chdir {
	my $dir = shift;
	#
	#  This can be invoked with $Arg{output_dir}, so $dir won't
	#  always be defined - which is okay.
	#
	if (defined $dir) {
		chdir "$dir" ||
		 die "ERROR21: Can't cd to $dir: $!\n";
	}
}


# File_Type - return file extension for given data, else "data".
#
sub File_Type {
	my $data = $_[0];
	my $type = "";
	
	if ( $http_data eq "" ) {
	    return "empty";
	}
	if ( length($http_data) < 8 ) {
	    return "small";
	}
	if ($http_header =~ /Content-Encoding: deflate/ ){
		return "deflate";
	}
	
	if ($data =~ /^GIF8[7-9]/) 		{ $type = "gif"; }
	elsif ($data =~ /^\377.....(JPEG|JFIF)/) 	{ $type = "jpeg"; }
	elsif ($data =~ /^.PNG/) 	        { $type = "png"; } # JL
	elsif ($data =~ /^PK\003\004/) 		{ $type = "zip"; }
	elsif ($data =~ /^\%PDF/) 		{ $type = "pdf"; }
	elsif ($data =~ /^\037\213/) 		{ $type = "gz"; }
	elsif ($data =~ /^BZh/) 		{ $type = "bz2"; }
	elsif ($data =~ /^\177ELF/) 		{ $type = "elf"; }
	elsif ($data =~ /^\%!/) 		{ $type = "ps"; }
	elsif ($data =~ /<html>/i) 		{ $type = "html"; }
	elsif ($data =~ /<?xml/i) 		{ $type = "xml"; } # JL
	else { $type = "data"; }
	
	return $type;
}


# Is_Image - returns true if extension is for an image.
#
sub Is_Image {
	my $ext = shift;
	
	# JL: Use MIME types.
	return ($ext_types{$ext} eq "image");
}



# Process_Hex - Create the coloured HTML 2-way hex dump, and a text dump.
#		Uses data stored to data structure %Hex.
sub Process_Hex {
	### Input
	my $type = shift;
	my $session_id = shift;
	my $offset = 0;
	my (@Bytes,$byte,$colour,$from_server,$hexhtml,$hextext,$html,$pos,$text,$view,$view2,$viewhtml,$viewtext);


	### Process
	foreach $from_server_AND_data (@{$Hex{$type}{$session_id}}) {
		($from_server, $data) = @{$from_server_AND_data};
		$colour = $from_server ? "blue" : "red";
		$pos = 1 unless defined $pos;
		$hexhtml .= "<font color=\"$colour\">";
		$viewhtml .= "<font color=\"$colour\">";
		@Bytes = unpack("C*", $data);
		foreach $byte (@Bytes) {
			$view = chr($byte);
			$view =~ tr/\040-\176/./c;
			$view2 = $view;
			$view2 =~ s/</&lt;/g;
			$view2 =~ s/>/&gt;/g;
			$viewhtml .= $view2;
			$viewtext .= $view;
			$hexhtml .= sprintf("%2.2x",$byte);
			$hextext .= sprintf("%2.2x",$byte);
			$pos++;
			if ($pos > 16) {
				### Save text version
				$text .= sprintf("%6.08x",$offset) . "  $hextext  $viewtext\n";
				
				### Save HTML version
				$hexhtml .= "</font>";
				$viewhtml .= "</font>";
				$html .= '<font color="green">' . sprintf("%6.08x",$offset) .  "</font>  $hexhtml  $viewhtml\n";
				
				$pos = 1;
				$offset += 16;
				$hexhtml = "<font color=\"$colour\">";
				$viewhtml = "<font color=\"$colour\">";
				$hextext = $viewtext = "";
			}
			if ( ($pos != 1) && (($pos %2) == 1) ) {
				$hexhtml .= " ";
				$hextext .= " ";
			}
		}
		$hexhtml .= "</font>";
		$viewhtml .= "</font>";
	}
	
	return unless defined $pos;
	return ($text, $html) if $pos == 1;
	
	$short = 39 - length($hextext);
	$hexhtml .= " " x $short;
	$hextext .= " " x $short;
	
	### Save text version
	$text .= sprintf("%6.08x",$offset) . "  $hextext  $viewtext\n";
	
	### Save HTML version
	$html .= '<font color="green">' . sprintf("%6.08x",$offset) .  "</font>  $hexhtml  $viewhtml\n";
	
	return ($text, $html)
}


# Save_HTTP_Files - Save HTTP components.
#
sub Save_HTTP_Files {
	my ($filename);
	my $session_id = shift;
	my $number = shift;
	my $service_name = shift;
	my $numtext = sprintf("%04d",$number);
	&logger("\$number: $number, \$numtext: $numtext");
	
	### Full - Input
	$http_session = &TCP_Follow_RawA($session_id);
	
	### Full - Processing
	@HttpParts = split(/HTTP\/[0-9.]* /,$http_session);
	
	### LOOP
	$partnum = 0;
	foreach $http_part (@HttpParts) {
		
		# JL.  I want to see all parts, in partcular empty ones
		# resulting from 304 (Not Modified).  Thus, the original
		# check below on $http_data is too strong.
		next if $http_part eq "";
		
		### Part - Processing
		($http_header,$http_data) = split(/\r\n\r\n|\n\n/,$http_part,2);
		# next if $http_data eq "";
		# next if length($http_data) < 8;
		$partnum++;
		$parttext = sprintf("%02d",$partnum);
		
		### JL: Chunk Check, patch from http://refrequelate.blogspot.com/2008/07/more-de-chunking-chaosreader-patch.html
		if ( $http_header =~ /Transfer-Encoding: chunked/ ) {
			my $new_http_data="";
			my $chunksize=-1;
			my $pos=0;
			until ($chunksize==0) {
				my $eolpos=index($http_data,"\r\n",$pos);
				$chunksize=hex(substr($http_data,$pos,$eolpos - $pos));
				$pos=($eolpos+2);
				if ($chunksize > 0) {
				    $new_http_data.=substr($http_data,$pos,$chunksize);
				}
				$pos+=($chunksize+2);
			}
			$http_data=$new_http_data;
		}
		
		### Part - Checks
		my $http_type = &File_Type($http_data);
		if ($TCP{id}{$session_id}{Partial}) { $ext = ".partial"; }
		else { $ext = ""; }
		
		### JL: Check for known MIME type in Content-Type
		my ($content_type) = $http_header =~ /Content-Type:\s+(\S*)/is;
		my $file_extension = "";
		if ($content_type ne "") {
			for my $pattern ( keys %mime_types ) {
				my $value = $mime_types{$pattern};
				if ( $content_type =~ /$pattern/i ) {
				    $file_extension = $value;
				    last;
				}
			}
			if (($file_extension eq "bin")
				or ($file_extension eq "asc")) {
				# Not too specific.  Some HTTP servers return images
				# with Content-Type: application/octet-stream, others
				# with Content-Type: text/plain
				# Prefer http_type then...
				if ($http_type ne "data") {
				    $file_extension = $http_type;
				}
			}
			elsif ($file_extension eq "") {
				#print "Unkown Content-Type $content_type.";
				#print "  May want to extend MIME types.\n";
			}
		}
		
		### Part - Output
		# JL: Create filename based on Content-Type
		my $filename = "session_${numtext}.part_$parttext${ext}";
		if ($file_extension ne "") {
		    $filename .= ".$file_extension";
		}
		if ( ($file_extension eq "") or ($http_type eq "gz") ) {
		    $filename .= ".$http_type";
		}
		open (OUT,">$filename") ||
		die "ERROR51: file create, $filename: $!\n";
		binmode(OUT);		# for backward OSs
		print OUT $http_data;
		close OUT;
		
		### JL: gz decompressing
		if ( $http_type eq "gz" ) {
			my $gunzipped = substr($filename, 0, length($filename) - 3);
			my $gunzip_failed = 0;
			gunzip $filename => $gunzipped
			or $gunzip_failed = 1;
			if ( $gunzip_failed == 0 ) {
				$filename = $gunzipped;
			}
		}
		# Pex:Deflate
		elsif ( $http_type eq "deflate") {
			#print "inflating " . $http_type ;
			my $inflated = substr($filename, 0, length($filename) - 4) . "inflated.html";
			my $status = IO::Uncompress::Inflate::inflate($filename, $inflated, Transparent => 0);
			my $error = $IO::Uncompress::Inflate::InflateError;
			if ($status) {
				#Succesful inflate
				$filename = $inflated;
			}
			else {
				my $status = IO::Uncompress::RawInflate::rawinflate($filename, $inflated);
				my $error = $IO::Uncompress::RawInflate::RawInflateError;
				if ($status) {
					#Succesful raw inflate
					$filename = $inflated;
				}
				elsif ($error eq "expected end of file"){
					# End of file, might been succesful
					$filename = $inflated;
				}			
				else {
					#failed inflate
					#print "failed inflate";
				}
			}
		}
		
		### Part - Global Vars
		my $length = length($http_data);
	}
}


# TCP_Follow_RawA - process session by TCP Seq numbers 1-way.
#			(TCP ASSEMBLY)
#
sub TCP_Follow_RawA {
	my $session_id = shift;
	my $raw = "";
	
	#
	#  Assemble TCP Sessions. Each hash contains session_ids as keys,
	#  and the value points to another hash of sequence numbers and data.
	#  %TCP{id}{}{Aseq} is input, and %TCP{id}{}{RawA} is output.
	#
	@Seqs = keys (%{$TCP{id}{$session_id}{Aseq}});
	foreach $seq (sort { $a <=> $b } @Seqs) {
		$raw .= ${$TCP{id}{$session_id}{Aseq}{$seq}};
	}

	return $raw;
}


# Pick_Service_Port - pick which port is the server. Usually is the lower
#	number, however check if the direction is already known (eg SYN).
#	The port arguments will not often be needed.
#
# NOTE: This code is different from Generate_TCP_IPs - which does the "<->"'s
#
sub Pick_Service_Port {
	my $type = shift;
	my $id = shift;
	my $porta = shift;
	my $portb = shift;
	my $from_server = 0;
	my ($hi,$low);
	
	if ($type eq "TCP") {
	   if (defined $TCP{id}{$id}{source}) {
		if ($TCP{id}{$id}{source} eq $TCP{id}{$id}{src}) {
		   return ($TCP{id}{$id}{dest_port},$TCP{id}{$id}{src_port});
		} else {
		   return ($TCP{id}{$id}{src_port},$TCP{id}{$id}{dest_port});
		}
	   }
	}
	
	# resort to a sort
	return sort { $a <=> $b } ($porta,$portb);
}

# Generate_SessionID - input source and dest IPs and ports, and generate
# 	a unique session_id based on them. this is done by sorting on
#	ports and then IPs. Also returns a flag if the packet may be
#	assumed to be from_server - where the lowest port is assumed to
#	be the server (unless TCP SYNs have been observed).
#
sub Generate_SessionID {
	my $ip_src = shift;
	my $tcp_src_port = shift;
	my $ip_dest = shift;
	my $tcp_dest_port = shift;
	my $type = shift;
	my $from_server = 0;
	my $session_id;
	
	#
	#  Generate session_id string using host:port,host:port sorted on
	#  port (low port last).
	#
	&logger("\$ip_src: $ip_src");
	&logger("\$tcp_src_port: $tcp_src_port");
	&logger("\$ip_dest: $ip_dest");
	&logger("\$tcp_dest_port: $tcp_dest_port");
	if ($tcp_src_port < $tcp_dest_port) {
		$session_id = "$ip_dest:$tcp_dest_port,$ip_src:$tcp_src_port";
		$from_server = 1;
	} elsif ($tcp_src_port > $tcp_dest_port) {
		$session_id = "$ip_src:$tcp_src_port,$ip_dest:$tcp_dest_port";
		$from_server = 0;
	} else {
		$session_id =join(",",sort("$ip_src:$tcp_src_port",
					"$ip_dest:$tcp_dest_port"));
		$from_server = 1;
	}
	
	if ($type eq "TCP") {
		if ( $TCP{id}{$session_id}{source} ) {
			&logger("\$TCP{id}{\$session_id}{source}: $TCP{id}{$session_id}{source}");
		}
		if (defined $TCP{id}{$session_id}{source}) {
			if ($TCP{id}{$session_id}{source} eq $ip_dest
			    # JL: Also look at the port as ip_src and ip_dest
			    # may be the same (e.g., 127.0.0.1)
			    # Also in Generate_TCP_IDs below.
			    && $TCP{id}{$session_id}{source_port} eq $tcp_dest_port) {
				$from_server = 1;
			} else {
				$from_server = 0;
			}
		}
	}
	return ($session_id,$from_server);
}



# Generate_TCP_IDs - generate a text and html version of the session ID, that
#		displays direction of the TCP session if SYNs and ACKs were
#		observed, else uses a "<->" symbol to represent unknown
#		direction. TCP only.
#
sub Generate_TCP_IDs {
	my $session_id = shift;
	my ($ip_src,$tcp_src_port,$ip_dest,$tcp_dest_port,$text,$html);
	
	# try this direction,
	$ip_src = $TCP{id}{$session_id}{src};
	$ip_dest = $TCP{id}{$session_id}{dest};
	$tcp_src_port = $TCP{id}{$session_id}{src_port};
	$tcp_dest_port = $TCP{id}{$session_id}{dest_port};
	
	if (defined $TCP{id}{$session_id}{source}) {
		if ($TCP{id}{$session_id}{source} eq $ip_dest
		    && $TCP{id}{$session_id}{source_port} eq $tcp_dest_port) {
			# nope, switch ends
			$ip_src = $TCP{id}{$session_id}{dest};
			$ip_dest = $TCP{id}{$session_id}{src};
			$tcp_src_port = $TCP{id}{$session_id}{dest_port};
			$tcp_dest_port = $TCP{id}{$session_id}{src_port};
		}
		$text = "$ip_src:$tcp_src_port -> $ip_dest:$tcp_dest_port";
		$html = "$ip_src:$tcp_src_port -&gt; $ip_dest:$tcp_dest_port";
	}
	
	return ($text,$html);
}



# Generate_IP_ID - input source IP, dest IP and ident, and generate a
#		unique ip_id based on them. This is necessary for IP
#		fragmentation reassembely. Normally we would assume that
#		the IP_ident was unique - however this program could
#		process traffic from many different hosts over a long
#		period of time - idents alone could clash.
#
sub Generate_IP_ID {
	my $ip_src = shift;
	my $ip_dest = shift;
	my $ip_ident = shift;
	my $ip_id;
	
	#
	#  Generate ip_id string using host:host:ident sorted on IP.
	#
	#
	$ip_id = join(",",sort("$ip_src","$ip_dest")) . ",$ip_ident";
	
	return $ip_id;
}



# Read_Tcpdump_Record - Read the next tcpdump record, will "last" if
#			there are no more records.
#
sub Read_Tcpdump_Record {
	my $more;
	
	### Fetch record header
	&logger("==================================================");
	# The packet numbering does not correspond to the correct numbering, say,
	# in Wireshark. It is so in original Chaosreader, where add this and see:
	#print "### \$packet $packet ###\n";
	&logger("### \$packet $packet ###");
	$length = read(INFILE,$header_rec,($integerSize * 2 + 8));
	&logger("\$header_rec:");
	&binner("$header_rec");
	
	### Quit main loop if at end of file
	last if $length < 16;
	
	### Throw out extra info in tcpdump/modified1 format
	if ($STYLE =~ /^modified/) {
		$length = read(INFILE,$more,8);
	}
	
	$frame++;
	
	## Unpack header, endian sensitive
	if ($STYLE =~ /1$/) {
		($tcpdump_seconds,$tcpdump_msecs,$tcpdump_length,
		 $tcpdump_length_orig)
		 = unpack('NNNN',$header_rec);
	} else {
		($tcpdump_seconds,$tcpdump_msecs,$tcpdump_length,
		 $tcpdump_length_orig)
		 = unpack('VVVV',$header_rec);
		&logger("\$tcpdump_seconds,\$tcpdump_msecs,\$tcpdump_length,\$tcpdump_length_orig = unpack('VVVV',\$header_rec);");
		&logger("$tcpdump_seconds,$tcpdump_msecs,$tcpdump_length,$tcpdump_length_orig,$my_header_rec;");
		# The created bin snippet/data.
		&binner("$header_rec");
		# Can be read too.
		#open my $binfile, "<", "$my_bin_d" or die "Could not open $my_bin_d: $!";
	}
	$length = read(INFILE,$tcpdump_data,$tcpdump_length);
	# See note above why this line.
	&logger("\$tcpdump_data (later: \$packet_data, same as \$header_rec above, always?):");
	&binner("$tcpdump_data");
	&logger("--------------------------------------------------");
	$tcpdump_drops = $tcpdump_length_orig - $tcpdump_length;
	# Uncomment to study just the initial loop:
	#exit(0);
}

# Set_Result_Names - Set a lookup hash for squid result codes.
#		(This needs some fine tuning).
#
sub Set_Result_Names {
	%Result_Names = ("" => "TCP_MISS",
			000 => "TCP_MISS",
			200 => "TCP_HIT",
			302 => "TCP_HIT",
			304 => "TCP_REFRESH_HIT",
			404 => "TCP_NEGATIVE_HIT"
	);
} 

# JL: Set_MIME_Types - create hash of MIME types and file extensions.
sub Set_MIME_Types {
    # Initialize with types seen in the wild but not covered below.
    %mime_types = (
	"application/binary" => "binary",
	"application/ocsp-response" => "ocsp",
	"application/pln" => "pln", # bahn.de schedule
	"application/vnd.google.safebrowsing-update" => "safebrowsing-update",
	"application/vnd.google.safebrowsing-chunk" => "safebrowsing-chunk",
	"application/vnd.ms-sync.wbxml" => "mssync", # MS ActiveSync
	"application/x-protobuffer" => "protobuffer", # google
	"application/x-smd" => "smd", # MapDroyd boundary
	"(application|text)/((x-)?javascript|(x-)?js)" => "js",
	"(application|text)/json" => "json",
	"application/x-amf" => ".amf",
	"application/x-zip-compressed" => ".zip",
	"image/bmp" => "bmp",
	"image/vnd.microsoft.icon" => "ico",
	"image/x-gif" => "gif",
	"(image/x-)?jp(e)?g" => "jpeg",
	"image/x-png" => "png",
	"text/xml" => "xml",
	"application/x-bzip2" => "bz2",
	"application/x-css" => "css",
	"font/woff" => "woff",
	"application/font-woff" => "woff");
    # Following created with:
    # grep -o -P "^(text|application|audio|image|video).*\t+([a-z0-9]+)" /etc/mime.types > mime.types
    $raw_mime_types = <<END;
application/andrew-inset			ez
application/annodex				anx
application/atom+xml				atom
application/atomcat+xml				atomcat
application/atomserv+xml			atomsrv
application/bbolin				lin
application/cap					cap
application/cu-seeme				cu
application/davmount+xml			davmount
application/dsptype				tsp
application/ecmascript				es
application/futuresplash			spl
application/hta					hta
application/java-archive			jar
application/java-serialized-object		ser
application/java-vm				class
application/javascript				js
application/m3g					m3g
application/mac-binhex40			hqx
application/mac-compactpro			cpt
application/mathematica				nb
application/msaccess				mdb
application/msword				doc
application/mxf					mxf
application/octet-stream			bin
application/oda					oda
application/ogg					ogx
application/pdf					pdf
application/pgp-keys				key
application/pgp-signature			pgp
application/pics-rules				prf
application/postscript				ps
application/rar					rar
application/rdf+xml				rdf
application/rss+xml				rss
application/rtf					rtf
application/smil				smi
application/xhtml+xml				xhtml
application/xml					xml
application/xspf+xml				xspf
application/zip					zip
application/vnd.android.package-archive		apk
application/vnd.cinderella			cdy
application/vnd.google-earth.kml+xml		kml
application/vnd.google-earth.kmz		kmz
application/vnd.mozilla.xul+xml			xul
application/vnd.ms-excel			xls
application/vnd.ms-pki.seccat			cat
application/vnd.ms-pki.stl			stl
application/vnd.ms-powerpoint			ppt
application/vnd.oasis.opendocument.chart			odc
application/vnd.oasis.opendocument.database			odb
application/vnd.oasis.opendocument.formula			odf
application/vnd.oasis.opendocument.graphics			odg
application/vnd.oasis.opendocument.graphics-template		otg
application/vnd.oasis.opendocument.image			odi
application/vnd.oasis.opendocument.presentation			odp
application/vnd.oasis.opendocument.presentation-template	otp
application/vnd.oasis.opendocument.spreadsheet			ods
application/vnd.oasis.opendocument.spreadsheet-template		ots
application/vnd.oasis.opendocument.text				odt
application/vnd.oasis.opendocument.text-master			odm
application/vnd.oasis.opendocument.text-template		ott
application/vnd.oasis.opendocument.text-web			oth
application/vnd.openxmlformats-officedocument.spreadsheetml.sheet		xlsx
application/vnd.openxmlformats-officedocument.spreadsheetml.template		xltx
application/vnd.openxmlformats-officedocument.presentationml.presentation	pptx
application/vnd.openxmlformats-officedocument.presentationml.slideshow		ppsx
application/vnd.openxmlformats-officedocument.presentationml.template		potx
application/vnd.openxmlformats-officedocument.wordprocessingml.document		docx
application/vnd.openxmlformats-officedocument.wordprocessingml.template		dotx
application/vnd.rim.cod				cod
application/vnd.smaf				mmf
application/vnd.stardivision.calc		sdc
application/vnd.stardivision.chart		sds
application/vnd.stardivision.draw		sda
application/vnd.stardivision.impress		sdd
application/vnd.stardivision.math		sdf
application/vnd.stardivision.writer		sdw
application/vnd.stardivision.writer-global	sgl
application/vnd.sun.xml.calc			sxc
application/vnd.sun.xml.calc.template		stc
application/vnd.sun.xml.draw			sxd
application/vnd.sun.xml.draw.template		std
application/vnd.sun.xml.impress			sxi
application/vnd.sun.xml.impress.template	sti
application/vnd.sun.xml.math			sxm
application/vnd.sun.xml.writer			sxw
application/vnd.sun.xml.writer.global		sxg
application/vnd.sun.xml.writer.template		stw
application/vnd.symbian.install			sis
application/vnd.visio				vsd
application/vnd.wap.wbxml			wbxml
application/vnd.wap.wmlc			wmlc
application/vnd.wap.wmlscriptc			wmlsc
application/vnd.wordperfect			wpd
application/vnd.wordperfect5.1			wp5
application/x-123				wk
application/x-7z-compressed			7z
application/x-abiword				abw
application/x-apple-diskimage			dmg
application/x-bcpio				bcpio
application/x-bittorrent			torrent
application/x-cab				cab
application/x-cbr				cbr
application/x-cbz				cbz
application/x-cdf				cdf
application/x-cdlink				vcd
application/x-chess-pgn				pgn
application/x-cpio				cpio
application/x-csh				csh
application/x-debian-package			deb
application/x-director				dcr
application/x-dms				dms
application/x-doom				wad
application/x-dvi				dvi
application/x-httpd-eruby			rhtml
application/x-font				pfa
application/x-freemind				mm
application/x-futuresplash			spl
application/x-gnumeric				gnumeric
application/x-go-sgf				sgf
application/x-graphing-calculator		gcf
application/x-gtar				gtar
application/x-hdf				hdf
application/x-httpd-php				phtml
application/x-httpd-php-source			phps
application/x-httpd-php3			php3
application/x-httpd-php3-preprocessed		php3p
application/x-httpd-php4			php4
application/x-httpd-php5			php5
application/x-ica				ica
application/x-info				info
application/x-internet-signup			ins
application/x-iphone				iii
application/x-iso9660-image			iso
application/x-jam				jam
application/x-java-jnlp-file			jnlp
application/x-jmol				jmz
application/x-kchart				chrt
application/x-killustrator			kil
application/x-koan				skp
application/x-kpresenter			kpr
application/x-kspread				ksp
application/x-kword				kwd
application/x-latex				latex
application/x-lha				lha
application/x-lyx				lyx
application/x-lzh				lzh
application/x-lzx				lzx
application/x-maker				frm
application/x-mif				mif
application/x-ms-wmd				wmd
application/x-ms-wmz				wmz
application/x-msdos-program			com
application/x-msi				msi
application/x-netcdf				nc
application/x-ns-proxy-autoconfig		pac
application/x-nwc				nwc
application/x-object				o
application/x-oz-application			oza
application/x-pkcs7-certreqresp			p7r
application/x-pkcs7-crl				crl
application/x-python-code			pyc
application/x-qgis				qgs
application/x-quicktimeplayer			qtl
application/x-redhat-package-manager		rpm
application/x-ruby				rb
application/x-sh				sh
application/x-shar				shar
application/x-shockwave-flash			swf
application/x-silverlight			scr
application/x-stuffit				sit
application/x-sv4cpio				sv4cpio
application/x-sv4crc				sv4crc
application/x-tar				tar
application/x-tcl				tcl
application/x-tex-gf				gf
application/x-tex-pk				pk
application/x-texinfo				texinfo
application/x-troff				t
application/x-troff-man				man
application/x-troff-me				me
application/x-troff-ms				ms
application/x-ustar				ustar
application/x-wais-source			src
application/x-wingz				wz
application/x-x509-ca-cert			crt
application/x-xcf				xcf
application/x-xfig				fig
application/x-xpinstall				xpi
audio/amr					amr
audio/amr-wb					awb
audio/amr					amr
audio/amr-wb					awb
audio/annodex					axa
audio/basic					au
audio/flac					flac
audio/midi					mid
audio/mpeg					mpga
audio/mpegurl					m3u
audio/ogg					oga
audio/prs.sid					sid
audio/x-aiff					aif
audio/x-gsm					gsm
audio/x-mpegurl					m3u
audio/x-ms-wma					wma
audio/x-ms-wax					wax
audio/x-pn-realaudio				ra
audio/x-realaudio				ra
audio/x-scpls					pls
audio/x-sd2					sd2
audio/x-wav					wav
image/gif					gif
image/ief					ief
image/jpeg					jpeg
image/pcx					pcx
image/png					png
image/svg+xml					svg
image/tiff					tiff
image/vnd.djvu					djvu
image/vnd.wap.wbmp				wbmp
image/x-canon-cr2				cr2
image/x-canon-crw				crw
image/x-cmu-raster				ras
image/x-coreldraw				cdr
image/x-coreldrawpattern			pat
image/x-coreldrawtemplate			cdt
image/x-corelphotopaint				cpt
image/x-epson-erf				erf
image/x-icon					ico
image/x-jg					art
image/x-jng					jng
image/x-ms-bmp					bmp
image/x-nikon-nef				nef
image/x-olympus-orf				orf
image/x-photoshop				psd
image/x-portable-anymap				pnm
image/x-portable-bitmap				pbm
image/x-portable-graymap			pgm
image/x-portable-pixmap				ppm
image/x-rgb					rgb
image/x-xbitmap					xbm
image/x-xpixmap					xpm
image/x-xwindowdump				xwd
text/cache-manifest				manifest
text/calendar					ics
text/css					css
text/csv					csv
text/h323					323
text/html					html
text/iuls					uls
text/mathml					mml
text/plain					asc
text/richtext					rtx
text/scriptlet					sct
text/texmacs					tm
text/tab-separated-values			tsv
text/vnd.sun.j2me.app-descriptor		jad
text/vnd.wap.wml				wml
text/vnd.wap.wmlscript				wmls
text/x-bibtex					bib
text/x-boo					boo
text/x-c++hdr					h
text/x-c++src					c
text/x-chdr					h
text/x-component				htc
text/x-csh					csh
text/x-csrc					c
text/x-dsrc					d
text/x-diff					diff
text/x-haskell					hs
text/x-java					java
text/x-literate-haskell				lhs
text/x-moc					moc
text/x-pascal					p
text/x-pcs-gcd					gcd
text/x-perl					pl
text/x-python					py
text/x-scala					scala
text/x-setext					etx
text/x-sh					sh
text/x-tcl					tcl
text/x-tex					tex
text/x-vcalendar				vcs
text/x-vcard					vcf
video/3gpp					3gp
video/annodex					axv
video/dl					dl
video/dv					dif
video/fli					fli
video/gl					gl
video/mpeg					mpeg
video/mp4					mp4
video/quicktime					qt
video/ogg					ogv
video/vnd.mpegurl				mxu
video/x-flv					flv
video/x-la-asf					lsf
video/x-mng					mng
video/x-ms-asf					asf
video/x-ms-wm					wm
video/x-ms-wmv					wmv
video/x-ms-wmx					wmx
video/x-ms-wvx					wvx
video/x-msvideo					avi
video/x-sgi-movie				movie
video/x-matroska				mpv
END
    %ext_types = ();
    foreach $line (split(/\n/, $raw_mime_types)) {
	my ($mime_type, $extension) = split(/\t+/, $line);
	# Beware.  "+" needs to be escaped in patterns.
	$mime_type =~ s/\+/\\\+/g;
	$mime_types{$mime_type} = $extension;
	my ($type, $sub_type) = split(/\//, $mime_type);
	# We check whether we already have a value for this extension.
	# We don't care if application is overwritten.
	if ((defined $ext_types{$extension}) &&
	    ($ext_types{$extension} ne $type) &&
	    ($ext_types{$extension} ne "application")) {
	    print "$extension already has $ext_types{$extension}.";
	    print "Should now become $type.  Fix mime.types?\n"
	}
	else {
	    $ext_types{$extension} = $type;
	}
    }
}


# Touch_Vars - This is stops perl -w warnings about vars used only once.
#		Part of my todo list is to cull this list.
#
#
sub Touch_Vars {
	@Once_is_okay = ($ip_ttl,$udp_checksum,$ip_ident,$tcp_length_data,
	$ip_tos,$tcp_options,$opt_A,$opt_D,$tcp_header_rest,$opt_J,
	$opt_P,$opt_U,$opt_X,$opt_e,$opt_h,$opt_i,$pad,$opt_j,
	$http_header,$opt_p,$opt_q,$opt_r,
	$header_rest,$tcp_ack,$ether_dest,$ether_src,$skip,
	$ip_length,$udp_length,$ip_options,$ip_checksum,$tcp_rst,$tcp_fin,
	$opt_b,$opt_B,$opt_l,$opt_L,$ip_rest,$ip_hop,$ip_reserved,
	$ip_flow,$icmp_rest,$opt_f,$opt_z,$junk1,$opt_H,$opt_I,$opt_R);
}


# Process_Command_Line_Arguments - this processes the command line arguments
# and sets various globals which are kept in %Arg. It also prints usage and
# exists if need be.
#
sub Process_Command_Line_Arguments {
	my $result;
	
	#
	#  Command Line Defaults
	#
	$Arg{output_raw} = 0;
	$Arg{output_hex} = 0;
	$Arg{output_UDP} = 0;
	$Arg{output_TCP} = 1;
	$Arg{output_ICMP} = 0;
	$Arg{output_info} = 0;
	$Arg{output_apps} = 1;
	$Arg{output_index} = 1;
	$Arg{prefer_dns} = 0; # JL: Prefer DNS names over IP addresses?
	$Arg{httplog_html} = 0; # JL: Should we create HTTPlog in HTML?
	$Arg{httplog_name} = "httplog.text"; # JL: Old default as variable
	$Arg{httplog_txt} = "httplog.txt";   # JL: New text format
	$Arg{keydata} = 0;
	$Arg{debug} = 0;
	
	#
	#  Check correct switches were used
	#
	Getopt::Long::Configure ("bundling");
	$result = GetOptions (
		"application!" => \$opt_a,
		"a" => \$opt_a,
		"d|preferdns" => \$opt_d, # JL: new option
		"e|everything" => \$opt_e,
		"h" => \$opt_h,
		"info!" => \$opt_i,
		"i" => \$opt_i,
		"n|names" => \$opt_n, # JL: new option
		"q|quiet" => \$opt_q,
		"raw!" => \$opt_r,
		"r" => \$opt_r,
		"v|verbose" => \$opt_v,
		"index!" => \$opt_x,
		"x" => \$opt_x,
		"A" => \$opt_A,
		"H|hex" => \$opt_H,
		"I" => \$opt_I,
		"R" => \$opt_R,
		"U|noudp" => \$opt_U,
		"T|notcp" => \$opt_T,
		"Y|noicmp" => \$opt_Y,
		"X" => \$opt_X,
		"D|dir=s" => \$opt_D,
		"l|htmltcp=s" => \$opt_l,
		"L|htmludp=s" => \$opt_L,
		"m|min=s" => \$opt_m,
		"M|max=s" => \$opt_M,
		"o|sort=s" => \$opt_o,
		"p|port=s" => \$opt_p,
		"P|noport=s" => \$opt_P,
		"j|ipaddr=s" => \$opt_j,
		"J|noipaddr=s" => \$opt_J,
		"f|filter=s" => \$opt_f,
		"k|keydata" => \$opt_k,
		"debug" => \$opt_debug,
		"bench" => \$opt_bench
	);
	
	#
	#  Process switches
	#
	$Arg{output_raw} = 1 if $opt_r or $opt_v;
	$Arg{output_hex} = 1 if $opt_H or $opt_e;
	$Arg{output_info} = 1 if $opt_i or $opt_v;
	$Arg{quiet} = 1 if $opt_q;
	$Arg{output_UDP} = 0 if $opt_U;
	$Arg{output_TCP} = 0 if $opt_T;
	$Arg{output_ICMP} = 0 if $opt_Y;
	$Arg{output_apps} = 0 if ($opt_A || (defined $opt_a && $opt_a eq "0"));
	$Arg{output_index} = 0 if ($opt_X || (defined $opt_x && $opt_x eq "0"));
	$Arg{output_allhtml} = 1 if $opt_e;
	$Arg{prefer_dns} = 1 if $opt_d;
	$Arg{httplog_html} = 1 if $opt_n;
	$Arg{httplog_name} = "httplog.html" if $opt_n;
	my $extra_TCPhtml = $opt_l;
	my $extra_UDPhtml = $opt_L;
	my $ports_accepted = $opt_p;
	my $ports_rejected = $opt_P;
	my $ips_accepted = $opt_j;
	my $ips_rejected = $opt_J;
	$Arg{output_dir} = $opt_D;
	$Arg{filter} = $opt_f || "";
	$Arg{minbytes} = 0;
	$Arg{maxbytes} = 0;
	$Arg{sort} = "time";
	$Arg{keydata} = 1 if $opt_k;
	$Arg{debug} = 1 if $opt_debug;
	$Arg{bench} = 1 if $opt_bench;
	
	mkdir $Arg{output_dir};
	
	#
	#  Check for min/max bytes
	#
	if (defined $opt_m) {
		if ($opt_m =~ /k$/) {
			$opt_m =~ s/k$//;
			$opt_m *= 1024;
		}
		$Arg{minbytes} = $opt_m;
	}
	if (defined $opt_M) {
		if ($opt_M =~ /k$/) {
			$opt_M =~ s/k$//;
			$opt_M *= 1024;
		}
		$Arg{maxbytes} = $opt_M;
	}
	
	#
	#  Check for sort option
	#
	if (defined $opt_o) {
		if ($opt_o !~ /^(time|size|type|ip)$/) {
			print STDERR "ERROR55: Sort must be \"time\", " .
			 "\"size\", \"type\" or \"ip\".\n";
		}
		$Arg{sort} = $opt_o;
	}
	
	#
	#  This is normal mode
	#
		$Arg{normal} = 1;
	
	#
	#  Build accepted or rejected port list as %Arg{Port_Accepted},...
	#
	if (defined $ports_accepted) {
		$Arg{port_accept} = 1;
		foreach $port (split(/,/,$ports_accepted)) {
			$Arg{Port_Accepted}{$port} = 1;
		}
	}
	if (defined $ports_rejected) {
		$Arg{port_reject} = 1;
		foreach $port (split(/,/,$ports_rejected)) {
			$Arg{Port_Rejected}{$port} = 1;
		}
	}
	
	#
	#  Check infile was provided, or print usage
	#
	if (! defined $ARGV[0]) {
		print "See usage in orig chaosreader.\n";
		exit 1;
	}
	@{$Arg{infiles}} = @ARGV;
}



__END__

Data types,
===========
	%IP
		-> time
			-> $packet_time
				-> ver
				-> src
				-> dest
				-> protocol
				-> frag
					-> $ip_frag
				-> fragged
				-> drops
		-> id
			-> $ip_id
				-> StartTime
	
	%TCP
		-> id
			-> $session_id
				-> src
				-> dest
				-> source	# SYN seen
				-> src_port
				-> dest_port
				-> Aseq
					-> $$tcp_seq
				-> Bseq
					-> $$tcp_seq
				-> time
					-> $time
						-> dir
						-> data
				-> BothHTML
				-> StartTime
				-> EndTime
				-> size
				-> knowndir

	%Index
		-> @HTML
		-> @Text
		-> Time_Order
			-> $session_timeid
		-> Sort_Lookup
			-> $session_timeid

