#!/usr/bin/perl
#
# chread_tcp.pl -D <some-very-short-only-tcp-PCAP>-chr-i-H-r.d/ \
#		-i -H -r <some-very-short-only-tcp-PCAP>.pcap
#	Or similar. Help in this maimed version is incomplete.
#
#	Derived from Chaosreader.
#	15-Jun-2014, ver 0.96		https://github.com/brendangregg/Chaosreader
#	(by: Brendan Gregg Indian Larry Jens Lechtenbörger Pavel Hančar Pex)
#
#	Accordingly, this derived work is best released also under license:
#                        GNU GPLv3 or later
#
#	This is my (Miroslav Rovis) Perl practicing copy. Learning Perl. Lots of
#	dirt and noise. You have been warned.
#
#	But this could be useful for other (hardworking) newbies to Perl... Along
#	with lots of plain perldoc pages reading where necessary.
#
#	Why am I doing this? Because I need to identify perl code of chaosreader
#	suitable to be modified, or my new work based on it, that can work on
#	extracted SSL TCP streams. Because Chaosreader can't extract SSL streams,
#	only plain HTTP TCP streams.
#	My tshark-streams:
#	https://github.com/miroR/tshark-streams
#	can extract TCP streams, both plain and SSL. But extracting the streams,
#	using tshark, is all it does. I want to create a script (based on
#	Chaosreader code) which would then extract data, i.e. mainly files of all
#	kinds, from SSL streams and maybe deploy them with HTML like Chaosreader
#	does for plain HTTP traffic.
#
#	And to be able to understand the needed Chaosreader code, I've removed a
#	lot of code that wouldn't serve my future script.
#
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
#	Somewere not long before the last line above I started inserting new, mostly
#		"print..." often after unpack(...", lines, to understand the code. Will
#		make this copy available, may help some other new explorer of Perl.
#		(Practice by running it on (very) small dumps first.)
#	Removed Wireless
#	Apparently the $llc_<something> were all wireless too. Removed.
#	Set "$Arg{debug} = 1;" (default 0)
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

#	If these uncommented in old orig, the script won't work either. I
#	(hopefully) haven't introduced more errors/inconsistencies...
#use strict;
#use warnings;
use Getopt::Long;
use IO::Uncompress::Gunzip qw(gunzip $GunzipError);
use IO::Uncompress::Inflate qw(inflate $InflateError) ;
use IO::Uncompress::RawInflate qw(rawinflate $RawInflateError) ;
use Time::Piece;		# needed for logger/binner/binner_d unique filename
						# creation

my $t = localtime();
my $my_log;
my $my_bin;
$my_log .= "$0-";
$my_log =~ s|/usr/local/bin/|| ; # well if your Chaosreader is elsewhere, modify.
$my_log =~ s/.pl// ;
$my_log .= $t->ymd;
$my_log =~ s/.pl// ;
$my_log .= "T";
$my_log .= $t->hms(".");
$my_log .= ".log";
$my_bin = $my_log;
sub logger {
	my $logmessage = shift;
	open my $logfile, ">>", "$my_log" or die "Could not open $my_log: $!";
	say $logfile $logmessage;
}
&logger("This log ($my_log) created for printing %IP and %TCP");
&logger("\tfor own understanding of the core functionality of this script,");
&logger("\tfor text, with sub logger.");
&logger("There can also be $my_bin<...>(,_d).bin");
&logger("\tfor binary snippets/data with sub(s) binner(,_d).");

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
	&Print_Header2();
	
	### Determine Session and Stream time order
	%Index = (); %Image = (); %ExtImage = (); %GETPOST = ();
	&Sort_Index();
	
	#
	#  Process %TCP and create session* output files, write %Index
	#
	&Process_TCP_Sessions();
	
	#
	#  Create Index Files from %Index
	#
	&Create_Index_Files();
	&Create_Log_Files();
	
	###############
	# --- END ---
	#
	&Print_Footer1();
}



#####################
# --- SUBROUTINES ---

# (Most of these subroutines are used as shortcuts to code, not traditional
#  scoped subroutines as with other languages)



# Open_Input_File - open the packet trace specified. This checks the header
#	of the file to determine whether it is a tcpdump/libpcap
#	trace (including several styles of tcpdump/libpcap). And there are new (or
#	new heuristics) to add code for. If ever I find time.
#
sub Open_Input_File {
	
	my $infile = shift;
	my ($length,$size);
	
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
	
	### Print status
	print "Reading file contents,\n" unless $Arg{quiet};
	$SIZE = -s $infile;
	#&logger("\$SIZE: $SIZE");
	
	#
	#  Try to determine if this is a tcpdump file
	#
	($ident) = unpack('a8',$header);
	
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
		
		### Print status summary
		unless ($Arg{quiet}) {
			$bytes += $record_size;
			if (($packet % 16) == 0) {
				printf("%s %2.0f%% (%d/%d)","\b"x24,
				 (100*$bytes/$SIZE),$bytes,$SIZE);
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
		#$my_ether_data = unpack('H*',$ether_data);
		#&logger("\$ether_dest,\$ether_src,\$ether_type,\$my_ether_data;");
		#&logger("$ether_dest,$ether_src,$ether_type,$my_ether_data;");
		&logger("\$ether_dest,\$ether_src,\$ether_type");
		&logger("$ether_dest,$ether_src,$ether_type");
		&logger("--------------------------------------------------");
		
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
			&logger("$lptype,$lladdr_type,$lladdr_len,$ether_src,$ll_dummy,$ether_type");
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
		($ip_verNihl,$ip_rest) = unpack('Ca*',$ether_data);	# ihl ip header length
		&logger("\$ip_verNihl");
		&logger("$ip_verNihl");
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
			&logger("\$ip_verNihl,\$ip_tos,\$ip_length,\$ip_ident,\$ip_flagNfrag,");
			&logger("\$ip_ttl,\$ip_protocol,\$my_ip_checksum,\ at ip_src[0..3],at ip_dest[0..3] ");
			&logger("= the_unpack(CCnnnCCa2CCCCCCCCa*,\$ether_data");
			#my $my_ether_data = unpack('H*', $ether_data);
			#&logger("$ip_verNihl,$ip_tos,$ip_length,$ip_ident,$ip_flagNfrag,$ip_ttl,");
			#&logger("$ip_protocol,$ip_checksum,@ip_src[0..3],@ip_dest[0..3]");
			#&logger("= unpack('CCnnnCCa2CCCCCCCC',$my_ether_data");
			my $my_ip_checksum = unpack('H*', $ip_checksum);
			&logger("$ip_verNihl,$ip_tos,$ip_length,$ip_ident,$ip_flagNfrag,");
			&logger("$ip_ttl,$ip_protocol,$my_ip_checksum,@ip_src[0..3],@ip_dest[0..3]");
			
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
			&logger("$ip_dlength = $ip_length - $ip_options_num - 20");
			# This actually unpacks it into $logfile, but illegible
			#&logger("($ip_data,$trailers) = unpack(\"a${ip_dlength}a*\",$ip_data);");
			&logger("(\$ip_data,\$trailers) = the_unpack (a\${ip_dlength}a*,\$ip_data);");
			&logger("\$ip_data,\$trailers: REMOVED,$trailers");
			
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
			}
			if (($ip_MF == 1) || ($ip_frag > 0)) {
				$IP{time}{$packet_timefull}{fragged} = 1;
			}
		} else {
			$start_time = $IP{id}{$ip_id}{StartTime};
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
	@Times = sort { $a <=> $b } ( keys(%{$IP{time}}) );
	foreach $time (@Times) {
		
		### Print status summary
		unless ($Arg{quiet}) {
			if (($packet % 16) == 0) {
				printf("%s %2.0f%% (%d/%d)","\b"x32,
				 (100*$packet/$packets),$packet,$packets);
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
		# But this goes on based on "Store IP data in %IP so..." some 60 lines above.
		# Uncomment for testing/learning/figuring out. Not sorted:
		#for my $key ( keys(%{$IP{time}})) {
		#	&logger("\$key: $key");
		#	print "$key => $IP{time}{$key}{ver}\n";
		#	&logger("\$key => \$IP{time}{\$key}{ver}");
		#	&logger("$key => $IP{time}{$key}{ver}");
		#	print "$key => $IP{time}{$key}{src}\n";
		#	&logger("\$key => \$IP{time}{\$key}{src}");
		#	&logger("$key => $IP{time}{$key}{src}");
		#	print "$key => $IP{time}{$key}{dest}\n";
		#	&logger("\$key => \$IP{time}{\$key}{dest}");
		#	&logger("$key => $IP{time}{$key}{dest}");
		#	print "$key => $IP{time}{$key}{protocol}\n";
		#	&logger("\$key => \$IP{time}{\$key}{protocol}");
		#	&logger("$key => $IP{time}{$key}{protocol}");
		#	sub spacer{ print '-' x 50, "\n"; }
		#	$spacer_m=&spacer;
		#	&logger("--------------------------------------------------");
		#}
		# Sorted:
		#for my $key ( sort { $a <=> $b } ( keys(%{$IP{time}})) ) {
		#	&logger("\$key: $key");
		#	print "$key => $IP{time}{$key}{ver}\n";
		#	&logger("\$key => \$IP{time}{\$key}{ver}");
		#	&logger("$key => $IP{time}{$key}{ver}");
		#	print "$key => $IP{time}{$key}{src}\n";
		#	&logger("\$key => \$IP{time}{\$key}{src}");
		#	&logger("$key => $IP{time}{$key}{src}");
		#	print "$key => $IP{time}{$key}{dest}\n";
		#	&logger("\$key => \$IP{time}{\$key}{dest}");
		#	&logger("$key => $IP{time}{$key}{dest}");
		#	print "$key => $IP{time}{$key}{protocol}\n";
		#	&logger("\$key => \$IP{time}{\$key}{protocol}");
		#	&logger("$key => $IP{time}{$key}{protocol}");
		#	sub spacer{ print '-' x 50, "\n"; }
		#	$spacer_m=&spacer;
		#	&logger("--------------------------------------------------");
		#}
		
		#
		#  Reassemble IP frags
		#
		if (defined $IP{time}{$time}{fragged}) {
			@IP_Frags = sort {$a <=> $b} (keys(%{$IP{time}{$time}{frag}}));
		
			### If never recieved the start of the packet, skip
			if ($IP_Frags[0] != 0) { next; }
		
			foreach $ip_frag (@IP_Frags) {
				$ip_data .= $IP{time}{$time}{frag}{$ip_frag};
			}
		} else {
			$ip_data = $IP{time}{$time}{frag}{0};
		}
		$length = length($ip_data);
		
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
	my $copy;
	
	#-------------------------------------------------------------------
	#
	#  TCP
	#
	
	### Unpack TCP data
	($tcp_src_port,$tcp_dest_port,$tcp_seq,$tcp_ack,$tcp_offset,$tcp_flags,
	 $tcp_header_rest,$tcp_data) = unpack('nnNNCCa6a*',$ip_data);
	
	### Strip off TCP options, if present
	$tcp_offset = $tcp_offset >> 4;		# chuck out reserved bits
	$tcp_offset = $tcp_offset << 2;		# now times by 4
	$tcp_options_num = $tcp_offset - 20;
	if ($tcp_options_num > 0) {
		($tcp_options,$tcp_data) =
		 unpack("a${tcp_options_num}a*",$tcp_data);
	}
	
	### Fetch length and FIN,RST flags
	$tcp_length_data = length($tcp_data);
	$tcp_fin = $tcp_flags & 1;
	$tcp_syn = $tcp_flags & 2;
	$tcp_rst = $tcp_flags & 4;
	$tcp_ack = $tcp_flags & 16;
	
	$copy = $tcp_data;
	
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
	}
	
	#
	#  Flag this session as a Partial if tcpdump
	#  confesses to dropping packets.
	#
	$TCP{id}{$session_id}{Partial}++ if $drops;
	
	### Store size
	$TCP{id}{$session_id}{size} += length($tcp_data);
	
	### Store the packet timestamp for the first seen packet
	if (! defined $TCP{id}{$session_id}{StartTime}) {
		$TCP{id}{$session_id}{StartTime} = $time;
		
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
		}
	}
	
	### Store the packet timestamp in case this is the last packet
	$TCP{id}{$session_id}{EndTime} = $time;
	
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
		
		#
		#  Determine the service - usually by the lowest numbered port, eg,
		#  ports 51321 and 23 would give 23 (telnet).
		#
		$ip_src = $TCP{id}{$session_id}{src};
		$ip_dest = $TCP{id}{$session_id}{dest};
		$tcp_src_port = $TCP{id}{$session_id}{src_port};
		$tcp_dest_port = $TCP{id}{$session_id}{dest_port};
		($service,$client) = &Pick_Service_Port("TCP",$session_id,
		 $tcp_src_port,$tcp_dest_port);
		
		### Fetch text name for this port
		$service_name = $Services_TCP{$service} || $service || "0";
		
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
			$rawboth .= $TCP{id}{$session_id}{time}{$time}{data};
		}
		$length = length($rawboth);
		
		#
		# --- Check for Min and Max size ---
		#
		next if $length < $Arg{minbytes};
		next if (($Arg{maxbytes} != 0) && ($length > $Arg{maxbytes}));
		
		### Print status line
		$numtext = sprintf("%04d",$number);
		printf "%6s  %-45s  %s\n",$numtext,$session_id,$service_name
		 unless $Arg{quiet};
		
		
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
		
		
		#
		# --- Save Index data to Memory ---
		#
		
		## Fetch times
		$starttime = scalar localtime($TCP{id}{$session_id}{StartTime});
		$duration = ($TCP{id}{$session_id}{EndTime} -
		 $TCP{id}{$session_id}{StartTime});
		$duration = sprintf("%.0f",$duration);
		
		### Generate session strings
		($id_text,$id_html) = &Generate_TCP_IDs($session_id);
		
		### Construct HTML table row containing session data
		# JL: Added id attribute as link target
		$Index{HTML}[$number] = "<tr id=\"$number\">" .
		 "<td><i>$number.</i></td>" .
		 "<td><b>$starttime</b></td><td>$duration s</td><td> " .
		 "<font color=\"blue\">$id_html " .
		 "</font></td><td> <font color=\"red\">" .
		 "$service_name</font></td><td> <font color=\"green\"> " .
		 "$length bytes</font></td><td>\n";
		
		### Construct text line containing session data
		$Index{Text}[$number] .= sprintf("%-4s %-45s %-10s %8s bytes\n",$number,
		 $id_text,"($service_name)",$length);
		
		### Construct image info line (in case it is needed)
		$Image{HTML}[$number]{info} = "<tr><td><i>$number.</i>" .
		 "</td><td><b>$starttime</b></td><td> " .
		 "<font color=\"blue\">$id_html </font></td><td><td>\n";
		
		### JL: Construct external image info line (in case it is needed)
		$ExtImage{HTML}[$number]{info} = "<tr><td><i>$number.</i>" .
		 "</td><td><b>$starttime</b></td><td> " .
		 "<font color=\"blue\">$id_html </font></td><td><td>\n";
		
		### Construct GETPOST info line (in case it is needed)
		# starttime and host:port... are formatted differently so that
		# they are narrow and leave more room for the sub table.
		$GETPOST{HTML}[$number]{info} = "<tr><td><i>$number.</i>" .
		 "</td><td><b>$starttime</b></td><td> " .
		 "<font color=\"blue\">$id_html </font></td><td><td>\n";
		
		
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
			
			### Update HTML index table with link
			$Index{HTML}[$number] .= "<li><a href=\"$filename\">raw</a> ";
			
			#
			#  Save ".raw1" file, server->client 1-way data assembled.
			#
			$filename = "session_${numtext}.${service_name}.raw1";
			open (OUT,">$filename") ||
			 die "ERROR13: creating $filename $!\n";
			binmode(OUT);		# for backward OSs
			print OUT &TCP_Follow_RawA($session_id);
			close OUT;
			
			### Update HTML index table with link
			$Index{HTML}[$number] .= "<a href=\"$filename\">raw1</a> ";
			
			#
			#  Save ".raw2" file, client->server 1-way data assembled.
			#
			$filename = "session_${numtext}.${service_name}.raw2";
			open (OUT,">$filename") ||
			 die "ERROR14: creating $filename $!\n";
			binmode(OUT);		# for backward OSs
			print OUT &TCP_Follow_RawB($session_id);
			close OUT;
			
			### Update HTML index table with link
			$Index{HTML}[$number] .= "<a href=\"$filename\">raw2</a></li> ";
		}
		
		next unless $Arg{output_apps};
		
		#
		# --- Save Session as HTML ---
		#
		if ($Arg{Save_As_TCP_HTML}{$service} || $Arg{output_allhtml}) {
			&Save_Both_HTML("TCP",$session_id,$number,$service_name,
			 $id_html);
		}
		
		
		#
		# --- Save Hex Dump as HTML ---
		#
		if ($Arg{output_hex}) {
			my ($text, $html) = &Process_Hex("TCP", $session_id);
			&Save_Hex_Text("TCP", $session_id, $number, $service_name,
				$id_text, $text);
			&Save_Hex_HTML("TCP", $session_id, $number, $service_name,
				$id_html, $html);
		}
		
		#
		# --- Process Application Data ---
		#
		if ($service == 80 or $service == 8080 or
			$service == 3127 or $service == 1080 or
			# JL: 8118 is HTTP(S) via polipo.
			#     9050 is Tor (socks4a, but works good enough for me).
			$service == 8118 or $service == 9050)  {
				&Save_HTTP_Files($session_id,$number,$service_name);
				&Process_HTTP($session_id,$number);
		}
		
		$raw = &TCP_Follow_RawB($session_id);
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
		}
		$i++; # speed
		$partnum++;
		if ($request =~ /^GET \S* HTTP/) {
			
			### JL: Get the host string, referer, and cookies.
			($host) = $request =~ /\sHost:\s(\S*)\s/is;
			($referer) = $request =~ /\sReferer:\s(\S*)/is;
			($cookie) = $request =~ /\sCookie:\s(\S*)/is;
			($setcookie) = $reply =~ /\sSet-Cookie:\s(\S*)/is;
			
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
			
			### Store the log entry
			$HTTPlog{time}{$time} =
				Print_Log_Line($number,$time,$duration,
					$src,$dest,$result,$status,$size,
					"GET",$site,"-","NONE","","-",$type);
			$HTTPtxtlog{time}{$time} =
				Print_TxtLog_Line($number,$time,
					$referer,$cookie,$setcookie,
					"GET",$site);
			$HTTPlog{notempty} = 1;
			
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
		
		### Store the log entry
		$HTTPlog{time}{$time} =
			Print_Log_Line($number,$time,$duration,
				   $src,$dest,$result,$status,$size,
				   "POST",$site,"-","NONE","","-",$type);
		$HTTPtxtlog{time}{$time} =
			Print_TxtLog_Line($number,$time,
				$referer,$cookie,$setcookie,
				"POST",$site);
		$HTTPlog{notempty} = 1;
		
		}
		
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
			#if ($get =~ /=/) {
			
			#
			#  Populate %GETPOST with a table containing the GET data
			#
			if (! defined $GETPOST{HTML}[$number]{query}) {
				$GETPOST{HTML}[$number]{info} .=
				 "<font color=\"red\">GET</font></td><td width=70%>";
				$GETPOST{notempty} = 1;
			} else {
				$GETPOST{HTML}[$number]{query} .= "<hr>\n";
			}
			
			#
			#  Generate table of query key value pairs
			#
			$GETPOST{HTML}[$number]{query} .= "$site<br><table border=1>\n";
			@Terms = split(/&/,$get);
			foreach $term (@Terms) {
				($var,$value) = split(/=/,$term);
				$value =~ tr/+/ /;
				$value =~ s/%([a-f0-9][a-f0-9])/pack("C",hex($1))/egi;
				$value =~ s/</&lt;/g;
				$value =~ s/>/&gt;/g;
				$value =~ s/\n/<br>\n/g;
				$GETPOST{HTML}[$number]{query} .=
				 "<tr><td><b>$var</b></td>" .
				 "<td><font face=\"Courier\">$value</font></td></tr>\n";
			}
			$GETPOST{HTML}[$number]{query} .= "</table>\n";
			#}
			
		} elsif ($request =~ /^POST .* HTTP/) {
		
		### Get the POST strings
		($junk,$post,$junk1) = split(/\n\n|\r\n\r\n/,$request);
		
		# check it looks like a POST
		if ($post =~ /=/) {
			
			#
			#  Populate %GETPOST with a table containing the POST data
			#
			if (! defined $GETPOST{HTML}[$number]{query}) {
				$GETPOST{HTML}[$number]{info} .=
				 "<font color=\"red\">POST</font></td><td width=70%>";
				$GETPOST{notempty} = 1;
			} else {
				$GETPOST{HTML}[$number]{query} .= "<hr>\n";
			}
			
			($site) = $request =~ /^POST (\S*)\s/;
			
			$post =~ s/HTTP .*//s;
			
			#
			#  Generate table of query key value pairs
			#
			$GETPOST{HTML}[$number]{query} .= "$site<br><table border=1>\n";
			@Terms = split(/&/,$post);
			foreach $term (@Terms) {
				($var,$value) = split(/=/,$term);
				$value =~ tr/+/ /;
				$value =~
				 s/%([a-fA-F0-9][a-fA-F0-9])/pack("C", hex($1))/eg;
				$value =~ s/</&lt;/g;
				$value =~ s/>/&gt;/g;
				$value =~ s/\n/<br>/g;
				$GETPOST{HTML}[$number]{query} .=
				 "<tr><td><b>$var</b></td>" .
				 "<td><font face=\"Courier\">$value</font></td></tr>\n";
			}
			$GETPOST{HTML}[$number]{query} .= "</table>\n";
			}
		}
	}
}


# Sort_Index - this creates a sort order for the master index.html, based
#	on the sort argument (defaults to sort by time).
#
sub Sort_Index {

	if ($Arg{sort} eq "size") {
		&Sort_Index_By_Size();
	} elsif ($Arg{sort} eq "type") {
		&Sort_Index_By_Type();
	} elsif ($Arg{sort} eq "ip") {
		&Sort_Index_By_IP();
	} else {
		&Sort_Index_By_Time();
	}
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


# Sort_Index_By_Size - this calculates an appropriate order for the index
#	files based on session size.
#
sub Sort_Index_By_Size {
	my ($session_id,$time,$number);

	#
	#  Determine Session and Stream size order
	#
	foreach $session_id (keys %{$TCP{id}}) {
		$Index{Size_Order}{"TCP:$session_id"} =
		 $TCP{id}{$session_id}{size};
	}
	$number = 0;
	foreach $session (sort {$Index{Size_Order}{$b} <=>
	 $Index{Size_Order}{$a}} keys %{$Index{Size_Order}}) {
		$number++;
		$Index{Sort_Lookup}{$session} = $number;
	}
}


# Sort_Index_By_Type - this calculates an appropriate order for the index
#	files based on session type, followed by time.
#
sub Sort_Index_By_Type {
	my ($service,$tcp_src_port,$tcp_dest_port,$client,$udp_src_port,
	 $udp_dest_port,$session_id,$time,$number);
	
	#
	#  Determine Session and Stream time order
	#
	foreach $session_id (keys %{$TCP{id}}) {
		# Determine the service - usually by the lowest numbered port
		$tcp_src_port = $TCP{id}{$session_id}{src_port};
		$tcp_dest_port = $TCP{id}{$session_id}{dest_port};
		($service,$client) = &Pick_Service_Port("TCP",$session_id,
		 $tcp_src_port,$tcp_dest_port);
		
		$Index{Type_Order}{"TCP:$session_id"}{1} = 1;
		$Index{Type_Order}{"TCP:$session_id"}{2} = $service;
		$Index{Type_Order}{"TCP:$session_id"}{3} =
		 $TCP{id}{$session_id}{StartTime};
	}
	
	# now we sort by TCP->UDP->IP then port then time.
	$number = 0;
	foreach $session (sort {
		$Index{Type_Order}{$a}{1} <=> $Index{Type_Order}{$b}{1} ||
		$Index{Type_Order}{$a}{2} <=> $Index{Type_Order}{$b}{2} ||
		$Index{Type_Order}{$a}{3} <=> $Index{Type_Order}{$b}{3}
	 } keys %{$Index{Type_Order}}) {
		$number++;
		$Index{Sort_Lookup}{$session} = $number;
	}
}


# Sort_Index_By_IP - this calculates an appropriate order for the index
#	files based on client IP, followed by time.
#
sub Sort_Index_By_IP {
	my ($service,$ip,$ip_dest,$ip_src,$client,
	 $session_id,$time,$number,$text,$html,$rest);
	my @IP;
	
	#
	#  Determine Session and Stream time order
	#
	foreach $session_id (keys %{$TCP{id}}) {
		# Determine source IP
		# here we use the same subroutine as the index.html
		# so that they match up.
		($text,$html) = &Generate_TCP_IDs($session_id);
		($ip,$rest) = split(/:/,$text,2);
		
		# Split on IPv4 or IPv6
		$IP = ();
		if ($ip =~ /\./) { @IP = split(/\./,$ip); }
		 else { $IP[0] = $ip; }
		
		$Index{Type_Order}{"TCP:$session_id"}{1} = $IP[0];
		$Index{Type_Order}{"TCP:$session_id"}{2} = $IP[1];
		$Index{Type_Order}{"TCP:$session_id"}{3} = $IP[2];
		$Index{Type_Order}{"TCP:$session_id"}{4} = $IP[3];
		$Index{Type_Order}{"TCP:$session_id"}{5} =
		 $TCP{id}{$session_id}{StartTime};
	}
	
	# now we sort by IP then time
	$number = 0;
	foreach $session (sort {
		$Index{Type_Order}{$a}{1} <=> $Index{Type_Order}{$b}{1} ||
		$Index{Type_Order}{$a}{2} <=> $Index{Type_Order}{$b}{2} ||
		$Index{Type_Order}{$a}{3} <=> $Index{Type_Order}{$b}{3} ||
		$Index{Type_Order}{$a}{4} <=> $Index{Type_Order}{$b}{4} ||
		$Index{Type_Order}{$a}{1} cmp $Index{Type_Order}{$b}{1} ||
		$Index{Type_Order}{$a}{5} <=> $Index{Type_Order}{$b}{5}
	} keys %{$Index{Type_Order}}) {
		$number++;
		$Index{Sort_Lookup}{$session} = $number;
	}
}


# Print_Header1 - print program welcome message.
#
sub Print_Header1 {
	unless ($Arg{quiet}) {
		print "Reading $TYPE log...\n";
		printf "%6s  %-45s  %s\n","Packet",
			"Session (host:port <=> host:port)","Length";
	}
}


# Print_Header2 - print header before loading the file
#
sub Print_Header2 {
	print "\nCreating files...\n" unless $Arg{quiet};
	printf "%6s  %-45s  %s\n","Num","Session (host:port <=> host:port)",
		"Service" unless $Arg{quiet};
}


# Print_Footer1 - print footer at end of program.
#
sub Print_Footer1 {
	if ($Arg{output_index}) {
		print "\nindex.html created.\n" unless $Arg{quiet};
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


# Create_Index_Files - Create the HTML and text index files. This reads
#	%Index and creates the files on disk.
#
sub Create_Index_Files {
	my ($html_index,$html_line,$html_links,$image_empty,$getpost_empty);
	$getpost_empty = $image_empty = "";
	
	if ($Arg{output_index}) {
		
		
		######################
		# --- index.html ---
		
		$image_empty = "(Empty) " unless $Image{notempty};
		$getpost_empty = "(Empty) " unless $GETPOST{notempty};
		$httplog_empty = "(Empty) " unless $HTTPlog{notempty};
		#
		#  Create HTML Index file containing all reports
		#
		open(FILE,">index.html") || die "ERROR22: creating index: $!\n";
		print FILE <<END_HTML;
<html>
<head><title>Chaosreader Report, $Arg{infile}</title></head>
<body bgcolor="white" textcolor="black">
<font size=+3>Chaosreader Report</font><br>
<font size=+1>File: $Arg{infile}, Type: $TYPE, Created at: $the_date</font><p>
<a href="image.html"><font color="blue"><b>Image Report</b></font></a>
 $image_empty - Click here for a report on captured images.<br>
<a href="extimage.html"><font color="blue"><b>External Image Report</b></font></a>
 $image_empty - Click here for a report embedding external images.<br>
<a href="getpost.html"><font color="blue"><b>GET/POST Report</b></font></a>
 $getpost_empty - Click here for a report on HTTP GETs and POSTs.<br>
<a href="$Arg{httplog_name}"><font color="blue"><b>HTTP Proxy Log</b></font></a>
 $httplog_empty - Click here for a generated proxy style HTTP log.<br>
<a href="$Arg{httplog_txt}"><font color="blue"><b>New HTTP Proxy Log</b></font></a>
 $httplog_empty - Click here for HTTP log with referers and Cookie indicators.<p>
<font size=+2>TCP Sessions</font><br>
<table border=2>
END_HTML
		for ($html_index=0; $html_index <= $#{$Index{HTML}}; $html_index++) {
			$html_line = $Index{HTML}[$html_index];
			next unless defined $html_line;
			print FILE "$html_line </td></tr>\n";
		}
		print FILE <<END_HTML;
</body>
</html>
END_HTML
		
		
		######################
		# --- index.text ---
		
		#
		#  Create Text index file
		#
		open(FILE,">index.text") || die "ERROR23: creating index: $!\n";
		print FILE "TCP Sessions\nFile: $Arg{infile}, "
		 . "Type: $TYPE, Created at: $the_date\n\n";
		print FILE @{$Index{Text}};
		close FILE;
		
		
		######################
		# --- image.html ---
		
		#
		#  Create HTML Image Index file to display images
		#
		open(FILE,">image.html") || die "ERROR24: creating index: $!\n";
		print FILE <<END_HTML;
<html>
<head><title>Chaosreader Image Report</title></head>
<body bgcolor="white" textcolor="black">
<font size=+3>Chaosreader Image Report</font><br>
<font size=+1>Created at: $the_date, Type: $TYPE</font><p>
<font size=+2>Images</font><br>
<table border=2>
END_HTML
		for ($html_index=0; $html_index <= $#{$Index{HTML}}; $html_index++) {
			$html_line = $Image{HTML}[$html_index]{info};
			$html_links = $Image{HTML}[$html_index]{links};
			next unless defined $html_links;
			print FILE "$html_line $html_links </td></tr>\n";
		}
		print FILE <<END_HTML;
</table><p>
</body>
</html>
END_HTML
		
		
		######################
		# --- extimage.html ---
		
		#
		#  Create HTML External Image Index file to display images
		#
		open(FILE,">extimage.html") || die "ERROR24: creating index: $!\n";
		print FILE <<END_HTML;
<html>
<head><title>Chaosreader External Image Report</title></head>
<body bgcolor="white" textcolor="black">
<font size=+3>Chaosreader External Image Report</font><br>
<font size=+1>Created at: $the_date, Type: $TYPE</font><p>
<font size=+2>Images</font><br>
<table border=2>
END_HTML
		for ($html_index=0; $html_index <= $#{$Index{HTML}}; $html_index++) {
			$html_line = $ExtImage{HTML}[$html_index]{info};
			$html_links = $ExtImage{HTML}[$html_index]{links};
			next unless defined $html_links;
			print FILE "$html_line $html_links </td></tr>\n";
		}
		print FILE <<END_HTML;
</table><p>
</body>
</html>
END_HTML
		
		
		######################
		# --- getpost.html ---
		
		#
		#  Create HTML GETPOST Index file to show HTTP GETs and POSTs
		#
		open(FILE,">getpost.html") || die "ERROR25: creating index: $!\n";
		print FILE <<END_HTML;
<html>
<head><title>Chaosreader GET/POST Report</title></head>
<body bgcolor="white" textcolor="black">
<font size=+3>Chaosreader GET/POST Report</font><br>
<font size=+1>Created at: $the_date, Type: $TYPE</font><p>
<font size=+2>HTTP GETs and POSTs</font><br>
<table border=2>
END_HTML
		for ($html_index=0; $html_index <= $#{$GETPOST{HTML}}; $html_index++) {
			$html_line = $GETPOST{HTML}[$html_index]{info};
			$html_links = $GETPOST{HTML}[$html_index]{query};
			next unless defined $html_links;
			print FILE "$html_line $html_links </td></tr>\n";
		}
		print FILE <<END_HTML;
</table><p>
</body>
</html>
END_HTML
	
	}
}



# Create_Index_Master - Create the HTML and text master index files. This
#	reads @Master and creates the files on disk.
#
sub Create_Index_Master {
	
	my ($start,$end,$dir,$file,$index,$duration);
	
	if ($Arg{output_index}) {
		
		#
		#  Create most recent link
		#
		
		$dir = $Master[$#Master]{dir};
		$recentname = "most_recent_index";
		unlink("$recentname");
		# don't die on symlink error, it's not essential
		symlink("$dir","$recentname");
		
		#
		#  Create HTML Index file containing all reports
		#
		open(FILE,">index.html") || die "ERROR26: creating index: $!\n";
		print FILE <<END_HTML;
<html>
<head><title>Chaosreader Master Index</title></head>
<body bgcolor="white" textcolor="black" vlink="blue">
<font size=+3>Chaosreader Master Index</font><br>
<font size=+1>Created at: $the_date, Type: $TYPE</font><p>
<a href="$recentname/index.html"><font color="red">
<b>Most Recent Report</b></font></a>
 - Click here for the most recent index, and click reload for updates.<p>
<font size=+2>Chaosreader Reports</font><br>
<table border=2>
END_HTML
		for ($index=0; $index <= $#Master; $index++) {
			$start = $Master[$index]{starttime};
			$end = $Master[$index]{endtime};
			$dir = $Master[$index]{dir};
			$file = $Master[$index]{file};
			$size = $Master[$index]{size};
			$duration = $Master[$index]{duration};
			$html_line = "<tr><td><i>". ($index+1) . "</i></td>" .
			 "<td><b>$start</b></td><td><b>$end</b></td>\n" .
			 "<td>$duration s</td>" . "<td><font color=\"green\"> " .
			 "$size bytes</font></td>" .
			 "<td><a href=\"$dir/index.html\">$dir/$file</a></td></tr>\n";
			print FILE "$html_line </td></tr>\n";
		}
		print FILE <<END_HTML;
</table><p>
END_HTML
		print FILE <<END_HTML;
</table>
</body>
</html>
END_HTML
		
		#
		#  Create Text index file
		#
		open(FILE,">index.text") || die "ERROR27: creating index: $!\n";
		print FILE "Master Indexes\nCreated at: $the_date, Type: $TYPE\n\n";
		for ($index=0; $index <= $#Master; $index++) {
			$start = $Master[$index]{starttime};
			$end = $Master[$index]{endtime};
			$dir = $Master[$index]{dir};
			$file = $Master[$index]{file};
			$size = $Master[$index]{size};
			$duration = $Master[$index]{duration};
			printf FILE "%-25s %3s s %8s b  %s\n",$start,$duration,
				$size,"$dir/index.text";
		}
		close FILE;
	}
}


# JL: Print a line for the HTTPlog
#
sub Print_Log_Line {
	my $number = shift;
	my $time = shift;
	my $duration = shift;
	my $src = shift;
	my $dest = shift;
	my $result = shift;
	my $status = shift;
	my $size = shift;
	my $method = shift;
	my $site = shift;
	my $type = shift;
	
	if ($Arg{httplog_html}) {
		sprintf("<pre><a href=\"index.html#%d\">%d</a>" .
			" %9d.%03d %6d " .
			"%-15s %-15s %s/%03d %d %s %s %s %s%s/%s %s</pre><br/>\n",
			$number,$number,
			int($time),(($time - int($time))*1000),($duration*1000),
			$src,$dest,$result,$status,$size,
			$method,$site,"-","NONE","","-",$type);
	} else {
		sprintf("%9d.%03d %6d %s %s/%03d %d %s %s %s %s%s/%s %s\n",
			int($time),(($time - int($time))*1000),($duration*1000),
			$src,$result,$status,$size,
			$method,$site,"-","NONE","","-",$type);
	}
}

# JL: Print a line for the new text HTTPlog
#
sub Print_TxtLog_Line {
	my $number = shift;
	my $time = shift;
	my $referer = shift;
	my $cookie = shift;
	my $setcookie = shift;
	my $method = shift;
	my $site = shift;
	
	($second, $minute, $hour, $dayOfMonth, $month, $yearOffset, $dayOfWeek, $dayOfYear, $daylightSavings) = localtime($time);
	$referer = "Referer: " . $referer if $referer ne "";
	$cookie = "Cookie sent." if $cookie ne "";
	$setcookie = "Sets cookie." if $setcookie ne "";
	sprintf("%-4s %02d:%02d:%02d %s %s %s %s %s\n",
		$number,$hour,$minute,$second,
		$method,$site,$referer,$cookie,$setcookie);
}


# Create_Log_Files - create log files such as the HTTP log.
#
sub Create_Log_Files {
	#BDG some memory debug
	#system("pmap -x $$");
	
	#
	#  Create httplog file
	    # JL: Don't use hardcoded filename
	#
	open(FILE,">$Arg{httplog_name}") || die "ERROR29: creating HTTP log: $!\n";
	foreach $time (sort { $a <=> $b }(keys (%{$HTTPlog{time}}))) {
		print FILE $HTTPlog{time}{$time};
	}
	
	close FILE;
	
	open(FILE,">$Arg{httplog_txt}") || die "ERROR29: creating HTTP text log: $!\n";
	
	foreach $time (sort { $a <=> $b }(keys (%{$HTTPtxtlog{time}}))) {
		print FILE $HTTPtxtlog{time}{$time};
	}
	
	close FILE;
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


# Desex_HTML - Removes HTML tags ("<" and ">") from data, so that it no
#		longer interferes when printed as HTML.
#
sub Desex_HTML {
	### Input
	my $data = shift;
	
	### Process
	# remove "<" and ">"s
	$data =~ s/</&lt;/g;
	$data =~ s/>/&gt;/g;
	
	### Return
	return $data;
}



# Process_BothHTML - Process the HTML 2-way session. Remove binary junk
#			that doesn't render well in a browser.
#
sub Process_BothHTML {
	### Input
	my $type = shift;
	my $session_id = shift;
	my $plain = shift;
	my $wrapped = "";
	my $index = 0;
	my $counter = 0;
	my $intag = 0;
	my ($char,$data);
	
	if ($type eq "TCP") {
		$data = $TCP{id}{$session_id}{BothHTML};
	}
	
	### Process (order dependant)
	$data =~ s/font color="red">     \0</font color="red"></g;
	$data =~ tr/\040-\176\n\r\f/./c;		# max 376, was 245
	if (defined $plain) {
		# This is a plain style of line wrap
		$data =~ s/([^\n\f<>]{$WRAP})/$&\n/g;
	} else {
		# This is a fancy line wrap, a green ">" starts the wrapped lines
		$data =~ s/([^\n\f<>]{$WRAP})/$&\n<font color="green">&gt;<\/font>/g;
	}
	
	### Save
	if ($type eq "TCP") {
		$TCP{id}{$session_id}{BothHTML} = $data;
	}
}

# Process_This_HTML - Process the HTML 2-way session. Remove binary junk
#			that doesn't render well in a browser.
#
sub Process_This_HTML {
	### Input
	my $data = shift;
	my $plain = shift;
	my $wrapped = "";
	my $index = 0;
	my $counter = 0;
	my $intag = 0;
	my ($char);
	
	### Process (order dependant)
	$data =~ s/font color="red">     \0</font color="red"></g;
	$data =~ tr/\040-\176\n\r\f/./c;		# max 376, was 245
	if (defined $plain) {
		# This is a plain style of line wrap
		$data =~ s/([^\n\f<>]{$WRAP})/$&\n/g;
	} else {
		# This is a fancy line wrap, a green ">" starts the wrapped lines
		$data =~ s/([^\n\f<>]{$WRAP})/$&\n<font color="green">&gt;<\/font>/g;
	}
	
	return $data;
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


# Save_Both_HTML - Save bidirectional (coloured) data into a html file.
#
sub Save_Both_HTML {
	my ($filename);
	
	### Input
	my $type = shift;
	my $session_id = shift;
	my $number = shift;
	my $service_name = shift;
	my $session_text = shift;
	my $numtext = sprintf("%04d",$number);
	my ($base,$raw);
	
	$session_text = $session_id unless defined $session_text;
	
	### Processing
	$session_text =~ s/,/ <-> /;
	
	### Checks
	$ext = "";
	$session_data = "";
	if ($type eq "TCP") {
		$base = "session";
		#
		# Note, the following is similar code for TCP, UDP and ICMP.
		# However UDP and ICMP use a simple strategy to store and fetch
		# the processed HTML; whereas TCP uses a complex yet memory
		# efficient strategy. This is intentional - the way TCP has
		# been stored has been tuned to reduce memory usage, as TCP has
		# the bulk of the data (and the bulk of the memory problem). This
		# has not been necessary with UDP and ICMP (yet).
		#
		if ($TCP{id}{$session_id}{BothHTML} ne "") {
			#
			#  If the BothHTML report has already been calculated, fetch
			#
			$session_data = $TCP{id}{$session_id}{BothHTML};
		} else {
			#
			#  Generate a BothHTML report by following packets by time
			#
			foreach $time (sort {$a <=> $b}
				(keys (%{$TCP{id}{$session_id}{time}}))) {
				$raw = $TCP{id}{$session_id}{time}{$time}{data};
				$raw = &Desex_HTML($raw);
				next unless length($raw);
				if ($TCP{id}{$session_id}{time}{$time}{dir} eq "A") {
					$session_data .= "<font color=\"blue\">$raw</font>";
					} else {
						$session_data .= "<font color=\"red\">$raw</font>";
					}
				}
				$session_data = &Process_This_HTML($session_data);
				$base = "session";
				if ($TCP{id}{$session_id}{Partial}) { $ext = ".partial"; }
		}
	
	} else {
		$base = "are_belong_to_us";
	}
	
	### Do nothing if there is no data ("26" is mostly due to colour tags)
	return unless ((defined $session_data)&&(length($session_data) > 26));
	
	### Output
	$filename = "${base}_${numtext}.${service_name}${ext}.html";
	open (OUT,">$filename") || die "ERROR30: file create, $filename: $!\n";
	binmode(OUT);
	print OUT "<HTML>\n<HEAD><TITLE>$number</TITLE></HEAD>" .
	"<BODY bgcolor=\"white\">\n" .
	"<H1>$service_name: $session_text</H1>\n" .
	"<H2>File $Arg{infile}, Session $number</H2>\n" .
	"<PRE WRAP=\"virtual\">\n" .
	$session_data . "</PRE>\n</BODY>\n</HTML>\n";
	close OUT;
	
	### Global Vars
	my $length = length($session_data);
	$Index{HTML}[$number] .= "<li><a href=\"$filename\">as_html</a></li>\n";
	$Index{Text}[$number] .= sprintf("%-4s %-45s %-10s %8s bytes\n",
	 '"' , "   $filename","",$length);
}


# Save_Hex_HTML - Save bidirectional (coloured) hex data into a html file.
#
sub Save_Hex_HTML {
	my ($filename);
	
	### Input
	my $type = shift;
	my $session_id = shift;
	my $number = shift;
	my $service_name = shift;
	my $session_text = shift;
	my $session_data = shift;
	my $numtext = sprintf("%04d",$number);
	my ($base);
	
	$session_text = $session_id unless defined $session_text;
	$session_data = "" unless defined $session_data;
	
	
	### Processing
	$session_text =~ s/,/ <-> /;
	
	### Checks
	$ext = "";
	if ($type eq "TCP") {
		$base = "session";
		if ($TCP{id}{$session_id}{Partial}) { $ext = ".partial"; }
	}
	
	### Output
	$filename = "${base}_${numtext}.${service_name}${ext}.hex.html";
	open (OUT,">$filename") || die "ERROR31: file create, $filename: $!\n";
	binmode(OUT);
	print OUT "<HTML>\n<HEAD><TITLE>$number</TITLE></HEAD>" .
	"<BODY bgcolor=\"white\">\n" .
	"<H1>$service_name: $session_text</H1>\n" .
	"<H2>File $Arg{infile}, Session $number</H2>\n" .
	"<PRE WRAP=\"virtual\">\n" .
	$session_data . "</PRE>\n</BODY>\n</HTML>\n";
	close OUT;
	
	### Global Vars
	my $length = length($session_data);
	$Index{HTML}[$number] .= "<li>";
	$Index{HTML}[$number] .= "<a href=\"$filename\">hex</a></li>\n";
	$Index{Text}[$number] .= sprintf("%-4s %-45s %-10s %8s bytes\n",
	 '"' , "   $filename","",$length);
}


# Save_Hex_Text - Save bidirectional hex data into a text file.
#
sub Save_Hex_Text {
	my ($filename);
	
	### Input
	my $type = shift;
	my $session_id = shift;
	my $number = shift;
	my $service_name = shift;
	my $session_text = shift;
	my $session_data = shift;
	my $numtext = sprintf("%04d",$number);
	my ($base);
	
	$session_text = $session_id unless defined $session_text;
	$session_data = "" unless defined $session_data;
	
	### Processing
	$session_text =~ s/,/ <-> /;
	
	### Checks
	$ext = "";
	if ($type eq "TCP") {
		$base = "session";
		if ($TCP{id}{$session_id}{Partial}) { $ext = ".partial"; }
	}
	
	### Output
	$filename = "${base}_${numtext}.${service_name}${ext}.hex.text";
	open (OUT,">$filename") || die "ERROR32: file create, $filename: $!\n";
	binmode(OUT);
	print OUT "$service_name: $session_text\n" .
	"File $Arg{infile}, Session $number\n\n$session_data\n";
	close OUT;
	
	### Global Vars
	my $length = length($session_data);
	$Index{Text}[$number] .= sprintf("%-4s %-45s %-10s %8s bytes\n",
	 '"' , "   $filename","",$length);
}


# Save_HTTP_Files - Save HTTP components.
#
sub Save_HTTP_Files {
	my ($filename);
	my $session_id = shift;
	my $number = shift;
	my $service_name = shift;
	my $numtext = sprintf("%04d",$number);
	
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
				print "Unkown Content-Type $content_type.";
				print "  May want to extend MIME types.\n";
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
		$Index{HTML}[$number] .= "<li><a href=\"$filename\">$filename" .
			"</a> $length bytes</li>\n";
		$Index{Text}[$number] .= sprintf("%-4s %-45s %-10s %8s bytes\n",
			'"' , "   $filename","",$length);
		if (&Is_Image($http_type) or
			&Is_Image($file_extension)) { # JL: Also check file ext.
			$Image{HTML}[$number]{links} .= "<img src=\"$filename\"> ";
			$Image{notempty} = 1;
			# JL: Remember this part as image.
			$ExtImage{HTML}[$number]{parts}[$partnum] = 1;
		}
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


# TCP_Follow_RawB - process session by TCP Seq numbers 1-way.
#			(TCP ASSEMBLY)
#
sub TCP_Follow_RawB {
	my $session_id = shift;
	my $raw = "";
	
	#
	#  Assemble TCP Sessions. Each hash contains session_ids as keys,
	#  and the value points to another hash of sequence numbers and data.
	#  %TCP{id}{}{Aseq} is input, and %TCP{id}{}{RawA} is output.
	#
	@Seqs = keys (%{$TCP{id}{$session_id}{Bseq}});
	foreach $seq (sort { $a <=> $b } @Seqs) {
		$raw .= ${$TCP{id}{$session_id}{Bseq}{$seq}};
	}
	
	return $raw;
}


# Pick_Service_Port - pick which port is the server. Usually is the lower
#	number, however check if the direction is already known (eg SYN).
#	The port arguments will not often be needed.
#
# NOTE: This code is different to Generate_TCP_IPs - which does the "<->"'s
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

# Retrieve DNS name for IP address based on DNS traffic of this capture.
# If possible, retrieve the original name for a CNAME of the IP address.
#
sub Get_Name_For_IP {
	my $ip_addr = shift;
	my $result = $ip_addr;
	if (defined $DNS{$ip_addr}) {
	$result = $DNS{$ip_addr};
	while (defined $DNS{$result}) {
	    $result = $DNS{$result};
	}
	}
	return $result;
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
	} else {
	        if ($Arg{prefer_dns}) {
		    $ip_src = &Get_Name_For_IP($ip_src);
		    $ip_dest = &Get_Name_For_IP($ip_dest);
		}
		$text = "$ip_src:$tcp_src_port <-> $ip_dest:$tcp_dest_port";
		$html = "$ip_src:$tcp_src_port &lt;-&gt; " .
		 "$ip_dest:$tcp_dest_port";
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
	$length = read(INFILE,$header_rec,($integerSize * 2 + 8));
	&logger("\$length = read(INFILE,\$header_rec,(\$integerSize * 2 + 8));");
	my $my_header_rec = unpack('H*', $header_rec);
	my $my_integerSizeBy2p8=($integerSize * 2 + 8);
	&logger("$length = read(INFILE,$my_header_rec,$my_integerSizeBy2p8);");
	
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
		&logger("$tcpdump_seconds,$tcpdump_msecs,$tcpdump_length, $tcpdump_length_orig,$my_header_rec;");
		# While logger unique filename creation is based on using Time::Piece,
		# binner and binner_d add $tcpdump_(seconds,msecs), so I defined them
		# here. They can be called any time after Read_Tcpdump_Record has been
		# run, I guess.
		$my_bin = $my_log;
		$my_bin .= "$tcpdump_seconds";
		$my_bin .= "$tcpdump_msecs";
		$my_bin_d = "$my_bin";
		$my_bin_d .= "_d";
		$my_bin_d .= ".bin";
		$my_bin .= ".bin";
		sub binner {	# logger (at top) is straight from perlintro, and binner is
						# copy-paste-n-modify on it, with a pun ending in -er.
			my $binmessage = shift;
			open my $binfile, ">>", "$my_bin" or die "Could not open $my_bin: $!";
			print $binfile $binmessage;
			&logger("created/used $my_bin");
		}
		sub binner_d {	# see note on binner above, _d is for data, put in data
						# that will make for streams/sessions once cat'ed
						# together
			my $binmessage = shift;
			open my $binfile_d, ">>", "$my_bin_d" or die "Could not open $my_bin_d: $!";
			print $binfile_d $binmessage;
		}
		# If you uncomment these, you might get just a little bit closer to
		# figuring out the code, if you apply a lot of perldoc
		# reading/comparisons/other reading/learning where necessary.
		&binner("$header_rec");
		open my $binfile, "<", "$my_bin" or die "Could not open $my_bin: $!";
		my $o_tcpdump_seconds;
		$length = read($binfile,$o_tcpdump_seconds,4);
		&binner("$o_tcpdump_seconds");
		my $my_o_tcpdump_seconds;
		$my_o_tcpdump_seconds = unpack('V',$o_tcpdump_seconds);
		&logger("\$my_o_tcpdump_seconds: $my_o_tcpdump_seconds");
		my $o_tcpdump_msecs;
		$length = read($binfile,$o_tcpdump_msecs,4);
		&binner("$o_tcpdump_msecs");
		my $my_o_tcpdump_msecs;
		$my_o_tcpdump_msecs = unpack('V',$o_tcpdump_msecs);
		&logger("\$my_o_tcpdump_msecs: $my_o_tcpdump_msecs");
		my $o_tcpdump_length;
		$length = read($binfile,$o_tcpdump_length,4);
		&binner("$o_tcpdump_length");
		my $my_o_tcpdump_length;
		$my_o_tcpdump_length = unpack('V',$o_tcpdump_length);
		&logger("\$my_o_tcpdump_length: $my_o_tcpdump_length");
	}
	$length = read(INFILE,$tcpdump_data,$tcpdump_length);
	# See note above why this line.
	&binner_d("$tcpdump_data");
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
	#  Process Global Defaults into %Arg
	#
	foreach (@Save_As_HTML_TCP_Ports) {
		$Arg{Save_As_TCP_HTML}{$_} = 1;
	}
	foreach (@Save_As_HTML_UDP_Ports) {
		$Arg{Save_As_UDP_HTML}{$_} = 1;
	}
	
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
	$Arg{debug} = 1;
	
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

