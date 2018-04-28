#!/usr/bin/perl
#
# streams-content.pl
#
#				Copyright (c) 2018 Miroslav Rovis
#
#	Derived from small part of Chaosreader code. How exactly, see
#	chread_tcp.pl, all the details/reasons.

#
#	released under BSD license, see LICENSE, or assume general BSD license,
#
#   ( except for the script chread_tcp.pl which is Chaosreader's own code, plus
#   two primitive subroutines, and which is, as Chaosreader itself, under GNU
#   GPLv3 or later )
#

#
#	Excerpt from chread_tcp.pl:
#
#	Chaosreader can't extract SSL streams, only plain HTTP TCP streams.
#	My tshark-streams program:
#	https://github.com/miroR/tshark-streams
#	can extract TCP streams, both plain and SSL. But extracting the streams,
#	that Bash script deploying Tshark, is all it does. I want to create a
#	script (based on Chaosreader code) which would then extract data, i.e.
#	mainly files of all kinds, from SSL streams [...]
#
#	And to be able to understand the needed Chaosreader code, I've removed a
#	lot of code that wouldn't serve my future script.
#
#	This is (hopefully) that future script (to become).

#use strict;
#use warnings;
use IO::Uncompress::Gunzip qw(gunzip $GunzipError);
use IO::Uncompress::Inflate qw(inflate $InflateError) ;
use IO::Uncompress::RawInflate qw(rawinflate $RawInflateError) ;


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
