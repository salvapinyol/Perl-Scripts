#! /usr/local/bin/perl
#
# RTG Target File Generator
#

use vars qw($community $defbits $output $DEBUG $DBOFF $INFO @ISA @EXPORT);

#########################################################################
# Local customization

$community   = "public";          # Default SNMP community
$defbits     = 32;                # Default OID bits: 32/64
$output      = "targets.cfg";     # Output target file name
$db_db       = "rtg";             # MySQL database name
$db_host     = "10.132.12.50";    # MySQL database host
$db_user     = "snmp";            # MySQL database user
$db_pass     = "rtgdefault";      # MySQL database password
$router_file = "routers";         # Input list of devices to poll
$INFO        = 1;                 # Print informational messages
$DEBUG       = 0;                 # Print debug messages
$DBOFF       = 0;                 # Turn database queries off (debug)
$MODULEDIR   = "rtgmodules";

# No edits needed beyond this point
#########################################################################

# This Perl script requires the included SNMP modules
use lib ".:/opt/rtg/etc";
use BER;
use SNMP_Session;
use SNMP_util;

# This Perl script requires the not-included DBI module
use DBI;

use vars qw(%snmp_modules %table_map %table_name);

# This Perl script requires the not-included DBI module
use DBI;

#
# Load all the modules we find
#
opendir( DIR, $MODULEDIR );
@modfiles = grep { /.*\.pl$/ } readdir(DIR);
closedir(DIR);

# Load all the added modules
foreach $mod_file (@modfiles) {
	debug("Now loading module $mod_file...");
	require "$MODULEDIR/$mod_file";
}

# Tipos de interface
%iftypes = (
	6   => "ethernet",
	9   => "token-ring",
	32  => "frame-relay",
	131 => "tunnel",
	5   => "x25",
	1   => "tunnel",
	117 => "Gigabit Ethernet",
	30  => "ATM",
	39  => "ATM Sonet",
	22  => "Serial",
	88  => "pvc",
	23  => "ppp"
);

%mibs_of_interest_int = (
	6 => {
		"ifInOctets"    => ".1.3.6.1.2.1.2.2.1.10.",
		"ifOutOctets"   => ".1.3.6.1.2.1.2.2.1.16.",
		"ifInDiscards"  => ".1.3.6.1.2.1.2.2.1.13.",
		"ifOutDiscards" => ".1.3.6.1.2.1.2.2.1.19.",
		"ifInErrors"    => ".1.3.6.1.2.1.2.2.1.14.",
		"ifOutErrors"   => ".1.3.6.1.2.1.2.2.1.20.",
	},
	9 => {
		"ifInOctets"  => ".1.3.6.1.2.1.2.2.1.10.",
		"ifOutOctets" => ".1.3.6.1.2.1.2.2.1.16.",
	},
	32 => {
		"ifInOctets"  => ".1.3.6.1.2.1.2.2.1.10.",
		"ifOutOctets" => ".1.3.6.1.2.1.2.2.1.16.",
		"ifInErrors"  => ".1.3.6.1.2.1.2.2.1.14.",
		"ifOutErrors" => ".1.3.6.1.2.1.2.2.1.20."
	},
	131 => {
		"ifInOctets"  => ".1.3.6.1.2.1.2.2.1.10.",
		"ifOutOctets" => ".1.3.6.1.2.1.2.2.1.16.",
	},
	5 => {
		"ifInOctets"  => ".1.3.6.1.2.1.2.2.1.10.",
		"ifOutOctets" => ".1.3.6.1.2.1.2.2.1.16.",
	},
	1 => {
		"ifInOctets"  => ".1.3.6.1.2.1.2.2.1.10.",
		"ifOutOctets" => ".1.3.6.1.2.1.2.2.1.16.",
	},
	117 => {
		"ifInOctets"    => ".1.3.6.1.2.1.2.2.1.10.",
		"ifOutOctets"   => ".1.3.6.1.2.1.2.2.1.16.",
		"ifInDiscards"  => ".1.3.6.1.2.1.2.2.1.13.",
		"ifOutDiscards" => ".1.3.6.1.2.1.2.2.1.19.",
		"ifInErrors"    => ".1.3.6.1.2.1.2.2.1.14.",
		"ifOutErrors"   => ".1.3.6.1.2.1.2.2.1.20."
	},
	30 => {
		"ifInOctets"  => ".1.3.6.1.2.1.2.2.1.10.",
		"ifOutOctets" => ".1.3.6.1.2.1.2.2.1.16.",
	},
	22 => {
		"ifInOctets"  => ".1.3.6.1.2.1.2.2.1.10.",
		"ifOutOctets" => ".1.3.6.1.2.1.2.2.1.16.",
		"ifInErrors"  => ".1.3.6.1.2.1.2.2.1.14.",
		"ifOutErrors" => ".1.3.6.1.2.1.2.2.1.20."
	},
	39 => {
		"ifInOctets"  => ".1.3.6.1.2.1.2.2.1.10.",
		"ifOutOctets" => ".1.3.6.1.2.1.2.2.1.16.",
		"ifInErrors"  => ".1.3.6.1.2.1.2.2.1.14.",
		"ifOutErrors" => ".1.3.6.1.2.1.2.2.1.20."
	},
	88 => {
		"frCircuitReceivedFECNs"  => ".1.3.6.1.2.1.10.32.2.1.4.2.",
		"frCircuitReceivedBECNs"  => ".1.3.6.1.2.1.10.32.2.1.5.2.",
		"frCircuitSentOctets"     => ".1.3.6.1.2.1.10.32.2.1.7.2.",
		"frCircuitReceivedOctets" => ".1.3.6.1.2.1.10.32.2.1.9.2."
	},
	23 => {
		"ifInOctets"  => ".1.3.6.1.2.1.2.2.1.10.",
		"ifOutOctets" => ".1.3.6.1.2.1.2.2.1.16.",
	},
);

# Set of standard MIB-II objects of interest
%mibs_of_interest_32 = (
	"ifInOctets"     => ".1.3.6.1.2.1.2.2.1.10.",
	"ifOutOctets"    => ".1.3.6.1.2.1.2.2.1.16.",
	"ifInUcastPkts"  => ".1.3.6.1.2.1.2.2.1.11.",
	"ifOutUcastPkts" => ".1.3.6.1.2.1.2.2.1.17.",
);

# Set of 64 bit objects, preferred where possible
%mibs_of_interest_64 = (
	"ifInOctets"     => ".1.3.6.1.2.1.31.1.1.1.6.",
	"ifOutOctets"    => ".1.3.6.1.2.1.31.1.1.1.10.",
	"ifInUcastPkts"  => ".1.3.6.1.2.1.31.1.1.1.7.",
	"ifOutUcastPkts" => ".1.3.6.1.2.1.31.1.1.1.11.",
);

$normal = [
	[ 1, 3, 6, 1, 2, 1, 2,  2, 1, 1 ],        # ifIndex
	[ 1, 3, 6, 1, 2, 1, 2,  2, 1, 2 ],        # ifDescr
	[ 1, 3, 6, 1, 2, 1, 2,  2, 1, 5 ],        # ifSpeed
	[ 1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 18 ],    # ifAlias
	[ 1, 3, 6, 1, 2, 1, 2,  2, 1, 7 ],        # ifAdminStatus
	[ 1, 3, 6, 1, 2, 1, 2,  2, 1, 8 ]         # ifOperStatus
];

$catalyst = [
	[ 1, 3, 6, 1, 2, 1, 2,  2, 1, 1 ],             # ifIndex
	[ 1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1 ],          # ifXEntry.ifName
	[ 1, 3, 6, 1, 2, 1, 2,  2, 1, 5 ],             # ifSpeed
	[ 1, 3, 6, 1, 4, 1, 9,  5, 1, 4, 1, 1, 4 ],    # CiscoCatalystPortName
	[ 1, 3, 6, 1, 2, 1, 2,  2, 1, 7 ],             # ifAdminStatus
	[ 1, 3, 6, 1, 2, 1, 2,  2, 1, 8 ]              # ifOperStatus
];

sub find_interface_id($$$$);
sub debug($);
sub print_target($$$$$$$);

#
# Makes things easier with debugging from
# modules, even tho it's not as fast as doing
# the if $DEBUG before calling debug()
#
sub debug($) {
	$debug_line = shift;
	print "$debug_line\n" if $DEBUG;
}

#
# If people use this instead of doing it themselves in their
# code, it makes it easier to change later on
#
sub print_target($$$$$$$) {
	my ( $router, $oid, $bits, $community, $table, $iid, $descr ) = @_;

	( $a, $a, $a, $a, @addrs ) = gethostbyname($router);
	printf CFG "%d.%d.%d.%d\t", unpack( 'C4', $addrs[0] );
	print CFG "$oid\t";
	print CFG "$bits\t";
	print CFG "$community\t";
	print CFG "$table\t";
	print CFG "$iid\t";
	print CFG "$descr\n";

}

# DBI SQL Insert Subroutine
sub sql_insert {
	($sql) = @_;
	debug("SQL-: $sql");
	my $sth = $dbh->prepare($sql)
	  or die "Can't prepare $sql: $dbh->errstr\n";
	my $rv = $sth->execute
	  or die "can't execute the query: $sth->errstr\n";
}

# Find an RTG router id (rid) in the MySQL database.  If it doesn't
# exist, create a new entry and corresponding tables.
sub find_router_id {
	($router) = @_;
	$sql = "SELECT DISTINCT rid FROM router WHERE name=\"$router\"";
	debug("SQL: $sql");
	my $sth = $dbh->prepare($sql)
	  or die "Can't prepare $sql: $dbh->errstr\n";
	my $rv = $sth->execute
	  or die "can't execute the query: $sth->errstr\n";
	if ( $sth->rows == 0 ) {
		print "No router id found for $router...";
		$sql =
"INSERT INTO router (name,company,location,devtype,sysDescr) VALUES(\"$router\",\"$company\",\"$locat\",\"$devtype\",\"$system\")";
		print "adding.\n";
		&sql_insert($sql);
		$rid = &find_router_id($router);
	}
	else {
		print "Updating $router...\n";

		# SALVA: FALTA HACER LA INSTRUCCION DE UPDATE
		@row = $sth->fetchrow_array();
		$rid = $row[0];
	}
	$sth->finish;
	return $rid;
}

# Find an RTG interface id (iid) in the MySQL database.  If it doesn't
# exist, create a new entry.
sub find_interface_id($$$$) {
	( $rid, $int, $desc, $speed, $type, $mib_list ) = @_;
	$desc =~ s/ +$//g;    #remove trailing whitespace
	$sql =
"SELECT id, description,speed FROM interface WHERE rid=$rid AND name=\"$int\"";
	debug("SQL: $sql");
	my $sth = $dbh->prepare($sql)
	  or die "Can't prepare $sql: $dbh->errstr\n";
	my $rv = $sth->execute
	  or die "can't execute the query: $sth->errstr\n";
	if ( $sth->rows == 0 ) {
		print "No id found for $int on device $rid...";
		$desc =~ s/\"/\\\"/g;    # Fix " in desc
		$sql =
"INSERT INTO interface (name, rid, speed, description, type, mib_list) VALUES(\"$int\", $rid, $speed, \"$desc\", \"$type\",\"$mib_list\")";
		print "adding.\n";
		&sql_insert($sql);
		$iid = &find_interface_id( $rid, $int, $desc, $speed, $type );
	}
	else {
		@row = $sth->fetchrow_array();
		$iid = $row[0];
		if ( $row[1] ne $desc ) {
			print "Interface description changed.\n";
			print "Was: \"$row[1]\"\n";
			print "Now: \"$desc\"\n";
			print
"Suggest: UPDATE interface SET description='$desc' WHERE id=$iid\n";
			$sql = "UPDATE interface SET description='$desc' WHERE id=$iid";
			&sql_insert($sql);
		}
		if ( $row[2] ne $speed ) {
			print "Interface speed changed.\n";
			print "Was: \"$row[2]\"\n";
			print "Now: \"$speed\"\n";
			print
			  "Suggest: UPDATE interface SET speed='$speed' WHERE id=$iid\n";
		}
	}
	$sth->finish;
	return $iid;
}

sub main {
	open ROUTERS, "<$router_file" or die "Could not open file: $router_file";
	while (<ROUTERS>) {
		chomp;
		s/ +$//g;    #remove space at the end of the line
		next if /^ *\#/;    #ignore comment lines
		next if /^ *$/;     #ignore empty lines
		if ( $_ =~ /(.+):(.+):(.+)/ ) {
			$r               = $1;
			$c               = $2;
			$b               = $3;
			$communities{$r} = $c;
			$counterBits{$r} = $b;
			push @routers, $r;
		}
		elsif ( $_ =~ /(.+):(.+)/ ) {
			$r               = $1;
			$c               = $2;
			$communities{$r} = $c;
			push @routers, $r;
		}
		else {
			$communities{$_} = $community;
			push @routers, $_;
		}
	}
	close ROUTERS;

	if ( $routers[0] eq "rtr-1.my.net" ) {
		print "\n** Error, $0 is not yet configured\n\n";
		print "Please edit the \"$router_file\" file and add network devices\n";
		exit(-1);
	}

	# SQL Database Handle
	if ( !$DBOFF ) {
		$dbh =
		  DBI->connect( "DBI:mysql:$db_db:host=$db_host", $db_user, $db_pass );
		if ( !$dbh ) {
			print "Could not connect to database ($db_db) on $db_host.\n";
			print "Check configuration.\n";
			exit(-1);
		}
	}

	open CFG, ">$output" or die "Could not open file: $!";
	( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) =
	  localtime( time() );
	printf CFG "# Generated %02d/%02d/%02d %02d:%02d by $0\n", $mon + 1, $mday,
	  $year + 1900, $hour, $min;
	print CFG "# Host\tOID\tBits\tCommunity\tTable\tID\tDescription\n";

	foreach $router (@routers) {
		$bits = $counterBits{$router};

		# Sanity check bits
		$bits = $defbits if ( ( $bits != 32 ) && ( $bits != 64 ) );
		if ( $bits == 64 ) { %mibs_of_interest = %mibs_of_interest_64 }
		else { %mibs_of_interest = %mibs_of_interest_32 }

		print "Poking $router ($communities{$router}) ($bits bit)...\n"
		  if $INFO;
		@location = snmpget( "$communities{$router}\@$router", 'sysLocation' );
		@result   = snmpget( "$communities{$router}\@$router", 'sysDescr' );
		$system   = join( ' ',                                 @result );
		debug("System: $system");

		#        if ($location[0] =~ /#.*#.*#.*/ ) {
		( $company, $locat, $devtype ) = ( $location[0] =~ /#(.*)#(.*)#(.*)/ );

#        }
#        else {
#            printf "ERROR: Elemento $router no tiene bien configurado el SysLocation\n";
#            exit(1);
#        }

		if ( !$DBOFF ) {
			$rid = &find_router_id($router);
		}

		$session = SNMP_Session->open( $router, $communities{$router}, 161 );
		debug("Checking for non-network information...");
		foreach $mod_name ( keys %snmp_modules ) {

			# we will have failures, suppress warnings to make output cleaner
			debug("Checking for $mod_name support");

			# we don't want messages about not finding the oid, it might
			# confuse/concern people as alot of these will fail
			#
			$SNMP_Session::suppress_warnings = 2;

			@result = snmpget( "$communities{$router}\@$router",
				$snmp_modules{$mod_name} );

			# turn warnings back on
			$SNMP_Session::suppress_warnings = 0;
			if ( ( $result[0] ne "(null)" ) && ( $result[0] ne "" ) ) {

				#                        printf $result[0];
				$module_func = "process_module_$mod_name";

				#                        printf $module_func;
				&$module_func( $router, $communities{$router}, $session );
			}

		}
	}
	close CFG;
	if ( !$DBOFF ) {
		$dbh->disconnect;
	}
	print "Done.\n";
}

main;
exit(0);
