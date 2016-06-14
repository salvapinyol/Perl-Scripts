# Get extra stats for Cisco Equipment, namely memory, cpu, and temp,
# but we also have backplane bandwith for the larger catalyst switches
#
#
# Set name of Module, and the OID to check to run this module
#
$MODULENAME = "CISCOSNMP";
$VERSION    = '0.1';

# Module requires a subroutine called process_module_$MODULENAME to exist.
#
sub process_module_CISCOSNMP($$$);

#
# Local sub-routines
#
sub add_def_ciscosnmp($$);
sub cpu_process_ciscosnmp();
sub temp_process_ciscosnmp();
sub mem_process_ciscosnmp();

# We check for enterprises.cisco.ciscoMgmt.ciscoImageMIB.ciscoImageMIBObjects.ciscoImageTable.ciscoImageEntry.ciscoImageString.1
$MIB_TO_CHECK = ".1.3.6.1.4.1.9.9.25.1.1.1.2.1";

# Set this so it's in the main hash
$main::snmp_modules{$MODULENAME} = $MIB_TO_CHECK;

$main::table_map{'CISCOSNMP-cpu'} =
  [qw(cpmCPUTotal5sec cpmCPUTotal1min cpmCPUTotal5min)];
$main::table_options{'CISCOSNMP-cpu'} = [qw(gauge=on units=%)];

$main::table_map{'CISCOSNMP-mem'} =
  [qw(ciscoMemoryPoolLargestFree ciscoMemoryPoolUsed ciscoMemoryPoolFree)];
$main::table_options{'CISCOSNMP-mem'} = [qw(gauge=on units=Bytes)];

$main::table_map{'CISCOSNMP-cattemp'}     = [qw(entSensorValue)];
$main::table_options{'CISCOSNMP-cattemp'} = [qw(gauge=on units=DegC)];

$main::table_map{'CISCOSNMP-iostemp'} = [qw(ciscoEnvMonTemperatureStatusValue)];
$main::table_options{'CISCOSNMP-iostemp'} = [qw(gauge=on units=DegC)];

$main::table_map{'CISCOSNMP-backplane'}     = [qw(sysTraffic)];
$main::table_options{'CISCOSNMP-backplane'} = [qw(gauge=on units=% scaley=on)];

#
# Local vars
#
%mibs_of_interest_ciscosnmp = (

	# cpu %
	#	"cpmCPUTotal5sec"	=> ".1.3.6.1.4.1.9.9.109.1.1.1.1.3.",
	#	"cpmCPUTotal1min"	=> ".1.3.6.1.4.1.9.9.109.1.1.1.1.4.",
	"cpmCPUTotal5min" => ".1.3.6.1.4.1.9.9.109.1.1.1.1.5.",

	#	"cpmCPUTotal5secRev"	=> ".1.3.6.1.4.1.9.9.109.1.1.1.1.6.",
	#	"cpmCPUTotal1minRev"	=> ".1.3.6.1.4.1.9.9.109.1.1.1.1.7.",
	"cpmCPUTotal5minRev" => ".1.3.6.1.4.1.9.9.109.1.1.1.1.8.",

	# memory usage
	#	"ciscoMemoryPoolUsed"		=> ".1.3.6.1.4.1.9.9.48.1.1.1.5.",
	"ciscoMemoryPoolFree" => ".1.3.6.1.4.1.9.9.48.1.1.1.6.",

	#	"ciscoMemoryPoolLargestFree"	=> ".1.3.6.1.4.1.9.9.48.1.1.1.7.",

	# Catalyst Temperature
	#	"entSensorValue"		=> ".1.3.6.1.4.1.9.9.91.1.1.1.1.4.",

	# IOS Temp
	#	"ciscoEnvMonTemperatureStatusValue"	=> ".1.3.6.1.4.1.9.9.13.1.3.1.3.",

	# Cisco Module Info
	"entPhysicalDescr"        => ".1.3.6.1.2.1.47.1.1.1.1.2.",
	"entPhysicalContainedIn"  => ".1.3.6.1.2.1.47.1.1.1.1.4.",
	"entPhysicalName"         => ".1.3.6.1.2.1.47.1.1.1.1.7.",
	"entPhysicalParentRelPos" => ".1.3.6.1.2.1.47.1.1.1.1.6.",

	# Catalyst backplane
	"sysTraffic" => ".1.3.6.1.4.1.9.5.1.1.8.",

);

$cisco_cpu = [
	[ 1, 3, 6, 1, 4, 1, 9, 9, 109, 1, 1, 1, 1, 2 ],   # cpmCPUTotalPhysicalIndex
	[ 1, 3, 6, 1, 4, 1, 9, 9, 109, 1, 1, 1, 1, 3 ],   # cpmCPUTotal5sec
	[ 1, 3, 6, 1, 4, 1, 9, 9, 109, 1, 1, 1, 1, 4 ],   # cpmCPUTotal1min
	[ 1, 3, 6, 1, 4, 1, 9, 9, 109, 1, 1, 1, 1, 5 ],   # cpmCPUTotal5min
	[ 1, 3, 6, 1, 4, 1, 9, 9, 109, 1, 1, 1, 1, 6 ],   # cpmCPUTotal5secRev
	[ 1, 3, 6, 1, 4, 1, 9, 9, 109, 1, 1, 1, 1, 7 ],   # cpmCPUTotal1minRev
	[ 1, 3, 6, 1, 4, 1, 9, 9, 109, 1, 1, 1, 1, 8 ]    # cpmCPUTotal5minRev
];

$cisco_ios_temp = [
	[ 1, 3, 6, 1, 4, 1, 9, 9, 13, 1, 3, 1, 2 ]
	,    # ciscoEnvMonTemperatureStatusDescr
	[ 1, 3, 6, 1, 4, 1, 9, 9, 13, 1, 3, 1,
		3 ]    # ciscoEnvMonTemperatureStatusValue
];

$cisco_cat_temp = [
	[ 1, 3, 6, 1, 2, 1, 47, 1, 1,  1, 1, 2 ],          # entPhysicalDescr
	[ 1, 3, 6, 1, 2, 1, 47, 1, 1,  1, 1, 4 ],          # entPhysicalContainedIn
	[ 1, 3, 6, 1, 2, 1, 47, 1, 1,  1, 1, 7 ],          # entPhysicalName
	[ 1, 3, 6, 1, 4, 1, 9,  9, 91, 1, 1, 1, 1, 1 ],    # entSensorType
	[ 1, 3, 6, 1, 4, 1, 9,  9, 91, 1, 1, 1, 1, 4 ]     # entSensorValue
];

$cisco_memory = [
	[ 1, 3, 6, 1, 4, 1, 9, 9, 48, 1, 1, 1, 2 ],    # ciscoMemoryPoolName
	[ 1, 3, 6, 1, 4, 1, 9, 9, 48, 1, 1, 1, 5 ],    # ciscoMemoryPoolUsed
	[ 1, 3, 6, 1, 4, 1, 9, 9, 48, 1, 1, 1, 6 ],    # ciscoMemoryPoolFree
	[ 1, 3, 6, 1, 4, 1, 9, 9, 48, 1, 1, 1, 7 ],    # ciscoMemoryPoolLargestFree

];

#
# for multibackplane switches (aka 5x00)
# the mib does wacky stuff for the naming with references inside the mib, so we need the enum
# to figure out what plane is what
#
# note: not being used yet, might in the future...
@sysSwitchingBusEum = (
	"blank",         "systemSwitchingBus",
	"switchingBusA", "switchingBusB",
	"switchingBusC"
);
$cisco_cat_backplane = [
	[ 1, 3, 6, 1, 4, 1, 9, 5, 1, 1, 32, 1, 2 ]    # % of bus used
];

sub process_module_CISCOSNMP($$$) {
	my ( $router, $community, $sess ) = @_;

	debug("$router is a Cisco of some sorts");

	add_def_ciscosnmp( $router, $community );
	$sess->map_table( $cisco_cpu,    \&cpu_process_ciscosnmp );
	$sess->map_table( $cisco_memory, \&mem_process_ciscosnmp );

	#$sess->map_table( $cisco_ios_temp, \&ios_temp_process_ciscosnmp );
	#$sess->map_table( $cisco_cat_temp, \&cat_temp_process_ciscosnmp );

	return 1;
}

sub mem_process_ciscosnmp() {
	my $reserved = 0;
	my ( $rowindex, $memalias, $memused, $memfree, $memlargest ) = @_;

	$bits = 0;
	grep ( defined $_ && ( $_ = pretty_print $_),
		( $memalias, $memused, $memfree, $memlargest ) );

	$memsize  = 0;
	$memdescr = "$memalias Memory";

	if ($memalias) {
		if ( !$DBOFF ) {
			$iid = &find_interface_id( $rid, $memdescr, $memalias, $memsize );
		}
		foreach $mib ( keys %mibs_of_interest_ciscosnmp ) {
			next unless ( $mib =~ /ciscoMemoryPool/ );

			if ( !$DBOFF ) {
				$sql = "SHOW TABLE STATUS LIKE '$mib" . "_$rid'";
				my $sth = $dbh->prepare($sql)
				  or die "Can't prepare $sql: $dbh->errstr\n";
				my $rv = $sth->execute
				  or die "can't execute the query: $sth->errstr\n";

				if ( $sth->rows == 0 ) {
					$sql =
					    "CREATE TABLE $mib"
					  . "_$rid (id INT NOT NULL, dtime DATETIME NOT NULL, counter BIGINT NOT NULL, KEY $mib"
					  . "_$rid"
					  . "_idx (dtime))";
					&sql_insert($sql);
				}
			}

			print_target(
				$router,
				"$mibs_of_interest_ciscosnmp{$mib}$rowindex",
				$bits,
				$communities{$router},
				"$mib" . "_$rid",
				$iid,
				"$memalias ($memdescr)"
			);
		}
	}
}

sub cpu_process_ciscosnmp() {
	my $reserved = 0;
	my (
		$rowindex, $index,      $fivesec,   $onemin,
		$fivemin,  $fivesecrev, $oneminrev, $fiveminrev
	  )
	  = @_;

	# max cpu % is 100
	$cpusize = 100;
	$bits    = 0;

	grep ( defined $_ && ( $_ = pretty_print $_),
		(
			$index,      $fivesec,   $onemin, $fivemin,
			$fivesecrev, $oneminrev, $fiveminrev
		) );

	$cpudescr = "CPU #$index";
	$cpualias = "CPU #$index";

	# do we have an index?
	if ( defined $index ) {
		if ( !$DBOFF ) {
			$iid = find_interface_id( $rid, $cpudescr, $cpualias, $cpusize );
		}
		foreach $mib ( keys %mibs_of_interest_ciscosnmp ) {
			next unless ( $mib =~ /CPUTotal/ );
			next if ( $mib =~ /Rev$/ );    # we process this later

			if ( !$DBOFF ) {
				$sql = "SHOW TABLE STATUS LIKE '$mib" . "_$rid'";
				my $sth = $dbh->prepare($sql)
				  or die "Can't prepare $sql: $dbh->errstr\n";
				my $rv = $sth->execute
				  or die "can't execute the query: $sth->errstr\n";

				if ( $sth->rows == 0 ) {
					$sql =
					    "CREATE TABLE $mib"
					  . "_$rid (id INT NOT NULL, dtime DATETIME NOT NULL, counter BIGINT NOT NULL, KEY $mib"
					  . "_$rid"
					  . "_idx (dtime))";
					&sql_insert($sql);
				}
			}

			#

		# hack to use the revised cisco cpu mib entries if the box supports them
			$mib_to_print = $mib;

			if ( $mib =~ /cpmCPUTotal5sec/ & defined $fivesecrev ) {
				$mib_to_print = "cpmCPUTotal5secRev";
			}
			elsif ( $mib =~ /cpmCPUTotal1min/ & defined $oneminrev ) {
				$mib_to_print = "cpmCPUTotal1minRev";
			}
			elsif ( $mib =~ /cpmCPUTotal5min/ & defined $fiveminrev ) {
				$mib_to_print = "cpmCPUTotal5minRev";
			}

			print_target(
				$router,
				"$mibs_of_interest_ciscosnmp{$mib_to_print}$rowindex",
				$bits,
				$communities{$router},
				"$mib" . "_$rid",
				$iid,
				"$cpualias ($cpudescr)"
			);
		}
	}
}

sub add_def_ciscosnmp($$) {
	my ( $router, $comm ) = @_;

	$SNMP_Session::suppress_warnings = 2;
	@result = snmpget( "$communities{$router}\@$router",
		"$mibs_of_interest_ciscosnmp{'sysTraffic'}0" );
	$SNMP_Session::suppress_warnings = 0;

	if ( defined $result[0] ) {

		$sstat   = "sysTraffic";
		$ifdescr = "Backplane Traffic Meter";
		$ifalias = "BP Traffic";
		$ifspeed = 100;

		if ( !$DBOFF ) {
			$rid = find_router_id($router);
			$iid = find_interface_id( $rid, $ifdescr, $ifalias, $ifspeed );
		}
		else { $iid = 999; $rid = 999; }

		if ( !$DBOFF ) {
			$sql = "SHOW TABLE STATUS LIKE '$sstat" . "_$rid'";
			my $sth = $dbh->prepare($sql)
			  or die "Can't prepare $sql: $dbh->errstr\n";
			my $rv = $sth->execute
			  or die "can't execute the query: $sth->errstr\n";

			if ( $sth->rows == 0 ) {
				$sql =
				    "CREATE TABLE $sstat"
				  . "_$rid (id INT NOT NULL, dtime DATETIME NOT NULL, counter BIGINT NOT NULL, KEY $mib"
				  . "_$rid"
				  . "_idx (dtime))";
				&sql_insert($sql);
			}
		}

		print_target(
			$router, "$mibs_of_interest_ciscosnmp{'sysTraffic'}0",
			0, $comm, "$sstat" . "_$rid",
			$iid, "$ifalias ($ifdescr)"
		);
	}

}

# have to end with a 1
1;

