#!/usr/bin/perl 
use Net::Telnet;
use POSIX ":sys_wait_h";
use DBI;
use tracker_spj;

my $name = "switch_collector";
my ( @row, %config, $dbconn, $sth );

$kk = localtime();
printf "$kk\n";

#connect to the database
unless ( $dbconn = tracker::conndb() ) {
	die "Unable to connect to Database Network";
}

unless ( $dbconn_rtg = tracker::conndb_rtg() ) {
	die "Unable to connect to Database RTG";
}

#Get the configuration variables from the database
$sth = $dbconn->prepare("SELECT name, value FROM config;");
$sth->execute or die "Database select failed:" . $dbconn->errstr;
while ( @row = $sth->fetchrow_array ) { $config{ $row[0] } = $row[1] }

#Get the list of all device that are active (status=1) and switches (type=2)
#$sth = $dbconn->prepare("SELECT name, username, passwd, console_passwd, enable_passwd, ignore_ports FROM devices WHERE type=2 AND status=1;");
#$sth->execute  or die "Database select failed:" .  $dbconn->errstr;

$sth =
  $dbconn_rtg->prepare(
"SELECT name,ignore_ports FROM router where (devtype='SWITCH' OR devtype='SWITCH-L3') and name='ES1SW01AUN3';"
  );
$sth->execute or die "Database select failed:" . $dbconn_rtg->errstr;

#build a list of switches to poll.  Each one represented by a reference to an array of name, username,
#password, console password and enable password
my ( $device, @devices );
while ( @row = $sth->fetchrow_array ) {
	my @device;
	$device[0] = $row[0];
	$device[1] = $config{username};
	$device[2] = $config{passwd};
	$device[3] = $config{console_passwd};
	$device[4] = $config{enable_passwd};
	$device[5] = $row[1];
	push @devices, \@device;
}
$sth->finish;
$dbconn->disconnect();
$dbconn_rtg->disconnect();

my $sub_procs = $config{ $name . '_threads' };
if ( $sub_procs > @devices ) { $sub_procs = @devices }

if ( $sub_procs > 1 ) {
	my ( @work, $i, $running_procs, $proc );

	#each worker will get a chunk_size list of work to do
	my $chunk_size = int( @devices / $sub_procs );
	for $i ( 0 .. $sub_procs - 2 ) {
		foreach $device ( @devices[ ( $i * $chunk_size )
			.. ( ( ( $i + 1 ) * $chunk_size ) - 1 ) ] )
		{
			push @{ $work[$i] }, $device;
		}
	}

	foreach $device (
		@devices[ ( ( $sub_procs - 1 ) * $chunk_size ) .. @devices - 1 ] )
	{
		push @{ $work[ $sub_procs - 1 ] }, $device;
	}

	foreach $i ( 1 .. $sub_procs ) {
		unless ( defined( $proc = fork ) ) { die "Couldn't fork" }
		if ( $proc == 0 ) {
			foreach $device ( @{ $work[ $i - 1 ] } ) {
				perform_collection($device);
			}
			exit;
		}
		else { $running_procs++ }
	}

	while ( $running_procs > 0 ) {
		if ( ( $pid = wait ) == -1 ) { last }
		else { $running_procs--; }
	}

}
else {
	foreach $device (@devices) { perform_collection($device) }
}

$kk = localtime();
printf "$kk\n";

sub perform_collection {
	my $device = shift;
	my ( $switch, $username, $password, $console_password, $enable_password,
		$ignore_ports )
	  = @$device;

	#some arrays we use to hold lines returned from telnet
	my ( @ignored_ports, @prompt, @pagelen, @trunks, @camdata );

	#some scratch scalar values
	my ( $match, $prompt, $match_string, $trunk, $trunk_port, $ignored_port );

	#Populate the ignored ports array with the string from the database
	foreach $ignored_port ( split( ":", $ignore_ports ) ) {
		if ( ( $ignored_port =~ /\d*\/\d*/ )
			&& !port_on_list( $ignored_port, \@ignored_ports ) )
		{
			push( @ignored_ports, $ignored_port );
		}
	}

	#create a telnet object for talking to the switches
	my $telnet = new Net::Telnet(
		Timeout => 15,
		Errmode => "return"
	);
	$telnet->open($switch);
	if ( $telnet->errmsg() ) {
		tracker::log("$name: Unable to contact $switch.");
		return;
	}
	( undef, $match ) = $telnet->waitfor('/password:|username:/i');
	if ( $match =~ /password:/i ) {
		$telnet->print($console_password);
	}
	elsif ( $match =~ /username:/i ) {
		$telnet->print($username);
		$telnet->waitfor('/password:/i');
		if ( $telnet->errmsg() ) {
			tracker::log("$name: Incorrect password prompt from  $switch.");
			return;
		}
		$telnet->print($password);
	}
	else { tracker::log("$name: Incorrect login prompt from $switch."); return }

	#wait a little while, so we get the prompt
	sleep 5;
	$_ = $telnet->get();

   #If what we got matches any of these things, then we didn't login succesfully
	if ( /Password:/ || /% Access denied/ || /% Authentication failed/ ) {
		tracker::log("$name: Failed authentication to $switch.");
		return;
	}

	#the input may be multi-line
	my @prompt = split( "\n", $_ );

	#and we only want the last line
	$_ = @prompt[ @prompt - 1 ];

	#pull the prompt out and use it as part of a match string
	($prompt) = (/^([\w-]*)/);
	$match_string = '/' . $prompt . '[\$#>]?\s?(?:\(enable\))?\s*$/';
	$crap         = $telnet->prompt($match_string);

	#go into enable mode
	$ok = $telnet->print("enable");
	$ok = $telnet->waitfor("/password:/i");

#if we send 'enable', but never get the 'Password prompt, then something must be wrong
	if ( $telnet->errmsg() ) {
		tracker::log(
"$name: Failed login or incorrect enable password prompt on $switch."
		);
		return;
	}
	$ok = $telnet->print($enable_password);

	#wait until the prompt comes back
	$telnet->waitfor($match_string);
	if ( $telnet->errmsg() ) {
		tracker::log("$name: Error communicating with $switch.");
		return;
	}

#We are past the point where we might abort and return, so connect to the database now.
	unless ( $dbconn = tracker::conndb() ) {
		die "Unable to connect to Database";
	}
	@pagelen = $telnet->cmd("term len 0");

#The output of term len 0 is used to differentiate between IOS and CatOS based switches
	if ( $pagelen[0] =~ /Unknown command/ ) {    # cisco CatOS
		$ok      = $telnet->cmd("set len 0");
		@trunks  = $telnet->cmd("sh trunk");
		@camdata = $telnet->cmd("sh cam dyn");
		$ok      = $telnet->print("exit");
		$ok      = $telnet->close;
		foreach $_ (@trunks) {
			if ( ($trunk_port) = /^\s*(\d*\/\d*)\s/ ) {
				unless ( port_on_list( $trunk_port, \@ignored_ports ) ) {
					push( @ignored_ports, $trunk_port );
				}
			}
		}
		my ($nmacs);
		$nmacs = 0;
		foreach $_ (@camdata) {
			my ( $vlan, $mac_addr, $module, $port ) =
			  /(\d+)\s*((?:[a-fA-F\d]{2}-){5}[a-fA-F\d]{2})\s*(\d+)\/(\d+)\s*/;
			unless ( defined($mac_addr) ) { next }
			unless ( port_on_list( $module . '/' . $port, \@ignored_ports ) ) {
				$nmacs++;
				updatedb( $dbconn, $mac_addr, $switch, $vlan, $module, $port );
			}
		}
	}
	else {    #Aqui se trata el IOS
		my ($nmacs);
		$nmacs = 0;

		#2900's set the prompt like a router
		$telnet->prompt('/[\w().-]*[\$#>]\s?(?:\(enable\))?\s*$/');
		my (@cluster_members);
		my @config = $telnet->cmd("show run");
		my ($in_interface);

		#read each line of the config to find trunk ports and cluster clients
		foreach $_ (@config) {
			if ($in_interface) {
				if (/^!$/) { $in_interface = "" }
				elsif (/switchport\smode\strunk/) {
					unless ( port_on_list( $in_interface, \@ignored_ports ) ) {
						push( @ignored_ports, $in_interface );
					}
				}
			}
			else {
				if ( ($cluster_member) = /cluster\smember\s(\d*)/ ) {
					push( @cluster_members, $cluster_member );
				}
				elsif (
/^interface\s*(FastEthernet)|(GigabitEthernet)|(TenGigabitEthernet)/
				  )
				{
					($in_interface) =
/interface\s*(?:FastEthernet|GigabitEthernet|TenGigabitEthernet)(\d*\/\d*)/;
				}
				elsif (/^interface\s*Port-channel/) {
					($in_interface) = /interface\s*Port-channel(\d*)/;
					$in_interface = "Po" . $in_interface;
				}

			}
		}
		foreach $_ (@ignored_ports) { printf "salva: ignored port $_\n" }
		@camdata = $telnet->cmd("sh mac-address dyn");

		#go through the cam data
		foreach $_ (@camdata) {
			my ( $vlan, $mac_addr, $module, $port );

			if (/.*dynamic.*/) {    # esto es para los IOS nativo grandes
				if (/.*Po\d+.*/) {
					$module='0';
					
					( $vlan, $mac_addr, $port ) =
/\D*(\d+)\s+(....\.....\.....)\s+dynamic\s+.+(Pod+)/;
					printf "salva: $vlan $mac_addr $module $port\n"
				}
				else {
					( $vlan, $mac_addr, $module, $port ) =
/\D*(\d+)\s+(....\.....\.....)\s+dynamic\s+.+(\d+)\/(\d+)/;
				}
			}
			if (/.*DYNAMIC.*/) {    # esto es para los IOS nativo grandes
				( $vlan, $mac_addr, $module, $port ) =
				  /\D*(\d+)\s+(....\.....\.....)\s+DYNAMIC\s+.+(\d+)\/(\d+)/;
			}

			#regexp matching the output of sh mac dyn
			if (/.*Dynamic.*/) {
				( $mac_addr, $vlan, $module, $port ) =
/((?:[a-fA-F\d]{4}\.){2}[a-fA-F\d]{4})\s*Dynamic\s*(\d*)\s*(?:FastEthernet|GigabitEthernet)(\d*).(\d*)/;
			}
			unless ( defined($mac_addr) ) { next }
			unless ( port_on_list( $module . '/' . $port, \@ignored_ports ) ) {
				$mac_addr = tracker::reformat_rtr_mac($mac_addr);
				updatedb( $dbconn, $mac_addr, $switch, $vlan, $module, $port );
			}
		}
		printf "$switch $nmacs\n";

		#talk to each cluster client we found out about
		foreach $_ (@cluster_members) {
			my (
				$in_interface,  $client_name, $client_hostname,
				$client_domain, @trunk_ports, @camdata
			);
			my @errout = $telnet->cmd("rcommand $_");
			if ( not( $errout[0] =~ /Open/ ) ) { next }
			my @config = $telnet->cmd("sh run");

  #examine the config to find trunkports and the hostname of this cluster client
			foreach $_ (@config) {
				if ($in_interface) {
					if (/^!$/) { $in_interface = "" }
					elsif (/switchport\smode\strunk/) {
						unless (
							port_on_list( $in_interface, \@ignored_ports ) )
						{
							push( @ignored_ports, $in_interface );
						}
					}
				}
				else {
					if (/^ip domain-name/) {
						($client_domain) = /^ip domain-name\s*(.*)\s/;
					}
					elsif (/^hostname/) {
						($client_hostname) = /^hostname\s*(.*)\s/;
					}
					elsif (/^interface\s*(FastEthernet)|(GigabitEthernet)/) {
						($in_interface) =
/interface\s*(?:FastEthernet|GigabitEthernet)(\d*\/\d*)/;
					}
				}
			}
			$client_name = $client_hostname . "." . $client_domain;
			@camdata     = $telnet->cmd("sh mac dyn");

			#go through the cam data
			foreach $_ (@camdata) {

				#regexp matching the output of sh mac dyn
				my ( $mac_addr, $vlan, $module, $port ) =
/((?:[a-fA-F\d]{4}\.){2}[a-fA-F\d]{4})\s*Dynamic\s*(\d*)\s*(?:FastEthernet|GigabitEthernet)(\d*).(\d*)/;
				unless ( defined($mac_addr) ) { next }
				unless (
					port_on_list( $module . '/' . $port, \@ignored_ports ) )
				{
					$mac_addr = tracker::reformat_rtr_mac($mac_addr);
					updatedb( $dbconn, $mac_addr, $client_name, $vlan, $module,
						$port );
				}
			}
			$ok = $telnet->cmd("exit");
		}
		$ok = $telnet->print("exit");
		$ok = $telnet->close;
	}

	if ( $telnet->errmsg() ) {
		tracker::log( "$name: Error "
			  . $telnet->errmsg()
			  . " during telnet session with $switch." );
	}
	else {
		my $sth =
		  $dbconn->prepare(
"UPDATE devices SET last_contacted = CURRENT_TIMESTAMP WHERE name = "
			  . $dbconn->quote($switch)
			  . ";" );
		$sth->execute
		  or tracker::log( "$name:Database update failed:" . $dbconn->errstr );
		$dbconn->commit
		  or tracker::log( "$name:Database commit failed:" . $dbconn->errstr );
	}
	$dbconn->disconnect();
}

sub updatedb {
	my ( $dbconn, $mac_addr, $switch, $vlan, $module, $port ) = @_;

	#find any record matching the mac_addr
	my $sth =
	  $dbconn->prepare( "SELECT COUNT(*) FROM nodes WHERE mac_addr = "
		  . $dbconn->quote($mac_addr)
		  . ";" );
	unless ( $sth->execute ) {
		tracker::log( "$name:Database select failed:" . $dbconn->errstr );
		return;
	}

	#if we got an existing record, UPDATE it, otherwise INSERT a new one
	if ( $sth->fetchrow_array ) {
		my $update =
		    "UPDATE nodes SET "
		  . "switch = "
		  . $dbconn->quote($switch)
		  . ", vlan = $vlan"
		  . ", module = $module"
		  . ", port = $port"
		  . ", last_updated = CURRENT_TIMESTAMP "
		  . "where mac_addr = "
		  . $dbconn->quote($mac_addr) . ";";
		$sth = $dbconn->prepare($update);
		printf "salva: $update\n";
		unless ( $sth->execute ) {
			tracker::log(
				"$name:Database update failed:" . $dbconn->errstr . $update );
			return;
		}
	}
	else {
		my $insert =
"INSERT INTO nodes (mac_addr, switch, vlan, module, port, last_updated) values ("
		  . $dbconn->quote($mac_addr) . ","
		  . $dbconn->quote($switch) . ","
		  . "$vlan, "
		  . "$module, "
		  . "$port, "
		  . "CURRENT_TIMESTAMP);";
		$sth = $dbconn->prepare($insert);
		printf "salva: $insert\n";
		unless ( $sth->execute ) {
			tracker::log(
				"$name:Database insert failed:" . $dbconn->errstr . $insert );
			return;
		}
	}
	$dbconn->commit
	  or tracker::log(
		"$name:COMMIT database transaction failed:" . $dbconn->errstr );
}

sub port_on_list {
	my ( $port, $list_ref ) = @_;
	my $port2;
	foreach $port2 (@$list_ref) {
		if ( $port eq $port2 ) { return 1 }
	}
	return 0;
}
