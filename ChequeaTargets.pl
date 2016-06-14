use Net::Ping;
use Net::hostent;
use SNMP_util "0.56";


open( STDERR, ">/dev/null");
open( TRG, "etc/targets.cfg" );
while (<TRG>) {
	next if /^#.*/;
	chomp;
	@kk = split /\t/;
	$ips{ $kk[0] } = $kk[3];
}
foreach $key ( keys(%ips) ) {
	$h = gethost($key);
	printf "$key";
	if ($h) { printf "(%s)", $h->name; }
	else {printf "(?????)";}
	$p=Net::Ping->new("icmp");
	if ($p->ping($key)) {
     		($ret) = &snmpgetnext( "$ips{$key}\@$key", ".1.3.6.1.2.1.1.5.0" );
	      	unless ($ret) { printf " -- Falla SNMP($ips{$key})\n"; }
	      	else { printf " -- Ok\n";}
	}
	else {
		print " -- Falla Ping\n";
		}
	$p->close();
}
close TRG;
close STDERR;