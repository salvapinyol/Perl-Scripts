use Net::Ping;
use Net::hostent;
use SNMP_util "0.56";

#open( STDERR, ">/dev/null" );
open( TRG,$ARGV[0] );
while (<TRG>) {
	next if /^#.*/;
	chomp;
#	@kk = split /,/;
#	printf "$kk[0]:$kk[1]";	
	$p = Net::Ping->new("icmp");
	if ( $p->ping($_) ) {
		printf "$_ -- Ok\n";
	}
	else {
		print "$_ -- Falla Ping\n";
	}
	$p->close();
}
close TRG;
#close STDERR;
