use Net::Ping;
use Net::hostent;
use SNMP_util "0.56";

$i = 1;
while ( $i < 256 ) {

        $j = 1;
#       while ( $j < 256 ) {
                $ip = "10.132.12." . $i;
#               printf STDERR "$ip\n";
                $h = gethost($ip);
                $p = Net::Ping->new("icmp");
                if ( $p->ping($ip) ) {
                        if ($h) { printf "$ip: (%s)\n",$h->name; }
                        else { printf "$ip: NODNS\n" }

                }

#               $j = $j + 1;

#       }
        $i = $i + 1;
}