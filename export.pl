#!/usr/bin/perl

# Exporta los datos del dia de la BD de RTG

use DBI;

# Begin with reasonable defaults
$db        = "rtg";
$host      = "localhost";
$user      = "snmp";
$pass      = "rtgdefault";
$onedaysec = 60 * 60 * 24;

( $kk, $kk, $kk, $day, $month, $year, $hora, $minuto, $kk ) = localtime();
if ( length($day) == 1 ) {
	$day = '0' . $day;
}

$month = $month + 1;
if ( length($month) == 1 ) {
	$month = '0' . $month;
}

$year    = 1900 + $year;
$fichero = "datosred" . $day . $month . $year;

open( SALIDA, ">$fichero" );

$dbh  = DBI->connect( "DBI:mysql:$db:host=$host", $user, $pass );
$dbh2 = DBI->connect( "DBI:mysql:$db:host=$host", $user, $pass );

$statement =
"SELECT router.rid,interface.id,router.name,interface.name,interface.description,interface.speed,router.company,router.location,router.devtype,interface.mib_list FROM interface,router WHERE interface.rid=router.rid and interface.reporting='si'";
$sth = $dbh->prepare($statement)
  or die "Can't prepare $statement: $dbh->errstr\n";
$rv = $sth->execute
  or die "can't execute the query: $sth->errstr\n";
while ( @row = $sth->fetchrow_array() ) {
	foreach $mib ( split( / /, $row[9] ) ) {
		$tabla     = $mib . "_" . $row[0];
		$statement =
"SELECT substring(dtime,1,13) as fechor, max(counter) as maximo,avg(counter) as media, sum(counter) as suma from $tabla where substring(dtime,1,10)=CURDATE() and id=$row[1] group by fechor";
		$sth2 = $dbh2->prepare($statement)
		  or die "Can't prepare $statement: $dbh2->errstr\n";
		$rv = $sth2->execute
		  or die "can't execute the query: $sth2->errstr\n";
		while ( @row2 = $sth2->fetchrow_array() ) {
			for $elemento ( 0 .. 8 ) { printf SALIDA "$row[$elemento],"; }
			printf SALIDA "$mib";
			foreach $elemento (@row2) {
				printf SALIDA ",$elemento";
			}
			printf SALIDA "\n";
		}
	}
}
system("scp -CB $fichero tdd\@129.39.138.5:/var/spool/DB2/logsback/");

