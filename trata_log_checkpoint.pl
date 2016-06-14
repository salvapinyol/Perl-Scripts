while(<*.log>) {
   printf stderr  "$_\n";

  open(LOG,$_);
  while(<LOG>) {
   chomp $_;
   ($num,$date,$time,$orig,$type,$action,$alert,$ifname,$ifdir,$proto,$src,$dst,$service,$s_port,$rule,$elapsed,$start_time,$packets,$bytes,$sys_msgs) = split(/;/,$_);
    printf "$_\n";
    if (($src =~ /Colmenares./)) {
       printf "$bytes\n";
   }
  }
  close LOG;
  exit;
}