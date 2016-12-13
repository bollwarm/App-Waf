use App::Waf;

my $filename =  "example.acess";
# change with you practice log pash,such as : 
#$filename =  "/var/logs/httpd/access.log";
my $numlines = shift;

my $line = tail( $filename, $numlines );

( $log, $zcount, $zip, $zrequrl, $zstatus, $siteurl ) = initCount($line);

print "==============Attack Summary ==================\n";
print "\nThe total attack count: $zcount \n";
print "\nThe count from source IP:  \n\n";
print "$_\=> $zip->{$_} \n" for ( sort keys %{$zip} );
print "The count From request Url:  \n\n";
print "$_\=> $zrequrl->{$_} \n" for ( sort keys %{$zrequrl} );
print "\n\nThe count From Http Status:  \n\n";
print "$_\=> $zstatus->{$_} \n" for ( sort keys %{$zstatus} );
print "\n\nThe count From Site Url:  \n\n";
print "$_\=> $siteurl->{$_} \n" for ( sort keys %{$siteurl} );

#print $log;
