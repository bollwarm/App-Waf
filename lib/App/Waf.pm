package App::Waf;

use 5.006;
use strict;
use warnings;
require Exporter;

=head1 NAME

App::Waf - A sample  Web Application Firewall,
analysis the web logs for illegal attempt in real time。
summary the source IP and other tpyes infomations ,using
this infomations for ban whith iptables. 

通过解析web访问日志，实时统计非法访问，结合防火期等进行
主动式防御。 

=head1 VERSION

Version 0.02

=cut

our $VERSION = '0.02';

our @ISA    = qw(Exporter);
our @EXPORT = qw(tail initCount);

=head1 SYNOPSIS

Perhaps a little code snippet.

=head1 EXPORT

use App::Waf;
my $filename = "example.acess";#日志文件
my $numlines  = 50000; #要处理的行数,从后读。
my $line=tail($filename,$$numlines);
 ($log,$zcount,$zip,$zrequrl,$zstatus,$siteurl)=initCount($line);
print "==============Attack Summary ==================\n";
print "\nThe total attack count: $zcount \n";
print "\nThe count from source IP:  \n\n";
print "$_\=> $zip->{$_} \n" for(sort  keys %{$zip});
print "The count From request Url:  \n\n";
print "$_\=> $zrequrl->{$_} \n" for(sort keys %{$zrequrl});
print "\n\nThe count From Http Status:  \n\n";
print "$_\=> $zstatus->{$_} \n" for(sort keys %{$zstatus});
print "\n\nThe count From Site Url:  \n\n";
print "$_\=> $siteurl->{$_} \n" for(sort keys %{$siteurl});

=head1 SUBROUTINES/METHODS
=cut

use File::ReadBackwards;

my $DEBUG=0;

my @validurl =(
'rfd.php\?include_file',
'\.\./',
'select.+(from|limit)',
'(?:(union(.*?)select))',
'having|rongjitest',
'sleep\((\s*)(\d*)(\s*)\)',
'benchmark\((.*)\,(.*)\)',
'base64_decode\(',
'(?:from\W+information_schema\W)',
'(?:(?:current_)user|database|schema|connection_id)\s*\(',
'(?:etc\/\W*passwd)',
'into(\s+)+(?:dump|out)file\s*',
'group\s+by.+\(',
'xwork.MethodAccessor',
'(?:define|eval|file_get_contents|include|require|require_once|shell_exec|phpinfo|system|passthru|preg_\w+|execute|echo|print|print_r|var_dump|(fp)open|concat|alert|showmodaldialog)\(',
'xwork\.MethodAccessor',
'(gopher|doc|php|glob|file|phar|zlib|ftp|ldap|dict|ogg|data)\:\/',
'java\.lang',
'\$_(GET|post|cookie|files|session|env|phplib|GLOBALS|SERVER)\[',
'\<(iframe|script|body|img|layer|div|meta|style|base|object|input)',
'(onmouseover|onerror|onload)\=',
'\.(bak|inc|old|mdb|sql|backup|java|class)$',
'\.(svn|htaccess|bash_history)',
'(vhost|bbs|host|wwwroot|www|site|root|hytop|flashfxp).*\.rar',
'(phpmyadmin|jmx-console|jmxinvokerservlet)',
'/xmlrpc.php',
'/(attachments|upimg|images|css|uploadfiles|html|uploads|templets|static|template|data|inc|forumdata|upload|includes|cache|avatar)/(\w+).(php|jsp|asp)',

);

sub tail {

my ($filename,$linenum)=@_;
print "DEBUG :: tail() :: IN : $filename,$linenum \n" if $DEBUG;
my $bw = File::ReadBackwards->new($filename)
  or die "can't read $filename $!";

my $count = 0;
my @lines;

while ( defined( my $line = $bw->readline ) ) {
    push @lines, $line;
    $count++;
    if ( $count == $linenum ) { last }
}

@lines = reverse @lines;
return \@lines;
}

sub initCount {

my $line=shift;
my @re=@validurl;
my $kcount=shift;
my ($zcount,$zip,$zrequrl,$zstatus,$siteurl);
my $rawlog;

for (@re) {
    my $result = scarlog1( $_,$line);
    my ( $mycount, $mylog ) = count($result);
    my $key = $_;
       $rawlog.=$mylog->{$key} if $mylog->{$key};
        
        $zcount+= $mycount->{$key}->[0] if $mycount->{$key}->[0];
        print "DEBUG\:: initCount()\::OUT  $key $mycount->{$key}->[0]   $zcount \n" if $DEBUG;
        $zip->{$_}+=$mycount->{$key}->[1]->{$_}  for ( keys %{ $mycount->{$key}->[1] } );
        $zrequrl->{$_}+=$mycount->{$key}->[2]->{$_}  for (keys %{ $mycount->{$key}->[2] } );
        if ($DEBUG) {
        print "DEBUG\:: initCount()\::OUT  $key $zrequrl->{$_}  $_\=> $mycount->{$key}->[2]->{$_} \n" for (keys %{ $mycount->{$key}->[2] } ) ;}
        $zstatus->{$_}+=$mycount->{$key}->[3]->{$_}   for (keys %{ $mycount->{$key}->[3] } );
        $siteurl->{$_}+=$mycount->{$key}->[4]->{$_}  for (keys %{ $mycount->{$key}->[4] } );

    }
 if ($DEBUG) {
print  "DEBUG\:: initCount()\::OUT\::\$zrequrl  $_\=>$zrequrl->{$_}\n"  for(keys %{$zrequrl})  ;
  }
return ($rawlog,$zcount,$zip,$zrequrl,$zstatus,$siteurl);
}

sub count {

    my $result = shift;

    my ($mcount, %rawlog);
    my $count = 0;
    for ( keys %{$result} ) {
        my (%ip, %requrl, %status, %siteurl);

        next if $result->{$_} eq "";
        $rawlog{$_} .= $result->{$_};
        my @seclogs = split /\n/ms, $result->{$_};
        for (@seclogs) {
           $count++;
            print "DEBUG\:: count()\::IN $_\n" if $DEBUG;
            my ( $ip, $requrl, $status, $siteurl ) = (split)[ 0, 6, 8, 10 ];
            $ip{$ip}++ if $ip;
            $requrl{$requrl}++ if $requrl;
            $status{$status}++ if $status;
            $siteurl{$siteurl}++ if $siteurl;
           print "DEBUG\:: count()\::OUT $ip\=>$ip{$ip} $requrl\=>$requrl{$requrl} $status\=>$status{$status} $siteurl\=>$siteurl{$siteurl} \n" if $DEBUG;
        }

        $mcount->{$_} = [ $count, \%ip, \%requrl, \%status, \%siteurl ];

    }

    return $mcount, \%rawlog;
}


sub scarlog1 {

    my ( $patter, $lines ) = @_;

    my %result;

    my $code = 'for(@{$lines}) {';
    $code .= 'if (m#';
    $code .= qr($patter);
    $code .= '#) {$result{' . q($patter) . '}.=$_}}';

    #print $patter, ":\n";
    eval $code;
    die "Error ---: $@\n Code:\n$code\n" if ($@);

    #print "DEBUG scarlog1 :: OUT :: $_: $result{$_}\n" for(keys %result);
    return \%result;
}
=head1 AUTHOR

ORANGE, C<< <bollwarm at ijz.me> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-app-waf at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=App-Waf>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc App::Waf


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker (report bugs here)

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=App-Waf>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/App-Waf>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/App-Waf>

=item * Search CPAN

L<http://search.cpan.org/dist/App-Waf/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2016 ORANGE.

This is free software; you can redistribute it and/or modify
it under the same terms as the Perl 5 programming language system itself.

=cut

1;    # End of App::Waf
