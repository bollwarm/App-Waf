package App::Waf;

use 5.006;
use strict;
use warnings;

=head1 NAME

App::Waf - The great new App::Waf!

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

Quick summary of what the module does.

Perhaps a little code snippet.

    use App::Waf;

    my $foo = App::Waf->new();
    ...

=head1 EXPORT

A list of functions that can be exported.  You can delete this section
if you don't export anything, such as for a purely object-oriented module.

=head1 SUBROUTINES/METHODS
=cut

use File::ReadBackwards;
my $dirctor = shift;

#usage tailfilebackwards filename numlines
my $filename = "/web/logs/access.log";
my $numlines = 100000;

$bw = File::ReadBackwards->new($filename)
  or die "can't read $filename $!";

my $count = 0;
my @lines;

while ( defined( $line = $bw->readline ) ) {
    push @lines, $line;
    $count++;
    if ( $count == $numlines ) { last }
}
@lines = reverse @lines;

my $validurl =
q#rfd.php\?include_file  \.\./  select.+(from|limit)  (?:(union(.*?)select))  having|rongjitest  sleep\((\s*)(\d*)(\s*)\)
            benchmark\((.*)\,(.*)\)  base64_decode\( (?:from\W+information_schema\W)
            (?:(?:current_)user|database|schema|connection_id)\s*\(  (?:etc\/\W*passwd)
            into(\s+)+(?:dump|out)file\s*  group\s+by.+\(  xwork.MethodAccessor
            (?:define|eval|file_get_contents|include|require|require_once|shell_exec|phpinfo|system|passthru|preg_\w+|execute|echo|print|print_r|var_dump|(fp)open|concat|alert|showmodaldialog)\( xwork\.MethodAccessor  (gopher|doc|php|glob|file|phar|zlib|ftp|ldap|dict|ogg|data)\:\/
            java\.lang  \$_(GET|post|cookie|files|session|env|phplib|GLOBALS|SERVER)\[
            \<(iframe|script|body|img|layer|div|meta|style|base|object|input)  (onmouseover|onerror|onload)\=
            .(bak|inc|old|mdb|sql|backup|java|class)$  \.(svn|htaccess|bash_history)
            (vhost|bbs|host|wwwroot|www|site|root|hytop|flashfxp).*\.rar
            (phpmyadmin|jmx-console|jmxinvokerservlet)  java\.lang
            /(attachments|upimg|images|css|uploadfiles|html|uploads|templets|static|template|data|inc|forumdata|upload|includes|cache|avatar)/(\w+).(php|jsp)#;

my @validurl = split /\s+/, $validurl;

my $start = time;

for (@validurl) {

    #http://www.freebuf.com/sectool/110644.html
    chomp;
    scarlog($_) if $dirctor;

}
my $duration = time - $start;
print "while loop Execution time: $duration s\n";

sub scarlog {

    my $re = shift;
    print "$re:\n";

    for (@lines) {
        print if /$re/;
    }
}

my $start = time;
for (@validurl) {
    my $result = scarlog1( $_, \@lines ) unless $dirctor;
    my ( $mycount, $mylog ) = count($result);
    my $key = $_;
    print "The count $_ is $mycount->{$_}->[0] \n";
    print "$mylog->{$_}";
    print "IP count:\n";
    for ( sort keys %{ $mycount->{$key}->[1] } ) {
        print "$_ : $mycount->{$key}->[1]->{$_} \n";

    }

}
my $duration = time - $start;

sub count {

    my $result = shift;

    my $mcount, %rawlog;
    my $count = 0;
    for ( keys %{$result} ) {
        my %ip, %result, %status, %siteurl;

        next if $result->{$_} eq "";
        $rawlog{$_} .= $result->{$_};
        my @seclogs = split /\n/ms, $result->{$_};
        $count++;
        for (@seclogs) {
            my ( $ip, $requrl, $status, $siteurl ) = (split)[ 0, 6, 8, 10 ];
            $ip{$ip}++;
            $requrl{$requrl}++;
            $status{$status}++;
            $siteurl{$siteurl}++;
        }
        $mcount->{$_} = [ $count, \%ip, \%requrl, \%status, \%siteurl ];

    }

    return $mcount, \%rawlog;
}

print "while loop Execution time: $duration s\n";

sub scarlog1 {

    my ( $patter, $lines ) = @_;

    my %result;

    $code = 'for(@{$lines}) {';
    $code .= 'if (m#';
    $code .= qr($patter);
    $code .= '#) {$result{' . q($patter) . '}.=$_}}';

    #print $patter, ":\n";
    eval $code;
    die "Error ---: $@\n Code:\n$code\n" if ($@);

    #print "DEBUG scarlog1 :: OUT :: $_: $result{$_}\n" for(keys %result);
    return \%result;

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


=cut

    1;    # End of App::Waf
