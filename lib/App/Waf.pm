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
my $dirctor=shift;

#usage tailfilebackwards filename numlines
my $filename = "/web/logs/access.log";
my $numlines  = 100000;


$bw = File::ReadBackwards->new($filename) or
die "can't read $filename $!" ;

my $count=0;
my @lines;

while(defined($line = $bw->readline)){
push @lines,$line ;
$count++;
if ($count == $numlines){last}
}
@lines= reverse @lines;


my $validurl=q#rfd.php\?include_file  \.\./  select.+(from|limit)  (?:(union(.*?)select))  having|rongjitest  sleep\((\s*)(\d*)(\s*)\)
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

my @validurl=split /\s+/,$validurl;

my $start = time;

for (@validurl) {
#http://www.freebuf.com/sectool/110644.html
chomp;
scarlog($_) if $dirctor;

};
my $duration = time - $start;
print  "while loop Execution time: $duration s\n";


sub scarlog {

   my  $re=shift;
   print "$re:\n";

for(@lines) {
    print if /$re/;
}
}

my $start = time;
for (@validurl) {
my $result=scarlog1($_,\@lines) unless $dirctor;
my ($mycount,$mylog)=count($result);
    my $key=$_;
    print "The count $_ is $mycount->{$_}->[0] \n";
    print "$mylog->{$_}";
    print "IP count:\n";
    for( sort keys %{$mycount->{$key}->[1]}) {
      print "$_ : $mycount->{$key}->[1]->{$_} \n";

     }


}
my $duration = time - $start;


sub count {

my $result=shift;

    my $mcount,%rawlog;
    my $count=0;
    for(keys %{$result}) {
    my %ip,%result,%status,%siteurl;

     next if $result->{$_} eq "";
     $rawlog{$_}.=$result->{$_};
     my @seclogs=split /\n/ms, $result->{$_};
     $count++;
     for(@seclogs) {
      my ($ip,$requrl,$status,$siteurl)=(split)[0,6,8,10];
      $ip{$ip}++;
      $requrl{$requrl}++;
      $status{$status}++;
      $siteurl{$siteurl}++;
     }
     $mcount->{$_}=[$count,\%ip,\%requrl,\%status,\%siteurl];

  }

 return $mcount,\%rawlog;
}


print  "while loop Execution time: $duration s\n";


sub scarlog1 {

my ($patter,$lines)=@_;

my %result;

$code = 'for(@{$lines}) {';
$code .= 'if (m#';
$code .= qr($patter);
$code .= '#) {$result{'.q($patter).'}.=$_}}';
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

This program is free software; you can redistribute it and/or modify it
under the terms of the the Artistic License (2.0). You may obtain a
copy of the full license at:

L<http://www.perlfoundation.org/artistic_license_2_0>

Any use, modification, and distribution of the Standard or Modified
Versions is governed by this Artistic License. By using, modifying or
distributing the Package, you accept this license. Do not use, modify,
or distribute the Package, if you do not accept this license.

If your Modified Version has been derived from a Modified Version made
by someone other than you, you are nevertheless required to ensure that
your Modified Version complies with the requirements of this license.

This license does not grant you the right to use any trademark, service
mark, tradename, or logo of the Copyright Holder.

This license includes the non-exclusive, worldwide, free-of-charge
patent license to make, have made, use, offer to sell, sell, import and
otherwise transfer the Package with respect to any patent claims
licensable by the Copyright Holder that are necessarily infringed by the
Package. If you institute patent litigation (including a cross-claim or
counterclaim) against any party alleging that the Package constitutes
direct or contributory patent infringement, then this Artistic License
to you shall terminate on the date that such litigation is filed.

Disclaimer of Warranty: THE PACKAGE IS PROVIDED BY THE COPYRIGHT HOLDER
AND CONTRIBUTORS "AS IS' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES.
THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE, OR NON-INFRINGEMENT ARE DISCLAIMED TO THE EXTENT PERMITTED BY
YOUR LOCAL LAW. UNLESS REQUIRED BY LAW, NO COPYRIGHT HOLDER OR
CONTRIBUTOR WILL BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR
CONSEQUENTIAL DAMAGES ARISING IN ANY WAY OUT OF THE USE OF THE PACKAGE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


=cut

1; # End of App::Waf
