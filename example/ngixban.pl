#!/usr/bin/perl

use App::Waf;

# 设置日志文件和需要解析的文件大小，一般是web日志，$threshold为封禁的阈值
# 可以根据实际情况调节大小

my $filename  = "/web/logs/access.log";
my $numlines  = 10000;
my $threshold = 200;

=pod
## 结合nginx 和 iptables 进行实时banip的实例（example/banip.pl）

## 加入crontab 每5分钟执行一次。

=code<`echo "*/5 * * * * perl $dir/banip.pl >> bianip.logs 2>&1 " >> /var/spool/cron/root`>
## 以下设置nginx格式，包括nginx封禁的文件和重启nginx
## 需要的pid格式。

=cut

my $nginx_home  = "/usr/local/nginx";
my $ngixBanfile = $nginx_home . '/conf/conf.d/blockip.conf';
my $ngixPidfile = $nginx_home . '/logs/nginx.pid';

my $line = tail( $filename, $numlines );

( $log, $zcount, $zip, $zrequrl, $zstatus, $siteurl ) = initCount($line);

for ( sort { $zip->{$b} <=> $zip->{$a} } keys %{$zip} ) {

    print "$_ : $zip->{$_} \n" if $zip->{$_} > $threshold;

    nginxBan( $_, $ngixBanfile, $ngixPidfile ) if $zip->{$_} > $threshold;


}

sub nginxBan {

    my $btime = localtime( time() );
    my ( $ip, $conf, $pid ) = @_;
    my $bid = 0;
    open my $nFD, "<", $conf or die("Can not open the file!$!\n");
    while (<$nFD>) {
        print "DEBUG ::nginxBan :: $conf IN $_" if $DEBUG;
        $bid = 1 if /$ip/;
    }
    close $nFD;

    open my $nFD, ">>", $conf or die("Can not open 1 the file!$!\n");

    unless ($bid) {
        print "$btime,banip $ip\n";
        print $nFD "deny $ip\;\n";
        $pid = `cat $pid`;
        chomp $pid;
        `/usr/bin/kill -HUP $pid`;
    }

    close $nFD;

}
