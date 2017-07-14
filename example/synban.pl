#!/usr/bin/perl

use App::Waf;

# 设置日志文件和需要解析的文件大小，一般是web日志，$threshold为封禁的阈值
# 可以根据实际情况调节大小

=pod
## 结合nginx 和 iptables 进行实时banip的实例（example/banip.pl）

## 加入crontab 每5分钟执行一次。

=code<`echo "*/5 * * * * perl $dir/banip.pl >> bianip.logs 2>&1 " >> /var/spool/cron/root`>

=cut

my $cmd=q(/usr/sbin/ss -a|grep SYN-RECV|perl -lane 'print $F[-1]'|perl -pe 's/:.*$//');
my @sync_ps_count=`$cmd`;
my %ipcount;
my $threshold=8;
my $btime=localtime time;
for(@sync_ps_count){

chomp;
$ipcount{$_}++;
}

for(sort {$ipcount{$b}<=>$ipcount{$a}} keys %ipcount) {

print "$btime $_ SYN攻击次数: $ipcount{$_} \n";

# Count are more than shreshold, Then Ban it through iptables;

if ($ipcount{$_} > $threshold) {

  print  "$btime Ban The IP ：$_ \n";

  iptabBan($_);
}

}

=pod
sub iptabBan {

# must be root user;
# 必须root用户才可以操作iptables，当然也必须有iptables服务跑动着

    my $IP = shift;

    my $ips     = `/sbin/iptables-save`;
    my @ipsline = split /\n/sm, $ips;
    my $dist    = 0;
    for (@ipsline) {

        $dist = 1 if ( /$IP/ and /INPUT/ and /DROP/ );

    }
    unless ($dist) {
        `/sbin/iptables -I INPUT -s $IP -j DROP`;
        my $btime = localtime( time() );
        print "$btime :band $IP \n";
    }
    else {

        print "band alread!\n";

    }

}
=cut
