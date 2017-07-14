#app-waf

##一个简单的waf模块。

用来实时探测web 非法访问，统计非法访问的ip ，web状态，访问url，来源web url。结合iptables可以实现实现实时封禁。

## 实例说明 见example目录（包括日志）

    use App::Waf;
    my $filename = "example.acess";#日志文件
    my $numlines  = 50000; #要处理的行数,从后读。
    my $line=tail($filename,$$numlines);
    my ($log,$zcount,$zip,$zrequrl,$zstatus,$siteurl)=initCount($line);
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

## 结合nginx 和 iptables 进行实时banip的实例（example/banip.pl）
   
加入crontab 每5分钟执行一次。

    echo "*/5 * * * * perl $dir/example/ngixban.pl >> bianip.logs 2>&1 " >> /var/spool/cron/root
    echo "*/5 * * * * perl $dir/example/synban.pl >> bianip.logs 2>&1 " >> /var/spool/cron/root

## 结果展示

+++++++++++++++++++++++++ban for SYN attact+++++++++++++++++++++

    Fri Jul 14 15:46:02 2017 Ban The IP ：173.173.199.246
    Fri Jul 14 15:46:02 2017 :band 173.173.199.246
    Fri Jul 14 15:46:02 2017 73.6.1.122 SYN攻击次数: 6
    Fri Jul 14 15:46:02 2017 103.56.116.150 SYN攻击次数: 2
    Fri Jul 14 15:47:01 2017 173.173.199.246 SYN攻击次数: 19
    Fri Jul 14 15:47:01 2017 Ban The IP ：173.173.199.246
    Fri Jul 14 15:47:01 2017 baned 173.173.199.246
    Fri Jul 14 15:47:01 2017 103.56.116.150 SYN攻击次数: 1
    Fri Jul 14 15:48:01 2017 173.173.199.246 SYN攻击次数: 19
    Fri Jul 14 15:48:01 2017 Ban The IP ：173.173.199.246
    Fri Jul 14 15:48:01 2017 baned 173.173.199.246
    Fri Jul 14 15:48:01 2017 103.56.116.150 SYN攻击次数: 1
    Fri Jul 14 15:49:01 2017 173.173.199.246 SYN攻击次数: 17
    Fri Jul 14 15:49:01 2017 Ban The IP ：173.173.199.246
    Fri Jul 14 15:49:01 2017 band alread!

==============Attack Summary ==================

    The total attack count: 131
    
    The count from source IP:
    
    103.248.223.116=> 19
    103.37.3.202=> 2
    106.39.200.46=> 3
    107.151.213.123=> 1
    115.148.98.127=> 2
    180.76.6.51=> 99
    59.42.147.17=> 4
    64.16.214.100=> 1

The count From request Url:

    /?cat=%0acat%20/etc/passwd%0a&paged=3=> 1
    /?cat=%22%26cat%20/etc/passwd%26%22&paged=3=> 1
    /?cat=%22;print(md5(acunetix_wvs_security_test));%24a%3d%22&paged=2=> 1
    /?cat=%22;print(md5(acunetix_wvs_security_test));%24a%3d%22&paged=3=> 1
    /?cat=%24%7b%40print(md5(acunetix_wvs_security_test))%7d%5c&paged=2=> 1
    /?cat=%24%7b%40print(md5(acunetix_wvs_security_test))%7d%5c&paged=3=> 1
    /?cat=%24%7b%40print(md5(acunetix_wvs_security_test))%7d&paged=2=> 1
    /?cat=%24%7b%40print(md5(acunetix_wvs_security_test))%7d&paged=3=> 1
    /?cat=%26cat%20/etc/passwd%26&paged=3=> 1
    /?cat=%60cat%20/etc/passwd%60&paged=3=> 1
    /?cat=%7ccat%20/etc/passwd%23&paged=3=> 1
    /?cat='%26cat%20/etc/passwd%26'&paged=3=> 1
    /?cat=';print(md5(acunetix_wvs_security_test));%24a%3d'&paged=2=> 1
    /?cat=';print(md5(acunetix_wvs_security_test));%24a%3d'&paged=3=> 1
    /?cat=(select(0)from(select(sleep(15)))v)/*'%2b(select(0)from(select(sleep(15)))v)%2b'%22%2b(select(0)from(select(sleep(15)))v)%2b%22*
    /&paged=3=> 4
    /?cat=.%5c%5c./.%5c%5c./.%5c%5c./.%5c%5c./.%5c%5c./.%5c%5c./etc/passwd&paged=3=> 1
    /?cat=..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd&paged=3=> 1
    
