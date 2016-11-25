use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'App::Waf',
    AUTHOR           => q{ORANGE <bollwarm@ijz.me>},
    VERSION_FROM     => 'lib/App/Waf.pm',
    ABSTRACT_FROM    => 'lib/App/Waf.pm',
    LICENSE          => 'Perl',
    PL_FILES         => {},
    MIN_PERL_VERSION => 5.006,
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => 0,
        'File::ReadBackwards' => 0,
    },
    BUILD_REQUIRES => {
        'Test::More' => 0,
    },
    PREREQ_PM => {
        #'ABC'              => 1.6,
        #'Foo::Bar::Module' => 5.0401,
    },
   
       META_MERGE => {
          'meta-spec' => { version => 2 },
           resources   => {
            repository => {
                type => 'git',
                url  => 'https://github.com/bollwarm/app-waf.git',
                web  => 'http://ijz.me',
            },
        },
    },


    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'App-Waf-*' },
);
