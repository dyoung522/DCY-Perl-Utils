use 5.008005;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'DCY::Utils',
    #VERSION_FROM      => 'lib/DCY/Utils.pm', # finds $VERSION
    VERSION           => '1.10',
    NO_META           => 1,
    PREREQ_PM         => { 'Net::FTP' => 0,
                           'Net::SCP' => 0,
                           'Regexp::Shellish' => 0,
                           'Net::SFTP' => 0,
                         }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/DCY/Utils.pm', # retrieve abstract from module
       AUTHOR         => 'Donovan C. Young <dyoung522@gmail.com>') : ()),
);
