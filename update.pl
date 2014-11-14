#!/usr/bin/perl

use Getopt::Long;
use BWMGR;

GetOptions(
  "if=s" => \$arg_if,
  "mac" => \$arg_mac,
  "inet" => \$arg_inet,
  "id=s" => \$arg_id,
  "verbose" => \$arg_verbose,
  "noexec" => \$arg_noexec,
  "last:s" => \$arg_last
);

die(<<EOM
KLAIDA!

$0 --id=<filialo id> --if=<interfeisas> [--mac] [--inet] [--noexec] [--verbose] [--last=<index>[:<bwboth>]]

 --mac      - filtruoti pagal MAC adresa
 --inet	    - naudoti tarptautinio srauto greicio konfiguracija (default: LT)
 --noexec   - nepaleidineti bwmgr komandu kurios modifikuoja taisykles
 --verbose  - rodyti kokios bwmgr komandos paleidziamos

bbb: $0 --id=2 --if=em0 --mac --inet --noexec --verbose
EOM
) if not $arg_id or not $arg_if or $arg_id !~ m/^\d+(,\d+)*$/;
die("blogas formatas: --last=<index>[:<bwboth>]\n") if ($arg_last and $arg_last !~ m/^\d+(:\d+)?$/);

my $bwmgr = BWMGR->new(
  IFACE => $arg_if,
  RULES => "/etc/bwmgr.default",
  ID => $arg_id,
  MAC => $arg_mac,
  INET => $arg_inet,
  VERBOSE => $arg_verbose,
  NOEXEC => $arg_noexec,
  LAST => $arg_last
);

$bwmgr->run();
