package BWMGR;

use strict;
use Data::Dumper;

sub new {
  my ($class, %params) = @_;
  my $self = {};
  $self->{CMD} = $params{CMD} || "/usr/bwmgr/utils/bwmgr";
  $self->{RULES} = $params{RULES} || undef;
  $self->{IFACE} = $params{IFACE} || undef;
  $self->{VERBOSE} = $params{VERBOSE} || undef;
  $self->{NOEXEC} = $params{NOEXEC} || undef;
  $self->{LAST} = $params{LAST} || undef;
  $self->{ID} = $params{ID} || undef; # filialo ID, formatas \d+(,\d+)*
  $self->{MAC} = $params{MAC} || undef; # deti/nedeti filtravima pagal MAC
  $self->{INET} = $params{INET} || undef; # naudoti INET greicio konfiga (default LT)

  bless($self, $class);
  return $self;
}

my %bwmgr_matchers = (
  x => '^(\d+)',
  ipprot => 'prot:([-\w]+)',
  addr => 'addr:((\d+\.){3}\d+)\/(\d+\.){3}\d+',
  addrmsk => 'addr:[\d\.]+\/([\d\.]+)',
  saddr => 'saddr:((\d+\.){3}\d+)\/(\d+\.){3}\d+',
  saddrmsk => 'saddr:[\d\.]+\/([\d\.]+)',
  daddr => 'daddr:((\d+\.){3}\d+)\/(\d+\.){3}\d+',
  daddrmsk => 'daddr:[\d\.]+\/([\d\.]+)',
  bwin => 'BW-IN:(\d+)bps',
  bwout => 'BW-OUT:(\d+)bps',
  bwboth => 'BW-BOTH:(\d+)bps',
  maddr => 'maddr:((\w{2}:){5}\w{2})',
  port => 'port:([-\w]+)',
  sport => 'sport:([-\w]+)',
  dport => 'dport:([-\w]+)',
  priority => 'priority:([-\w]+)'
);

sub run {
  my ($self) = @_;

  my $actual_rules = $self->load_actual_rules();
  my $config_rules = $self->load_config_rules();
  my $client_rules = $self->load_client_rules();
  my $expected_rules = [ @$client_rules, @$config_rules ];

  foreach my $actual_rule (@$actual_rules) {
    if ($self->is_not_in($actual_rule, $expected_rules)) {
      $self->remove_rule($actual_rule);
    }
  }

  foreach my $expected_rule (@$expected_rules) {
    if ($self->is_not_in($expected_rule, $actual_rules)) {
      $self->add_rule($expected_rule);
    }
  }

  $self->add_last_rule();
}

sub is_not_in {
  my ($self, $rule, $rules) = @_;
  foreach my $item (@$rules) {
    if ($self->is_equal($rule, $item)) {
      return undef;
    }
  }
  1;
}

sub load_client_rules {
  my ($self) = @_;
  my @rules = ();

  my $cmd = qx(/usr/bin/ssh 89.190.99.132 $self->{ID});
  foreach (split /[\r\n]+/, $cmd) {
    my ($id, $ip, $mac, $inet_in, $inet_out, $lt_in, $lt_out) = split /\|/;
    my %rule = ();
    $rule{x} = $id;
    $rule{addr} = $ip;
    $rule{addrmsk} = '255.255.255.255';
    $rule{maddr} = $mac if $self->{MAC};
    $rule{bwin} = $self->{INET} ? $inet_in : $lt_in;
    $rule{bwout} = $self->{INET} ? $inet_out : $lt_out;
    push @rules, \%rule;
  }

  \@rules;
}

sub load_config_rules {
  my ($self) = @_;
  my @rules = ();

  open RULES, $self->{RULES} or return ();
  while (my $line = <RULES>) {
    push @rules, $self->parse_config_rule($line);
  }
  close RULES;

  \@rules;
}

sub parse_config_rule {
  my ($self, $line) = @_;
  my %rule;

  foreach (keys %bwmgr_matchers) {
    $rule{$_} = $1 if $line =~ m/-$_\s+([\.:-\w]+)/i;
  }

  \%rule;
}

sub load_actual_rules {
  my ($self) = @_;

  my $command = sprintf("%s %s show", $self->{CMD}, $self->{IFACE});
  my @output = `$command`;
  my @rules = ();
  for (@output) {
    next if not m/^\d+/;
    push @rules, $self->parse_actual_rule($_);
  }

  return \@rules;
}

sub parse_actual_rule {
  my ($self, $line) = @_;
  my %rule;

  $rule{x} = $1 if $line =~ m/^(\d+)\s+/;
  foreach (keys %bwmgr_matchers) {
    $rule{$_} = $1 if $line =~ m/\s$bwmgr_matchers{$_}/i;
  }

  \%rule;
}

sub is_equal {
  my ($self, $src, $dst) = @_;

  return undef if ($src->{x} ne $dst->{x});
 
  my $found = 1;

  foreach (keys %$src) {
    if (not exists($dst->{$_}) or $src->{$_} ne $dst->{$_}) {
      $found = undef;
    }
  }
  foreach (keys %$dst) {
    if (not exists($src->{$_}) or $src->{$_} ne $dst->{$_}) {
      $found = undef; 
    }
  }

  $found;
}

sub add_rule {
  my ($self, $rule) = @_;

  my @cmd_args = ();
  foreach (keys %$rule) {
    push @cmd_args, sprintf("-%s %s", $_, $rule->{$_});
  }
  my $command = sprintf("%s %s %s", $self->{CMD}, $self->{IFACE}, join ' ', sort @cmd_args);
  print "exec: $command\n" if $self->{VERBOSE};
  `$command` if not $self->{NOEXEC};
}

sub remove_rule {
  my ($self, $rule) = @_;

  my $last_rule = $self->get_last_rule();
  return if $last_rule and $rule->{x} eq $last_rule->{x};

  my $command = sprintf("%s %s -x %s", $self->{CMD}, $self->{IFACE}, $rule->{x});
  print "exec: $command\n" if $self->{VERBOSE};
  `$command` if not $self->{NOEXEC};
}

sub get_last_rule {
  my ($self) = @_;
  my %rule;
  if ($self->{LAST} =~ m/(\d+):(\d+)/) {
    $rule{x} = $1;
    $rule{bwboth} = $2;
    $rule{l} = '';
  } elsif ($self->{LAST} =~ m/(\d+)/) {
    $rule{x} = $1;
    $rule{priority} = 'discard';
    $rule{l} = '';
  }
  return \%rule;
}

sub add_last_rule {
  my ($self) = @_;

  my $rule = $self->get_last_rule();
  return if not $rule;

  my @cmd_args = ();
  foreach (keys %$rule) {
    push @cmd_args, sprintf("-%s %s", $_, $rule->{$_});
  }
  my $command = sprintf("%s %s %s", $self->{CMD}, $self->{IFACE}, join ' ', sort @cmd_args);
  `$command`;
}

1;
