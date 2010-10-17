package FusionInventory::Agent::Task::NetDiscovery::Manufacturer::Zebranet;

use strict;
use warnings;

sub getDescription {
    my ($session) = @_;

    my $result = $session->snmpGet({
        oid => '.1.3.6.1.4.1.11.2.3.9.1.1.7.0',
        up  => 1,
    });

    return unless $result;

    foreach my $info (split(/;/, $result)) {
        if ($info =~ /^MDL:/) {
            $info =~ s/MDL://;
            return $info;
        } elsif ($info =~ /^MODEL:/) {
            $info =~ s/MODEL://;
            return $info;
        }
    }

    return;
}

1;
