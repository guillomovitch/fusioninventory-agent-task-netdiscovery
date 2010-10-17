package FusionInventory::Agent::Task::NetDiscovery::Manufacturer::Axis;

use strict;
use warnings;

sub getDescription {
    my ($session) = @_;

    my $result = $session->snmpGet({
        oid => '.1.3.6.1.4.1.2699.1.2.1.2.1.1.3.1',
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
