package FusionInventory::Agent::Task::NetDiscovery::Manufacturer::Epson;

use strict;
use warnings;

sub getDescriptionBuiltin {
    my ($session) = @_;

    my $result = $session->snmpGet({
        oid => '.1.3.6.1.4.1.1248.1.1.3.1.3.8.0',
        up  => 1,
    });

    return $result;
}

sub getDescriptionInternal {
    my ($session) = @_;

    my $result = $session->snmpGet({
        oid => '.1.3.6.1.2.1.25.3.2.1.3.1',
        up  => 1,
    });

    return $result;
}

1;
