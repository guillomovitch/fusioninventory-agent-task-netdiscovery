package FusionInventory::Agent::Task::NetDiscovery::Samsung;

use strict;
use warnings;

sub getDescription {
    my ($session) = @_;

    my $result = $session->snmpGet({
        oid => '.1.3.6.1.4.1.236.11.5.1.1.1.1.0',
        up  => 1,
    });

    return $result;
}

1;
