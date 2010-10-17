package FusionInventory::Agent::Task::NetDiscovery::Dell;

use strict;
use warnings;

sub getDescription {
    my ($session) = @_;

    my $result = $session->snmpGet({
        oid => '.1.3.6.1.4.1.674.10895.3000.1.2.100.1.0',
        up  => 1,
    });

    return $result;
}

1;
