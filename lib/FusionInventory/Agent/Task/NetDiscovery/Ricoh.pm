package FusionInventory::Agent::Task::NetDiscovery::Ricoh;

use strict;
use warnings;

sub getDescription {
    my ($session) = @_;

    my $result = $session->snmpGet({
        oid => '.1.3.6.1.4.1.11.2.3.9.1.1.7.0',
        up  => 1,
    });

    return $result;
}

1;
