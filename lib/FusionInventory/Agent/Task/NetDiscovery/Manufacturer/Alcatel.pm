package FusionInventory::Agent::Task::NetDiscovery::Manufacturer::Alcatel;

use strict;
use warnings;

sub discovery {
    my ($session) = @_;

    my $result = $session->snmpGet({
        oid => '.1.3.6.1.2.1.47.1.1.1.1.13.1',
        up  => 1,
    });

    if ($result && $result eq 'OS66-P24') {
        $result = 'OmniStack 6600-P24';
    }

    return $result;
}

1;
