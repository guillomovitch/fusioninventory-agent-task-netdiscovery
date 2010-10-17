package FusionInventory::Agent::Task::NetDiscovery::Ddwrt;

use strict;
use warnings;

sub getDescription {
    my ($session) = @_;

    my $result = $session->snmpGet({
        oid => '.1.3.6.1.2.1.1.5.0',
        up  => 1,
    });

    if ($result && $result eq 'dd-wrt') {
        $result = 'dd-wrt';
    }

    return $result;
}

1;
