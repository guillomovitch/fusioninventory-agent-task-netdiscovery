package FusionInventory::Agent::Task::NetDiscovery::Manufacturer::Dell;

use strict;
use warnings;

sub discovery {
    my ($description, $session) = @_;

    # for Switch
    if ($description eq 'Ethernet Switch') {
        my $description_new = $session->snmpGet({
            oid => '.1.3.6.1.4.1.674.10895.3000.1.2.100.1.0',
            up  => 1,
        });
        if ($description_new) {
            $description = $description_new;
        }
    }

    return $description;
}

1;
