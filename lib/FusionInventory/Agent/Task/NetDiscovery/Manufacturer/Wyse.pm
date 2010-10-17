package FusionInventory::Agent::Task::NetDiscovery::Manufacturer::Wyse;

use strict;
use warnings;

sub getDescription {
    my ($session) = @_;

    my $result = $session->snmpGet({
        oid => '.1.3.6.1.4.1.714.1.2.5.6.1.2.1.6.1',
        up  => 1,
    });

    if ($result) {
        $result =~ s/^"//;
        $result =~ s/"$//;
        $result = "Wyse $result";
    }

    return $result;
}

1;
