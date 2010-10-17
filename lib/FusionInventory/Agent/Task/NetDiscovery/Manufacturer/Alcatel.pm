package FusionInventory::Agent::Task::NetDiscovery::Manufacturer::Alcatel;

use strict;
use warnings;

sub discovery {
    my ($description, $session) = @_;

    # example : 5.1.6.485.R02 Service Release, September 26, 2008.

    if ($description =~ m/Service Release/ ) {
        my $description_new = $session->snmpGet({
            oid => '.1.3.6.1.2.1.47.1.1.1.1.13.1',
            up  => 1,
        });
        if ($description_new) {
            if ($description_new eq "OS66-P24") {
                $description = "OmniStack 6600-P24";
            } else {
                $description = $description_new;
            }
        }
    }
    return $description;
}

1;
