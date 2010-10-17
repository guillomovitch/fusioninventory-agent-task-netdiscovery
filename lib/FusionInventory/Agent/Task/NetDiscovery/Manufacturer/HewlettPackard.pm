package FusionInventory::Agent::Task::NetDiscovery::Manufacturer::HewlettPackard;

use strict;
use warnings;

sub discovery {
    my ($description, $session) = @_;

    if (
        $description =~ m/HP ETHERNET MULTI-ENVIRONMENT/ ||
        $description =~ m/A SNMP proxy agent, EEPROM/
    ) {
        my $description_new = $session->snmpGet({
            oid => '.1.3.6.1.2.1.25.3.2.1.3.1',
            up  => 1,
        });
        if ($description_new) {
            $description = $description_new;
        } else {
            $description_new = $session->snmpGet({
                oid => '.1.3.6.1.4.1.11.2.3.9.1.1.7.0',
                up  => 1,
            });
            if ($description_new) {
                my @infos = split(/;/,$description_new);
                foreach (@infos) {
                    if ($_ =~ /^MDL:/) {
                        $_ =~ s/MDL://;
                        $description = $_;
                        last;
                    } elsif ($_ =~ /^MODEL:/) {
                        $_ =~ s/MODEL://;
                        $description = $_;
                        last;
                    }
                }
            }
        }
    }

    return $description;
}

1;
