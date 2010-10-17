package FusionInventory::Agent::Task::NetDiscovery;

use strict;
use warnings;
use base 'FusionInventory::Agent::Task';

use threads;
use threads::shared;
if ($threads::VERSION > 1.32){
    threads->set_stack_size(20*8192);
}

use Data::Dumper;
use Digest::MD5 qw(md5_hex);
use English qw(-no_match_vars);
use File::Find;
use Net::IP;
use UNIVERSAL::require;

use FusionInventory::Agent::Regexp;
use FusionInventory::Agent::Storage;
use FusionInventory::Agent::Tools;
use FusionInventory::Agent::Task::NetDiscovery::Dico;
use FusionInventory::Agent::XML::Query::SimpleMessage;

our $VERSION = '1.2';

my @dispatch_table = (
    {
        # alcatel
        match => qr/^\S+ Service Release/,
        module => 'FusionInventory::Agent::Task::NetDiscovery::Alcatel',
        function => 'getDescription'
    },
    {
        match => qr/AXIS OfficeBasic Network Print Server/,
        module => 'FusionInventory::Agent::Task::NetDiscovery::Axis',
        function => 'getDescription'

    },
    {
        # dd-wrt
        match => qr/Linux/,
        module => 'FusionInventory::Agent::Task::NetDiscovery::Ddwrt',
        function => 'getDescription'
    },
    {
        # dell switch
        match => 'Ethernet Switch',
        module => 'FusionInventory::Agent::Task::NetDiscovery::Dell',
        function => 'getDescription'
    },
    {
        # Epson
        match => qr/EPSON Built-in/,
        module => 'FusionInventory::Agent::Task::NetDiscovery::Epson',
        function => 'getDescriptionBuiltin'
    },
    {
        # Epson
        match => qr/EPSON Internal 10Base-T/,
        module => 'FusionInventory::Agent::Task::NetDiscovery::Epson',
        function => 'getDescriptionInternal'
    },
    {
        match => qr/HP ETHERNET MULTI-ENVIRONMENT/,
        module => 'FusionInventory::Agent::Task::NetDiscovery::HewlettPackard',
        function => 'getDescription'
    },
    {
        match => qr/A SNMP proxy agent, EEPROM/,
        module => 'FusionInventory::Agent::Task::NetDiscovery::HewlettPackard',
        function => 'getDescription'
    },
    {
        # kyocera
        match => qr/,HP,JETDIRECT,J/,
        module => 'FusionInventory::Agent::Task::NetDiscovery::Kyocera',
        function => 'getDescriptionHP'
    },
    {
        match => 'KYOCERA MITA Printing System',
        module => 'FusionInventory::Agent::Task::NetDiscovery::Kyocera',
        function => 'getDescriptionOther'
    },
    {
        match => 'KYOCERA Printer I/F',
        module => 'FusionInventory::Agent::Task::NetDiscovery::Kyocera',
        function => 'getDescriptionOther'

    },
    {
        match => 'SB-110',
        module => 'FusionInventory::Agent::Task::NetDiscovery::Kyocera',
        function => 'getDescriptionOther'

    },
        {
        match => qr/RICOH NETWORK PRINTER/,
        module => 'FusionInventory::Agent::Task::NetDiscovery::Ricoh',
        function => 'getDescription'

    },
    {
        # samsung
        match => qr/SAMSUNG NETWORK PRINTER,ROM/,
        module => 'FusionInventory::Agent::Task::NetDiscovery::Samsung',
        function => 'getDescription'
    },
    {
        # Wyse
        match => qr/Linux/,
        module => 'FusionInventory::Agent::Task::NetDiscovery::Wyse',
        function => 'getDescription'
    },
    {
        # Zebra
        match => qr/ZebraNet PrintServer/,
        module => 'FusionInventory::Agent::Task::NetDiscovery::Zebranet',
        function => 'getDescription'
    },
);

sub run {
    my ($self) = @_;

    if (!$self->{target}->isa('FusionInventory::Agent::Target::Server')) {
        $self->{logger}->debug("No server. Exiting...");
        return;
    }

    my $options = $self->{prologresp}->getOptionsInfoByName('NETDISCOVERY');
    if (!$options) {
        $self->{logger}->debug("No NETDISCOVERY. Exiting...");
        return;
    }

    $self->{logger}->debug("FusionInventory NetDiscovery module $VERSION");

    $self->{countxml} = 0;

    $self->startThreads();

    return;
}


sub startThreads {
    my ($self) = @_;

    my $options = $self->{prologresp}->getOptionsInfoByName('NETDISCOVERY');
    my $params  = $options->{PARAM}->[0];

    Parallel::ForkManager->require();
    if ($EVAL_ERROR) {
        if ($params->{CORE_DISCOVERY} > 1) {
            $self->{logger}->debug(
                "Parallel::ForkManager unvailable, only 1 core will be used..."
            );
            $params->{CORE_DISCOVERY} = 1;
        }
    }

    my $storage = $self->{target}->getStorage();
    my $dico;
    my $dicohash;

    # Load storage with XML dico
    if (defined($options->{DICO})) {
        $storage->save({
            idx => 999998,
            data => $options->{DICO}
        });
        $dicohash->{HASH} = md5_hex($options->{DICO});
        $storage->save({
            idx => 999999,
            data => $dicohash
        });
    }

    $dico = $storage->restore({
        idx => 999998
    });
    $dicohash = $storage->restore({
        idx => 999999
    });

    if ( (!defined($dico)) || !(%$dico)) {
        $dico = FusionInventory::Agent::Task::NetDiscovery::Dico->new();
        $storage->save({
            idx => 999998,
            data => $dico
        });
        $dicohash->{HASH} = md5_hex($dico);
        $storage->save({
            idx => 999999,
            data => $dicohash
        });
    }
    if (defined($options->{DICOHASH})) {
        if ($dicohash->{HASH} eq $options->{DICOHASH}) {
            $self->{logger}->debug("Dico is up to date.");
        } else {
            # Send Dico request to plugin for next time :
            my $xml_thread = {
                AGENT         => { END => 1 },
                MODULEVERSION => $VERSION,
                PROCESSNUMBER => $params->{PID},
                DICO          => 'REQUEST'
            };
            $self->sendInformations({
                data => $xml_thread
            });
            $self->{logger}->debug("Dico is old. Exiting...");
            return;
        }
    }
    $self->{logger}->debug("Dico loaded.");

    if (! Nmap::Parser->require()) {
        if (! Nmap::Scanner->require()) {
            $self->{logger}->debug(
                "Can't load Nmap::Parser or Nmap::Scanner. Nmap can't be used!"
            );
        }
    }

    if (! Net::NBName->require()) {
        $self->{logger}->debug(
            "Can't load Net::NBName. Netbios detection can't be used!"
        );
    }

    if (! FusionInventory::Agent::SNMP->require()) {
        $self->{logger}->debug(
            "Can't load FusionInventory::Agent::SNMP. SNMP detection can't be ".
            "used!"
        );
    }

    # Auth SNMP
    my $authlist = FusionInventory::Agent::SNMP->getAuthList($options);

    # Dispatch IPs to different core
    my $iplist = {};
    my $iplist2 = &share({});
    my $maxIdx : shared = 0;
    my $sendstart = 0;

    my $nbip = 0;
    my $countnb;
    my $nb_ip_per_thread = 25;
    my $limitip = $params->{THREADS_DISCOVERY} * $nb_ip_per_thread;
    my $ip;

    #============================================
    # Begin ForkManager (multiple core / process)
    #============================================
    my $pm;
    if ($params->{CORE_DISCOVERY} > 1) {
        $pm = Parallel::ForkManager->new($params->{CORE_DISCOVERY});
    }

    for (my $i = 0; $i < $params->{CORE_DISCOVERY}; $i++) {
        if ($params->{CORE_DISCOVERY} > 1) {
            my $pid = $pm->start and next;
        }

        my $threads_run = 0;
        my $loop_action : shared = 1;
        my $exit : shared = 0;

        my @Thread;
        my $ThreadState : shared;
        my $ThreadAction : shared;
        $iplist = &share({});
        my $loop_nbthreads : shared;
        my $sendbylwp : shared;
        my $sentxml = {};

        while ($loop_action > 0) {
            $countnb = 0;
            $nbip = 0;

            if ($threads_run == 0) {
                $iplist2 = &share({});
                $iplist = &share({});
            }


            if (ref($options->{RANGEIP}) eq "HASH"){
                if ($options->{RANGEIP}->{IPSTART} eq $options->{RANGEIP}->{IPEND}) {
                    if ($threads_run == 0) {
                        $iplist->{$countnb} = &share({});
                    }
                    $iplist->{$countnb}->{IP} = $options->{RANGEIP}->{IPSTART};
                    $iplist->{$countnb}->{ENTITY} = $options->{RANGEIP}->{ENTITY};
                    $iplist2->{$countnb} = $countnb;
                    $countnb++;
                    $nbip++;
                } else {
                    $ip = Net::IP->new($options->{RANGEIP}->{IPSTART}.' - '.$options->{RANGEIP}->{IPEND});
                    do {
                        if ($threads_run == 0) {
                            $iplist->{$countnb} = &share({});
                        }
                        $iplist->{$countnb}->{IP} = $ip->ip();
                        $iplist->{$countnb}->{ENTITY} = $options->{RANGEIP}->{ENTITY};
                        $iplist2->{$countnb} = $countnb;
                        $countnb++;
                        $nbip++;
                        if ($nbip eq $limitip) {
                            if ($ip->ip() ne $options->{RANGEIP}->{IPEND}) {
                                ++$ip;
                                $options->{RANGEIP}->{IPSTART} = $ip->ip();
                                $loop_action = 1;
                                goto CONTINUE;
                            }
                        }
                    } while (++$ip);
                    undef $options->{RANGEIP};
                }
            } else {
                foreach my $num (@{$options->{RANGEIP}}) {
                    if ($num->{IPSTART} eq $num->{IPEND}) {
                        if ($threads_run == 0) {
                            $iplist->{$countnb} = &share({});
                        }
                        $iplist->{$countnb}->{IP} = $num->{IPSTART};
                        $iplist->{$countnb}->{ENTITY} = $num->{ENTITY};
                        $iplist2->{$countnb} = $countnb;
                        $countnb++;
                        $nbip++;
                    } else {
                        if ($num->{IPSTART} ne "") {
                            $ip = Net::IP->new($num->{IPSTART}.' - '.$num->{IPEND});
                            do {
                                if ($threads_run == 0) {
                                    $iplist->{$countnb} = &share({});
                                }
                                $iplist->{$countnb}->{IP} = $ip->ip();
                                $iplist->{$countnb}->{ENTITY} = $num->{ENTITY};
                                $iplist2->{$countnb} = $countnb;
                                $countnb++;
                                $nbip++;
                                if ($nbip eq $limitip) {
                                    if ($ip->ip() ne $num->{IPEND}) {
                                        ++$ip;
                                        $num->{IPSTART} = $ip->ip();
                                        $loop_action = 1;
                                        goto CONTINUE;
                                    }
                                }
                            } while (++$ip);
                            undef $ip;
                            $num->{IPSTART} = q{}; # Empty string
                        }
                    }
                }
            }
            $loop_action = 0;

            CONTINUE:
#$self->{logger}->debug("LOOP : ".$loop_action);
            $loop_nbthreads = $params->{THREADS_DISCOVERY};


            for(my $j = 0 ; $j < $params->{THREADS_DISCOVERY} ; $j++) {
                $ThreadState->[$j] = "0";
                $ThreadAction->[$j] = "0";
            }
            #===================================
            # Create Thread management others threads
            #===================================
            $exit = 2;
#$self->{logger}->debug("exit : ".$exit);
            if ($threads_run == 0) {            
                #===================================
                # Create all Threads
                #===================================
                for(my $j = 0; $j < $params->{THREADS_DISCOVERY}; $j++) {
                    $threads_run = 1;
                    $Thread[$i][$j] = threads->create(
                        'handleIPRange',
                        $i,
                        $j,
                        $authlist,
                        $self,
                        $ThreadAction,
                        $ThreadState,
                        $iplist,
                        $iplist2,
                        $dico,
                        $maxIdx,
                        $params->{PID}
                    )->detach();

                    # sleep one second every 4 threads
                    sleep 1 unless $j % 4;
                }
                ##### Start Thread Management #####
                my $Threadmanagement = threads->create(
                    sub {
                        my ($self, $params) = @_;

                        my $count;
                        my $i;
                        my $loopthread;

                        while (1) {
                            if (($loop_action == 0) && ($exit eq "2")) {
                                ## Kill threads who do nothing partiel ##
#                              for($i = ($loop_nbthreads - 1) ; $i < $params->{THREADS_DISCOVERY} ; $i++) {
#                                 $ThreadAction{$i} = "3";
#                              }

                                ## Start + end working threads (faire fonction) ##
                                for($i = 0 ; $i < $loop_nbthreads ; $i++) {
                                    $ThreadAction->[$i] = "2";
                                    #$ThreadState->[$i] = "1";
                                }
                                ## Fonction etat des working threads (s'ils sont arretes) ##
                                $count = 0;
                                $loopthread = 0;

                                while ($loopthread != 1) {
                                    for($i = 0 ; $i < $loop_nbthreads ; $i++) {
                                        if ($ThreadState->[$i] == 2) {
                                            $count++;
                                        }
                                    }
                                    if ($count eq $loop_nbthreads) {
                                        $loopthread = 1;
                                    } else {
                                        $count = 0;
                                    }
                                    sleep 1;
                                }
                                $exit = 1;
                                return;

                            } elsif (($loop_action == 1) && ($exit eq "2")) {
                                ## Start + pause working Threads (faire fonction) ##
                                for($i = 0 ; $i < $loop_nbthreads ; $i++) {
                                    $ThreadAction->[$i] = "1";
                                    #$ThreadState->[$i] = "1";
                                }
                                sleep 1;

                                ## Fonction etat des working threads (s'il sont tous en pause) ##
                                $count = 0;
                                $loopthread = 0;

                                while ($loopthread != 1) {
                                    for($i = 0 ; $i < $loop_nbthreads ; $i++) {
                                        #print "ThreadState ".$i." = ".$ThreadState{$i}."\n";
                                        if ($ThreadState->[$i] == 0) {
                                            $count++;
                                        }
                                    }
                                    if ($count eq $loop_nbthreads) {
                                        $loopthread = 1;
                                    } else {
                                        $count = 0;
                                    }
                                    sleep 1;
                                }
                                $exit = 1;
                                $loop_action = "2";
                            }

                            sleep 1;
                        }

                        return;
                    },
                    $self
                )->detach();
                ### END Threads Creation
            }

            # Send infos to server :
            if ($sendstart == 0) {
                my $xml_thread = {
                    AGENT => {
                        START => '1',
                        AGENTVERSION => $FusionInventory::Agent::VERSION,
                    },
                    MODULEVERSION => $VERSION,
                    PROCESSNUMBER => $params->{PID}
                };
                $self->sendInformations({
                    data => $xml_thread
                });
                $sendstart = 1;
            }

            # Send NB ips to server :
            my $xml_thread = {
                AGENT => { NBIP => $nbip },
                PROCESSNUMBER => $params->{PID}
            };
            {
                lock $sendbylwp;
                $self->sendInformations({
                    data => $xml_thread
                });
            }

            while($exit != 1) {
                sleep 2;
                foreach my $idx (1 .. $maxIdx) {
                    next unless $sentxml->{$idx};

                    my $data = $storage->restore({
                        idx => $idx
                    });

                    $self->sendInformations({
                        data => $data
                    });

                    $sentxml->{$idx} = 1;

                    $storage->remove({
                        idx => $idx
                    });

                    sleep 1;
                }
            }

            foreach my $idx (1 .. $maxIdx) {
                next unless $sentxml->{$idx};

                my $data = $storage->restore({
                    idx => $idx
                });

                $self->sendInformations({
                    data => $data
                });

                $sentxml->{$idx} = 1;

                sleep 1;
            }
            $storage->removeSubDumps();

        }

        if ($params->{CORE_DISCOVERY} > 1) {
            $pm->finish;
        }
    }

    if ($params->{CORE_DISCOVERY} > 1) {
        $pm->wait_all_children;
    }

    # Send infos to server :
    my $xml_thread = {
        AGENT => { END => 1 },
        MODULEVERSION => $VERSION,
        PROCESSNUMBER => $params->{PID}
    };
    sleep 1; # Wait for threads be terminated
    $self->sendInformations({
        data => $xml_thread
    });

    return;
}


sub sendInformations {
    my ($self, $content) = @_;

    my $message = FusionInventory::Agent::XML::Query::SimpleMessage->new({
        logger => $self->{logger},
        deviceid => $self->{deviceid},
        msg    => {
            QUERY   => 'NETDISCOVERY',
            CONTENT => $content->{data},
        },
    });
    $self->{transmitter}->send({
        message => $message,
        url     => $self->{target}->getUrl()
    });
}

sub handleIPRange {
    my ($p, $t, $authlistt, $self,  $ThreadAction, $ThreadState, $iplist2, $iplist, $dico, $maxIdx, $pid) = @_;

    my $storage = $self->{target}->getStorage();
    my $loopthread = 0;
    my $loopbigthread = 0;
    my $count = 0;
    my $device_id;
    my $xml_threadt;

    $self->{logger}->debug("Core $p - Thread $t created");
    while ($loopbigthread != 1) {
        ##### WAIT ACTION #####
        $loopthread = 0;
        while ($loopthread != 1) {
    #$self->{logger}->debug("[".$t."] : waiting...");
            if ($ThreadAction->[$t] == 3) { # STOP
                $ThreadState->[$t] = "2";
                $self->{logger}->debug("Core $p - Thread $t deleted");
                return;
            } elsif ($ThreadAction->[$t] != 0) { # RUN
                $ThreadState->[$t] = "1";
                $loopthread  = 1;
            }
            sleep 1;
        }
        ##### RUN ACTION #####
    #$self->{logger}->debug("[".$t."] : run...");
        $loopthread = 0;
        while ($loopthread != 1) {
            $device_id = q{}; # Empty string
            {
                lock $iplist2;
                if (keys %{$iplist2} != 0) {
                    my @keys = sort keys %{$iplist2};
                    $device_id = pop @keys;
                    delete $iplist2->{$device_id};
                } else {
                    $loopthread = 1;
                }
            }
            if ($loopthread != 1) {
                my $datadevice = $self->discoveryIpThreaded({
                        ip                  => $iplist->{$device_id}->{IP},
                        entity              => $iplist->{$device_id}->{ENTITY},
                        authlist            => $authlistt,
                        dico                => $dico
                    });
                undef $iplist->{$device_id}->{IP};
                undef $iplist->{$device_id}->{ENTITY};

                if (keys %{$datadevice}) {
                    $xml_threadt->{DEVICE}->[$count] = $datadevice;
                    $xml_threadt->{MODULEVERSION} = $VERSION;
                    $xml_threadt->{PROCESSNUMBER} = $pid;
                    $count++;
                }
            }
            if (($count == 4) || (($loopthread eq "1") && ($count > 0))) {
                $maxIdx++;
                $storage->save({
                    idx => $maxIdx,
                    data => $xml_threadt
                });

                $count = 0;
            }
        }
        ##### CHANGE STATE #####
        if ($ThreadAction->{$t} == 2) { # STOP
            $ThreadState->[$t] = 2;
            $ThreadAction->[$t] = 0;
    #$self->{logger}->debug("[".$t."] : stoping...");
            $self->{logger}->debug("Core $p - Thread $t deleted");
            return;
        } elsif ($ThreadAction->[$t] == 1) { # PAUSE
            $ThreadState->[$t] = 0;
            $ThreadAction->[$t] = 0;
        }
    }
}

sub discoveryIpThreaded {
    my ($self, $params) = @_;

    if (!defined($params->{ip})) {
        $self->{logger}->debug("ip address empty...");
        return;
    }
    if ($params->{ip} !~ /^$ip_address_pattern$/ ) {
        $self->{logger}->debug("Invalid ip address...");
        return;
    }

    my $device;

    # NMAP discovery
    if ($INC{'Nmap/Parser.pm'}) {
        _discoverByNmapParser($params->{ip}, $device);
    } elsif ($INC{'Nmap/Scanner.pm'}) {
        _discoverByNmapScanner($params->{ip}, $device);
    }

    # Netbios discovery
    if ($INC{'Net/NBName.pm'}) {
        _discoverByNetbios($params->{ip}, $device);
    }

    # SNMP discovery
    if ($INC{'Net/SNMP.pm'}) {
        _discoverBySNMP(
            $params->{ip}, $device,
            $params->{authlist}, $params->{dico},
            $self->{logger}
        );
    }

    if (exists $device->{MAC}) {
        $device->{MAC} =~ tr/A-F/a-f/;
    }
    if (
        exists $device->{MAC} ||
        exists $device->{DNSHOSTNAME} || 
        exists $device->{NETBIOSNAME}
    ) {
        $device->{IP} = $params->{ip};
        $device->{ENTITY} = $params->{entity};
        $self->{logger}->debug("[$params->{ip}] ".Dumper($device));
    } else {
        $self->{logger}->debug("[$params->{ip}] Not found !");
    }
    return $device;
}

sub _discoverByNmapParser {
    my ($ip, $device) = @_;

    my $scan = Nmap::Parser->new();
    eval {
        $scan->parsescan(
            'nmap',
            '-sP --system-dns --max-retries 1 --max-rtt-timeout 1000 ',
            $ip
        );
        my $host = $scan->{HOSTS}->{$ip};
        $device->{DNSHOSTNAME} = getSanitizedString($host->{hostnames}->[0])
            if $host->{hostnames}->[0];
        $device->{MAC} = getSanitizedString($host->{addrs}->{mac}->{addr})
            if $host->{addrs}->{mac}->{addr};
        $device->{NETPORTVENDOR} = getSanitizedString(
            $host->{addrs}->{mac}->{vendor}
        ) if $host->{addrs}->{mac}->{vendor};
    };
}

sub _discoverByNmapScanner {
    my ($ip, $device) = @_;

    my $scan = Nmap::Scanner->new();
    my $result = $scan->scan(
        "-sP --system-dns --max-retries 1 --max-rtt-timeout 1000 $ip"
    );

    my $host = $result->get_host_list()->get_next();
    return unless $host;

    foreach my $address ($host->addresses()) {
        if ($address->addrtype() eq 'mac') {
            $device->{MAC} = getSanitizedString($address->addr());
        }
        if ($address->vendor()) {
            $device->{NETPORTVENDOR} = getSanitizedString($address->vendor());
        }
    }

    foreach my $hostname ($host->hostnames()) {
        if ($hostname->name()) {
            $device->{DNSHOSTNAME} = getSanitizedString($hostname->name());
        }
    }
}

sub _discoverByNetBios {
    my ($ip, $device) = @_;

    my $nb = Net::NBName->new();

    my $ns = $nb->node_status($ip);
    if ($ns) {
        foreach my $rr ($ns->names()) {
            if ($rr->suffix() == 0 && $rr->G() eq "GROUP") {
                $device->{WORKGROUP} = getSanitizedString($rr->name());
            }
            if ($rr->suffix() == 3 && $rr->G() eq "UNIQUE") {
                $device->{USERSESSION} = getSanitizedString($rr->name());
            }
            if ($rr->suffix() == 0 && $rr->G() eq "UNIQUE") {
                my $machine = $rr->name();
                $device->{NETBIOSNAME} = getSanitizedString($machine)
                    unless $machine =~ /^IS~/;
            }
        }
        if (
            ! exists $device->{MAC} ||
            $device->{MAC} !~ /^$mac_address_pattern$/
        ) {
            my $NetbiosMac = $ns->mac_address();
            $NetbiosMac =~ tr/-/:/;
            $device->{MAC} = $NetbiosMac;
        }
    }
}

sub _discoverBySNMP {
    my ($ip, $device, $authlist, $dico, $logger) = @_;

    foreach my $key (keys %{$authlist}) {
        my $auth = $authlist->{$key};
        my $session;
        eval {
            $session = FusionInventory::Agent::SNMP->new({
                hostname     => $ip,
                version      => $auth->{VERSION},
                community    => $auth->{COMMUNITY},
                username     => $auth->{USERNAME},
                authpassword => $auth->{AUTHPASSPHRASE},
                authprotocol => $auth->{AUTHPROTOCOL},
                privpassword => $auth->{PRIVPASSPHRASE},
                privprotocol => $auth->{PRIVPROTOCOL},
                translate    => 1,
            });
        };
        if ($EVAL_ERROR) {
            $logger->error(
                "Unable to create SNMP session for $ip: $EVAL_ERROR"
            );
            return;
        }

        # description
        my $description = $session->snmpGet({
            oid => '1.3.6.1.2.1.1.1.0',
            up  => 1,
        });

        if (!$description) {
            $session->close();
            return;
        }

        foreach my $entry (@dispatch_table) {
            if (ref $entry->{match} eq 'Regexp') {
                next unless $description =~ $entry->{match};
            } else {
                next unless $description eq $entry->{match};
            }

            $entry->{module}->require();
            if ($EVAL_ERROR) {
                $logger->debug ("Failed to load $entry->{module}: $EVAL_ERROR");
                last;
            }

            no strict 'refs'; ## no critic
            $description = &{$entry->{module} . '::' . $entry->{function}}(
                $session
            );

            last;
        }

        $device->{DESCRIPTION} = $description;

        # name
        my $name = $session->snmpGet({
            oid => '.1.3.6.1.2.1.1.5.0',
            up  => 1,
        });
        $device->{SNMPHOSTNAME} = $name;

        # other parameters
        my ($serial, $type, $model, $mac) = verifySerial(
            $description, $session, $dico
        );
        if ($serial eq "Received noSuchName(2) error-status at error-index 1") {
            $serial = '';
        } else {
            $serial =~ s/^\s+//;
            $serial =~ s/\s+$//;
            $serial =~ s/(\.{2,})*//g;
        }
        $device->{SERIAL} = $serial;
        $device->{MODELSNMP} = $model;
        $device->{AUTHSNMP} = $key;
        $device->{TYPE} = $type;
        $device->{IP} = $ip;
        if (exists($device->{MAC})) {
            if ($device->{MAC} !~ /^$mac_address_pattern$/) {
                $device->{MAC} = $mac;
            }
        } else {
            $device->{MAC} = $mac;
        }

        $session->close();
    }
}

sub verifySerial {
    my ($description, $session, $dico) = @_;

    $description =~ s/\n//g;
    $description =~ s/\r//g;

    my ($serial, $type, $model, $mac);

    # iterate the dictionnary until a model matches current description
    foreach my $device (@{$dico->{DEVICE}}) {
        next unless $device->{SYSDESCR} eq $description;

        if (exists $device->{SERIAL}) {
            $serial = $session->snmpGet({
                oid => $device->{SERIAL},
                up  => 1,
            });

            if ($serial) {
                $serial =~ s/\n//g;
                $serial =~ s/\r//g;
            }
        }

        $type  = $device->{TYPE};

        $model = $device->{MODELSNMP};
        
        if (exists $device->{MAC}) {
            $mac  = $session->snmpGet({
                oid => $device->{MAC},
                up  => 0,
            });
        }

        if (exists $device->{MACDYN}) {
            my $macadresses = $session->snmpWalk({
                oid_start => $device->{MACDYN}
            });

            foreach my $macadress (values %{$macadresses}) {
                next unless $macadress;
                next if $macadress eq '0:0:0:0:0:0';
                next if $macadress eq '00:00:00:00:00:00';
                if ($mac !~ /^$mac_address_pattern$/) {
                    $mac = $macadress;
                }
            }
        }

        # Mac of switchs
        if ($mac !~ /^$mac_address_pattern$/) {
            $mac = $session->snmpGet({
                oid => ".1.3.6.1.2.1.17.1.1.0",
                up  => 0,
            });
        }

        if ($mac !~ /^$mac_address_pattern$/) {
            my $macadresses = $session->snmpWalk({
                oid_start => ".1.3.6.1.2.1.2.2.1.6"
            });
            foreach my $macadress (values %{$macadresses}) {
                next unless $macadress;
                next if $macadress eq '0:0:0:0:0:0';
                next if $macadress eq '00:00:00:00:00:00';
                if ($mac !~ /^$mac_address_pattern$/) {
                    $mac = $macadress;
                }
            }
        }

        last;
    }

    return ($serial, $type, $model, $mac);
}

1;

__END__

=head1 NAME

FusionInventory::Agent::Task::NetDiscovery - Network discovery task for FusionInventory Agent

=head1 DESCRIPTION

This module scans your networks to detect unknown devices with various
methods (SNMP, NetBios, Netmap).

The plugin depends on FusionInventory for GLPI.

=head1 AUTHORS

The maintainer is David DURIEUX <d.durieux@siprossii.com>

Please read the AUTHORS, Changes and THANKS files to see who is behind
FusionInventory.

=head1 SEE ALSO

=over 4

=item *
FusionInventory website: L<http://www.FusionInventory.org/>

=item *
the Mailing lists and IRC

=back

=head1 BUGS

Please, use the mailing lists as much as possible. You can open your own bug
tickets. Patches are welcome.

=head1 COPYRIGHT

=over 4

=item *

Copyright (C) 2009 David Durieux

=item *

=back

Copyright (C) 2010 FusionInventory Team

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

=cut
