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
use XML::Simple;

use FusionInventory::Agent::Storage;
use FusionInventory::Agent::Task::NetDiscovery::Dico;
use FusionInventory::Agent::Task::NetDiscovery::Manufacturer::HewlettPackard;
use FusionInventory::Agent::XML::Query::SimpleMessage;

our $VERSION = '1.2';

$ENV{XML_SIMPLE_PREFERRED_PARSER} = 'XML::SAX::PurePerl';

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

    my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
    $hour  = sprintf("%02d", $hour);
    $min  = sprintf("%02d", $min);
    $yday = sprintf("%04d", $yday);
    $self->{PID} = $yday.$hour.$min;

    $self->{countxml} = 0;

    $self->initModList();

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

    my $ModuleNmapParser = Nmap::Parser->require();
    my $ModuleNmapScanner = Nmap::Scanner->require();
    if (!$ModuleNmapParser && !$ModuleNmapScanner) {
        $self->{logger}->debug(
            "Can't load Nmap::Parser && map::Scanner. Nmap can't be used!"
        );
    }

    my $ModuleNetNBName = Net::NBName->require();
    if (!$ModuleNetNBName) {
        $self->{logger}->debug(
            "Can't load Net::NBName. Netbios detection can't be used!"
        );
    }

    my $ModuleNetSNMP = FusionInventory::Agent::SNMP->require();
    if (!$ModuleNetSNMP) {
        $self->{logger}->debug(
            "Can't load FusionInventory::Agent::SNMP. SNMP detection can't be used!"
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

    my @Thread;
    for (my $p = 0; $p < $params->{CORE_DISCOVERY}; $p++) {
        if ($params->{CORE_DISCOVERY} > 1) {
            my $pid = $pm->start and next;
        }

        my $threads_run = 0;
        my $loop_action : shared = 1;
        my $exit : shared = 0;

        my %ThreadState : shared;
        my %ThreadAction : shared;
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

#         if ($nbip > ($nb_ip_per_thread * 4)) {
#            
#         } elsif ($nbip > $nb_ip_per_thread) {
#            $params->{THREADS_DISCOVERY} = int($nbip / $nb_ip_per_thread) + 4;
#         } else {
#            $params->{THREADS_DISCOVERY} = $nbip;
#         }

            CONTINUE:
#$self->{logger}->debug("LOOP : ".$loop_action);
            $loop_nbthreads = $params->{THREADS_DISCOVERY};


            for(my $j = 0 ; $j < $params->{THREADS_DISCOVERY} ; $j++) {
                $ThreadState{$j} = "0";
                $ThreadAction{$j} = "0";
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
                my $k = 0;
                for(my $j = 0; $j < $params->{THREADS_DISCOVERY}; $j++) {
                    $threads_run = 1;
                    $k++;
                    $Thread[$p][$j] = threads->create(
                        'handleIPRange',
                        $p,
                        $j,
                        $authlist,
                        $self,
                        \%ThreadAction,
                        \%ThreadState,
                        $iplist,
                        $iplist2,
                        $ModuleNmapParser,
                        $ModuleNmapScanner,
                        $ModuleNetNBName,
                        $ModuleNetSNMP,
                        $dico,
                        $maxIdx,
                        $params->{PID}
                    )->detach();

                    if ($k == 4) {
                        sleep 1;
                        $k = 0;
                    }
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
                                    $ThreadAction{$i} = "2";
                                    #$ThreadState{$i} = "1";
                                }
                                ## Fonction etat des working threads (s'ils sont arretes) ##
                                $count = 0;
                                $loopthread = 0;

                                while ($loopthread != 1) {
                                    for($i = 0 ; $i < $loop_nbthreads ; $i++) {
                                        if ($ThreadState{$i} == 2) {
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
                                    $ThreadAction{$i} = "1";
                                    #$ThreadState{$i} = "1";
                                }
                                sleep 1;

                                ## Fonction etat des working threads (s'il sont tous en pause) ##
                                $count = 0;
                                $loopthread = 0;

                                while ($loopthread != 1) {
                                    for($i = 0 ; $i < $loop_nbthreads ; $i++) {
                                        #print "ThreadState ".$i." = ".$ThreadState{$i}."\n";
                                        if ($ThreadState{$i} == 0) {
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
    my ($p, $t, $authlistt, $self,  $ThreadAction, $ThreadState, $iplist2, $iplist, $ModuleNmapScanner, $ModuleNmapParser, $ModuleNetNBName, $ModuleNetSNMP, $dico, $maxIdx, $pid) = @_;

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
            if ($ThreadAction->{$t} == 3) { # STOP
                $ThreadState->{$t} = "2";
                $self->{logger}->debug("Core $p - Thread $t deleted");
                return;
            } elsif ($ThreadAction->{$t} != 0) { # RUN
                $ThreadState->{$t} = "1";
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
                        ModuleNmapScanner   => $ModuleNmapScanner,
                        ModuleNetNBName     => $ModuleNetNBName,
                        ModuleNmapParser    => $ModuleNmapParser,
                        ModuleNetSNMP       => $ModuleNetSNMP,
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
            $ThreadState->{$t} = 2;
            $ThreadAction->{$t} = 0;
    #$self->{logger}->debug("[".$t."] : stoping...");
            $self->{logger}->debug("Core $p - Thread $t deleted");
            return;
        } elsif ($ThreadAction->{$t} == 1) { # PAUSE
            $ThreadState->{$t} = 0;
            $ThreadAction->{$t} = 0;
        }
    }
}

sub discoveryIpThreaded {
    my ($self, $params) = @_;

    my $datadevice = {};

    if (!defined($params->{ip})) {
        $self->{logger}->debug("ip address empty...");
        return $datadevice;
    }
    if ($params->{ip} !~ m/^(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)\.(\d\d?\d?)/ ) {
        $self->{logger}->debug("Invalid ip address...");
        return $datadevice;
    }

    #** Nmap discovery
    if ($params->{ModuleNmapParser} == 1) {
        my $scan = Nmap::Parser->new();
        if (eval {$scan->parsescan('nmap','-sP --system-dns --max-retries 1 --max-rtt-timeout 1000 ', $params->{ip})}) {
            if (exists($scan->{HOSTS}->{$params->{ip}}->{addrs}->{mac}->{addr})) {
                $datadevice->{MAC} = specialChar($scan->{HOSTS}->{$params->{ip}}->{addrs}->{mac}->{addr});
            }
            if (exists($scan->{HOSTS}->{$params->{ip}}->{addrs}->{mac}->{vendor})) {
                $datadevice->{NETPORTVENDOR} = specialChar($scan->{HOSTS}->{$params->{ip}}->{addrs}->{mac}->{vendor});
            }

            if (exists($scan->{HOSTS}->{$params->{ip}}->{hostnames}->[0])) {
                $datadevice->{DNSHOSTNAME} = specialChar($scan->{HOSTS}->{$params->{ip}}->{hostnames}->[0]);
            }
        }
    } elsif ($params->{ModuleNmapScanner} == 1) {
        my $scan = Nmap::Scanner->new();
        my $results_nmap = $scan->scan('-sP --system-dns --max-retries 1 --max-rtt-timeout 1000 '.$params->{ip});

        my $xml_nmap = XML::Simple->new();
        my $macaddress = q{}; # Empty string
        my $hostname = q{}; # Empty string
        my $netportvendor = q{}; # Empty string

        foreach my $key (keys (%{$$results_nmap{'ALLHOSTS'}})) {
            for (my $n=0; $n<@{$$results_nmap{'ALLHOSTS'}{$key}{'addresses'}}; $n++) {
                if ($$results_nmap{'ALLHOSTS'}{$key}{'addresses'}[$n]{'addrtype'} eq "mac") {
                    $datadevice->{MAC} = specialChar($$results_nmap{'ALLHOSTS'}{$key}{'addresses'}[$n]{'addr'});
                    if (defined($$results_nmap{'ALLHOSTS'}{$key}{'addresses'}[$n]{'vendor'})) {
                        $datadevice->{NETPORTVENDOR} = specialChar($$results_nmap{'ALLHOSTS'}{$key}{'addresses'}[$n]{'vendor'});
                    }
                }
            }
            if (exists($$results_nmap{'ALLHOSTS'}{$key}{'hostnames'}[0])) {
                for (my $n=0; $n<@{$$results_nmap{'ALLHOSTS'}{$key}{'hostnames'}}; $n++) {
                    $datadevice->{DNSHOSTNAME} = specialChar($$results_nmap{'ALLHOSTS'}{$key}{'hostnames'}[$n]{'name'});
                }
            }
        }
    }

    #** Netbios discovery
    if ($params->{ModuleNetNBName} == 1) {
        my $nb = Net::NBName->new();

        my $domain = q{}; # Empty string
        my $user = q{}; # Empty string
        my $machine = q{}; # Empty string
        my $type = 0;

        my $ns = $nb->node_status($params->{ip});
        if ($ns) {
            for my $rr ($ns->names) {
                if ($rr->suffix == 0 && $rr->G eq "GROUP") {
                    $datadevice->{WORKGROUP} = specialChar($rr->name);
                }
                if ($rr->suffix == 3 && $rr->G eq "UNIQUE") {
                    $datadevice->{USERSESSION} = specialChar($rr->name);
                }
                if ($rr->suffix == 0 && $rr->G eq "UNIQUE") {
                    $machine = $rr->name unless $rr->name =~ /^IS~/;
                    $datadevice->{NETBIOSNAME} = specialChar($machine);
                    $type = 1;
                }
            }
            if (not exists($datadevice->{MAC})) {
                my $NetbiosMac = $ns->mac_address;
                $NetbiosMac =~ tr/-/:/;
                $datadevice->{MAC} = $NetbiosMac;
            } elsif ($datadevice->{MAC} !~ /^([0-9a-f]{2}([:]|$)){6}$/i) {
                my $NetbiosMac = $ns->mac_address;
                $NetbiosMac =~ tr/-/:/;
                $datadevice->{MAC} = $NetbiosMac;
            }
        }
    }


    if ($params->{ModuleNetSNMP} == 1) {
        my $i = "4";
        my $snmpv;
        while ($i != 1) {
            $i--;
            $snmpv = $i;
            if ($i == 2) {
                $snmpv = "2c";
            }
            for my $key ( keys %{$params->{authlist}} ) {
                if ($params->{authlist}->{$key}->{VERSION} eq $snmpv) {
                    my $session;
                    eval {
                        $session = FusionInventory::Agent::SNMP->new({
                            version      => $params->{authlist}->{$key}->{VERSION},
                            hostname     => $params->{ip},
                            community    => $params->{authlist}->{$key}->{COMMUNITY},
                            username     => $params->{authlist}->{$key}->{USERNAME},
                            authpassword => $params->{authlist}->{$key}->{AUTHPASSPHRASE},
                            authprotocol => $params->{authlist}->{$key}->{AUTHPROTOCOL},
                            privpassword => $params->{authlist}->{$key}->{PRIVPASSPHRASE},
                            privprotocol => $params->{authlist}->{$key}->{PRIVPROTOCOL},
                            translate    => 1,
                        });
                    };
                    if ($EVAL_ERROR) {
                        $self->{logger}->error(
                            "Unable to create SNMP session for " .
                            "$params->{device}->{IP}: $EVAL_ERROR"
                        );
                    } else {

                        #print "[".$params->{ip}."] GNE () \n";
                        my $description = $session->snmpGet({
                            oid => '1.3.6.1.2.1.1.1.0',
                            up  => 1,
                        });
                        if ($description =~ m/No response from remote host/) {
                            #print "[".$params->{ip}."][NO][".$authlist->{$key}->{VERSION}."][".$authlist->{$key}->{COMMUNITY}."]\n";
                            #$session->close;
                        } elsif ($description =~ m/No buffer space available/) {
                            #print "[".$params->{ip}."][NO][".$authlist->{$key}->{VERSION}."][".$authlist->{$key}->{COMMUNITY}."]\n";
                            #$session->close;
                        } elsif ($description ne "null") {
                            #print "[".$params->{ip}."][YES][".$authlist->{$key}->{VERSION}."][".$authlist->{$key}->{COMMUNITY}."]\n";

                            # ***** manufacturer specifications
                            for my $m ( keys %{$self->{modules}} ) {
                                $description = $m->discovery($description, $session,$description);
                            }

                            $datadevice->{DESCRIPTION} = $description;

                            my $name = $session->snmpGet({
                                oid => '.1.3.6.1.2.1.1.5.0',
                                up  => 1,
                            });
                            if ($name eq "null") {
                                $name = q{}; # Empty string
                            }
                            # Serial Number
                            my ($serial, $type, $model, $mac) = verifySerial($description, $session, $params->{dico});
                            if ($serial eq "Received noSuchName(2) error-status at error-index 1") {
                                $serial = q{}; # Empty string
                            }
                            if ($serial eq "noSuchInstance") {
                                $serial = q{}; # Empty string
                            }
                            if ($serial eq "noSuchObject") {
                                $serial = q{}; # Empty string
                            }
                            if ($serial eq "No response from remote host") {
                                $serial = q{}; # Empty string
                            }
                            $serial =~ s/^\s+//;
                            $serial =~ s/\s+$//;
                            $serial =~ s/(\.{2,})*//g;
                            $datadevice->{SERIAL} = $serial;
                            $datadevice->{MODELSNMP} = $model;
                            $datadevice->{AUTHSNMP} = $key;
                            $datadevice->{TYPE} = $type;
                            $datadevice->{SNMPHOSTNAME} = $name;
                            $datadevice->{IP} = $params->{ip};
                            if (exists($datadevice->{MAC})) {
                                if ($datadevice->{MAC} !~ /^([0-9a-f]{2}([:]|$)){6}$/i) {
                                    $datadevice->{MAC} = $mac;
                                }
                            } else {
                                $datadevice->{MAC} = $mac;
                            }
                            $datadevice->{ENTITY} = $params->{entity};
                            $self->{logger}->debug("[$params->{ip}] ".Dumper($datadevice));
                            #$session->close;
                            return $datadevice;
                        } else {
                            #debug($log,"[".$params->{ip}."][NO][".$$authSNMP_discovery{$key}{'version'}."][".$$authSNMP_discovery{$key}{'community'}."] ".$session->error, "",$PID,$Bin);
                            $session->close;
                        }
                    }
                }
            }
        }
    }

    if (exists($datadevice->{MAC})) {
        $datadevice->{MAC} =~ tr/A-F/a-f/;
    }
    if ((exists($datadevice->{MAC})) || (exists($datadevice->{DNSHOSTNAME})) || (exists($datadevice->{NETBIOSNAME}))) {
        $datadevice->{IP} = $params->{ip};
        $datadevice->{ENTITY} = $params->{entity};
        $self->{logger}->debug("[$params->{ip}] ".Dumper($datadevice));
    } else {
        $self->{logger}->debug("[$params->{ip}] Not found !");
    }
    return $datadevice;
}



sub specialChar {
    my $variable = shift;
    if (defined($variable)) {
        if ($variable =~ /0x$/) {
            return "";
        }
        $variable =~ s/([\x80-\xFF])//;
        return $variable;
    } else {
        return "";
    }
}



sub verifySerial {
    my $description = shift;
    my $session     = shift;
    my $dico    = shift;

    my $oid;
    my $macreturn = q{}; # Empty string
    my $modelreturn = q{}; # Empty string
    my $serial;
    my $serialreturn = q{}; # Empty string

    $description =~ s/\n//g;
    $description =~ s/\r//g;

    foreach my $num (@{$dico->{DEVICE}}) {
        if ($num->{SYSDESCR} eq $description) {

            if (defined($num->{SERIAL})) {
                $oid = $num->{SERIAL};
                $serial = $session->snmpGet({
                    oid => $oid,
                    up  => 1,
                });
            }

            if (defined($serial)) {
                $serial =~ s/\n//g;
                $serial =~ s/\r//g;
                $serialreturn = $serial;
            }
            my $typereturn  = $num->{TYPE};
            if (defined($num->{MODELSNMP})) {
                $modelreturn = $num->{MODELSNMP};
            }
            if (defined($num->{MAC})) {
                $oid = $num->{MAC};
                $macreturn  = $session->snmpGet({
                    oid => $oid,
                    up  => 0,
                });

            }

            $oid = $num->{MACDYN};
            my $Arraymacreturn = {};
            $Arraymacreturn  = $session->snmpWalk({
                    oid_start => $oid
                });
            while ( (undef,my $macadress) = each (%{$Arraymacreturn}) ) {
                if (($macadress ne '') && ($macadress ne '0:0:0:0:0:0') && ($macadress ne '00:00:00:00:00:00')) {
                    if ($macreturn !~ /^([0-9a-f]{2}([:]|$)){6}$/i) {
                        $macreturn = $macadress;
                    }
                }
            }

            # Mac of switchs
            if ($macreturn !~ /^([0-9a-f]{2}([:]|$)){6}$/i) {
                $oid = ".1.3.6.1.2.1.17.1.1.0";
                $macreturn  = $session->snmpGet({
                        oid => $oid,
                        up  => 0,
                    });
            }
            if ($macreturn !~ /^([0-9a-f]{2}([:]|$)){6}$/i) {
                $oid = ".1.3.6.1.2.1.2.2.1.6";
                my $Arraymacreturn = {};
                $Arraymacreturn  = $session->snmpWalk({
                        oid_start => $oid
                    });
                while ( (undef,my $macadress) = each (%{$Arraymacreturn}) ) {
                    if (($macadress ne '') && ($macadress ne '0:0:0:0:0:0') && ($macadress ne '00:00:00:00:00:00')) {
                        if ($macreturn !~ /^([0-9a-f]{2}([:]|$)){6}$/i) {
                            $macreturn = $macadress;
                        }
                    }
                }
            }

            return ($serialreturn, $typereturn, $modelreturn, $macreturn);
        }
    }

    # Mac of switchs
    if ($macreturn !~ /^([0-9a-f]{2}([:]|$)){6}$/i) {
        $oid = ".1.3.6.1.2.1.17.1.1.0";
        $macreturn  = $session->snmpGet({
            oid => $oid,
            up  => 0,
        });
    }
    if ($macreturn !~ /^([0-9a-f]{2}([:]|$)){6}$/i) {
        $oid = ".1.3.6.1.2.1.2.2.1.6";
        my $Arraymacreturn = {};
        $Arraymacreturn  = $session->snmpWalk({
            oid_start => $oid
        });
        while ( (undef,my $macadress) = each (%{$Arraymacreturn}) ) {
            if (($macadress ne '') && ($macadress ne '0:0:0:0:0:0') && ($macadress ne '00:00:00:00:00:00')) {
                if ($macreturn !~ /^([0-9a-f]{2}([:]|$)){6}$/i) {
                    $macreturn = $macadress;
                }
            }
        }
    }

    return ("", 0, "", "");
}

sub initModList {
    my $self = shift;

    my $logger = $self->{logger};
    my $config = $self->{config};

    my @dirToScan;
    my @installed_mods;
    my @installed_files;

    if ($config->{devlib}) {
        # devlib enable, I only search for backend module in ./lib
        push (@dirToScan, './lib');
    } else {
        foreach (@INC) {
            next if ! -d || (-l && -d readlink) || /^(\.|lib)$/;
            next if ! -d $_.'/FusionInventory/Agent/Task/NetDiscovery/Manufacturer';
            push @dirToScan, $_;
        }
    }
    if (@dirToScan) {
        # here I need to use $d to avoid a bug with AIX 5.2's perl 5.8.0. It
        # changes the @INC content if i use $_ directly
        # thanks to @rgs on irc.perl.org
        File::Find::find(
            {
                wanted => sub {
                    push @installed_files, $File::Find::name if $File::Find::name =~
                    /FusionInventory\/Agent\/Task\/NetDiscovery\/Manufacturer\/.*\.pm$/;
                },
                follow => 1,
                follow_skip => 2
            }
            , @dirToScan
        );
    }
    foreach my $file (@installed_files) {
        my $t = $file;
        next unless $t =~ s!.*?(FusionInventory/Agent/Task/NetDiscovery/Manufacturer/)(.*?)\.pm$!$1$2!;
        my $m = join ('::', split /\//, $t);
        $m->require();
        if ($EVAL_ERROR) {
            $logger->debug ("Failed to load $m: $EVAL_ERROR");
            next;
        } else {
            $logger->debug ($m." loaded");
            $self->{modules}->{$m} = 1;
        }
    }
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
