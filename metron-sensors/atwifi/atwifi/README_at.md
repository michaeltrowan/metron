
This is a merge of the Metron pycapa and the AT wifi agent

We disconnected the at agent stuff from the normal infratstucture --
there is a general simple parent calss in atsensor.py that replaces
the pieces we need out of the Tutella AtDevice class (mostly just an
init and cget that pulls from environment/yml config -- I didn't feel
like connecting to the metron zookeeper/etc for now, but ...

The cli is the same as the pycapa but the consumer and producer are
using our AtWifi class -- on the producer we stand it up, scan for
devices and then start it (so it should start scanning every 5 minutes)

The update state function in the AtWifi now just keeps a queue of states,
and in the producer here, we call in to pull the most recently produced
packet (and it sleeps a minute at a time until there is one)

It then bascially posts this to the kafka queue (much like the
pycapa was publishing network scan packets)

If you use the --simulation option, it will try to connect to the Azure
device scan db and pull packets from there instead of doing an actual
scan.  The db credentials are in the config.yml file, the db code itself
is in simulation.py and the pseudo class for simulated work is in
atwifisimulator.py

