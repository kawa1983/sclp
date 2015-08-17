## SCLP module


### Overview

SCLP (Segment-oriented Connection-less Protocol) is a novel L4 protocol 
for accelerating performance of existing tunneling protocols, such as 
VXLAN and NVGRE. The SCLP protocol is designed to take advantage of 
a GSO (Generic Segmentation Offload) and a GRO (Generic Receive Offload) 
features of the Linux kernel. Unlike an sclp_offload module that we have 
released so far, this module provides full-implementation of the SCLP 
protocol including Tx/Rx features, GRO/GRO support, tunneling interface 
for Open vSwitch. Therefore, the sclp_offload module is not needed anymore.


=
### Contents

* proto.c:		Module's main functions

* ipv4.c:		IPv4-dependent functions

* output.c:		Packet transmission

* tunnel.c:		Tunnel related functions (called by OVS)

* offload.c:		GSO/GRO implementations

* sock_util.c:		Utility functions for SCLP sockets

* frag_table.h: 	Fragment table definition for Rx

* frag_table.c:		Fragment table implementation for Rx

* sclp_impl.h: 		Common function definition

* compat/: 		Exported structure and function definition

* examples/: 		Echo and nc like applications using SCLP


=
### Supported distributions

Currently, the SCLP module has been tested on the following distributions.

 * Redhat Enterprise Linux 6.6, 6.7


=
### Install

### 1. Getting the source code of the SCLP offload module

You can download the code from the GitHub repository.

    https://github.com/sdnnit/sclp


### 2. Bulding the SCLP offload module

To build the module, you can simply use the rpmbuild system

```sh
$ tar cvzf sclp.tar.gz sclp

$ mv sclp.tar.gz ~/rpmbuild/SOURCES

$ cd sclp

$ rpmbuild -bb rhel/sclp-rhel6.spec
```

If the building process succeeds, 'sclp-0.1.0-1.x86_64.rpm' file is created in ~/rpmbuild/RPMS/x86_64.


### 3. Installing the SCLP module

```sh
# rpm -ivh sclp-0.1.0-1.x86_64.rpm
```

- Note: The sclp module is automatically loaded by loading an SCLP-enabled openvswitch module. 
The SCLP-enabled openvswitch module can be downloaded from the following link.

	https://github.com/sdnnit/ovs-sclp


=
### Papers

Overview of the SCLP protocol is described in the following paper.

* R. Kawashima and H. Matsuo, "Accelerating the Performance of Software 
Tunneling using a Receive Offload-aware Novel L4 Protocol", IEICE 
Transactions on Communications, vol.E98-B, no.11, 2015 (to appear).

* R. Kawashima, S. Muramatsu, H. Nakayama, T. Hayashi, and H. Matsuo, 
"SCLP: Segment-oriented Connection-less Protocol for High-Performance 
Software Tunneling in Datacenter Networks", Proc. 1st IEEE Conference on 
Network Softwarization (NetSoft 2015), pp.1-8, London, UK, April 2015.


=
### Contact 

Ryota Kawashima &lt;kawa1983<span>@</span>ieee.org&gt;

