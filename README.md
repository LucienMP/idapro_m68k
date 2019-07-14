idapro_m68k
=======

Extension of the existing IDA processor module for the Motorola 68000 processor family

Several versions of the programmers reference manual can be found online, below is the main source used in this module:
 * [MOTOROLA M68000 FAMILY Programmer’s Reference Manual, 1992](https://www.nxp.com/files/archives/doc/ref_manual/M68000PRM.pdf)

Python was chosen because it doesnt need the SDK, compiler, or other overhead and is simpler to work with initially for beginners.
However performance maybe worse than C, some functionality maybe impossible or difficult, and the API varies from that of the standard C api a little and can lead to confusion.
 
This is a sample plugin for extending gdb support for step-over for the M68K,
and to enable type information support so you can press "y" on functions and 
have the parameters propagate inside and back out of the funciton.

When you install a hook in the HT_IDP category, it will be called
before the processor module's notify() function, so if you return
non-zero, your results will be used.

Steps used to implement these features are:
1) Add GDB style XML files for the CPU register descriptions to $IDA_HOME/cfg/
2) Add to the section in $IDA_HOME/cfg/dbg_gdb.cfg that integrates that XML for GDB
    CONFIGURATIONS = { "M68K" : ...
    IDA_FEATURES = { "m68k" : ... 
    NOT NEEDED> ARCH_MAP = { "m68k" : ... 
    NOT NEEDED> FEATURE_MAP = ...
3) Add function to handle step-over understanding around branches
    The ev_calc_step_over interprets the current instruction.
    If it is a JSR/BSR routine call then it will advance the IP to the next instruction.
    In all other cases it will advance to the next insturction by passing back BADADDR
4) Add function to handle type info (funciton name, and paramater propagation)
    To enable type support you must set PR_TYPEINFO in ph.flag and 
    implement most of the related callbacks (see "START OF TYPEINFO 
    CALLBACKS" in idp.hpp from the IDA SDK).

Many thanks to Ilfak Guilfanov @ Hey-Rays for all his help.

Usage
-------
Copy the various files into the IDA installation.
Create a m68k based deubg db, and set the gdb remote connection.     

Known Issues
-------

* XML varies from GDB core as it needs SR flags

* GDB handling in 7.1 had some issues, recommend 7.3 or later
  * crash if GDB port disconnects (fixed) and you step/run
  * thinks its connected to a GDB server if the port is blocked/not open (fixed by error message)
  * keeps jumping back to PC if you make edits elsewhere in database (fixed)
  * mishandling of types in 64bit version resulting in crash (fixed)

* Bugs in gdb handling in QEMU versions 3.x, recommend 4.1
  * SR should combine SR and CCR, ( https://patchew.org/QEMU/20190609105154.GA16755@localhost.localdomain/ )
  * step operation regression, ( https://patchew.org/QEMU/20190526075056.33865-1-lucienmp_antispam@yahoo.com/ )
  * vCont format regression. ( https://patchew.org/QEMU/20190325110452.6756-1-luc.michel@greensocs.com/ )
  * Exception entry steps twice

    
Authoring information
=======

Lucien Murray-Pitts (lucienmp_antispam@yahoo.com)

History
-------
2019-02-28 v1.0 (c) Lucien Murray-Pitts - Initial version to support step-over in ida v7.2

License
-------
GNU v3.0

        
