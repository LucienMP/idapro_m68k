import idaapi
import ida_pro
import idautils

#from pprint import pprint

# Used by the loop for function purge
from idaapi import *

# Used for printing various data
import logging

"""
    This is a sample plugin for extending gdb support for step-over for the M68K,
    and to enable type support so you can press "y" on functions.

    When you install a hook in the HT_IDP category, it will be called
    before the processor module's notify() function, so if you return
    non-zero, your results will be used.

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

    Many thanks to Ilfak Guilfanov @ Hey-Rays

    Versioning:
        2019-02-28 v1.0 (c) Lucien Murray-Pitts - Initial version to support step-over
""" 

#--------------------------------------------------------------------------
#
class m68kstepover_idp_hook_t(idaapi.IDP_Hooks):
    #
    def __init__(self):
        idaapi.IDP_Hooks.__init__(self)

    #--------------------------------------------------------------------------
    #
    # Handling of GDB related events
	
    # Calculate the address of the instruction which will be
    # executed after "step over". The kernel will put a breakpoint there.
    #
    def ev_calc_step_over(self, target, ip):
        # Supports the following instructions
        # 4E80..BF        jsr     (a0) +2
        # 61xx            bsr     (a0) +2
        # 6100 xxyy       bsr     (a0) +4
        # 61ff xxyy xxyy  bsr     (a0) +6
        # idaapi.BADADDR  else    BADADDR
        #
        logging.debug("BSR/JSR, checking instruction")
        ta=ida_pro.ea_pointer_frompointer(target)

        insn = idautils.DecodeInstruction(ip)
        if insn and insn.itype in [idaapi.mc_jsr, idaapi.mc_bsr]:
            over_ea = insn.ea + insn.size
            logging.debug(" - JSR STEP> +%s %s" % (insn.size, hex(over_ea)) )
            ta.assign(over_ea)
        else:
            logging.debug(" - NO STEP> "+hex(ip))
            ta.assign(idaapi.BADADDR)

# Original code before IDA guys helped me write the above!
#
#        if idaapi.get_bytes(ip, 2) >= "\x4E\x80" and idaapi.get_bytes(ip, 2) <= "\x4E\xBF":
#            logging.debug( "JSR STEP> +2 " + hex(ip+2) )
#            ta.assign(ip+2)
#        elif idaapi.get_bytes(ip, 2) == "\x61\x00":
#            logging.debug( "BSR STEP> +4 " + hex(ip+4) )
#            ta.assign(ip+4)
#        elif idaapi.get_bytes(ip, 2) == "\x61\xff":
#            logging.debug( "BSR STEP> +6 " + hex(ip+6) )
#            ta.assign(ip+6)
#        elif idaapi.get_bytes(ip, 1) == "\x61":
#            logging.debug( "BSR STEP> +2 " + hex(ip+2) )
#            ta.assign(ip+2)
#        else:
#            logging.debug( "NO STEP> "+hex(ip) )
#            ta.assign(idaapi.BADADDR)
        return 1

    #--------------------------------------------------------------------------
    #
    # Handling of TYPE related events
	
    # Setup default type libraries.
    # (called after loading a new file into the database). The processor module may load tils, 
    # setup memory model and perform other actions required to set up the type system. This is an optional callback.
    #
    def ev_setup_til(self, abi_names, abi_opts, comp):
        logging.debug("##########ev_setup_til")
        return
		
    # Get all possible ABI names and optional extensions for given compiler
    # abiname/option is a string entirely consisting of letters, digits and underscore
    # 0=not implemented, 1=ok
    #
    def ev_get_abi_info(self, abi_names, abi_opts, comp):
        logging.debug("##########ev_get_abi_info")
        logging.debug(abi_names)
        logging.debug(abi_opts)
        logging.debug(comp)
        return 0

    # Get maximal size of a pointer in bytes.
    #
    #
    def ev_max_ptr_size(self, target, ip):
        logging.debug("##########ev_max_ptr_size")
        return 4

    # Get default enum size.
    # returns sizeof(enum)
    #
    def ev_get_default_enum_size(self, cm):
        logging.debug("##########ev_get_default_enum_size")
        return 4

    # Get register allocation convention for given calling convention.
    # 1, or 0=not implemented
    #
    def ev_get_cc_regs(self, regs, cc):
        logging.debug("##########ev_get_cc_regs")
        return 0

    # Get offset from SP to the first stack argument.
    #
    #
    def ev_get_stkarg_offset(self):
        logging.debug("##########ev_get_stkarg_offset")
        return 0

    # Get SIMD-related types according to given attributes ant/or argument location.
    # returns number of found types, -1-error If name==NULL, initialize all SIMD types
    #
    def ev_get_simd_types(self, out, simd_attrs, argloc, create_tifs):
        logging.debug("##########ev_get_simd_types")
        return 0

    # Calculate number of purged bytes after call.
    # returns number of purged bytes (usually add sp, N)
    # 
    def ev_calc_cdecl_purged_bytes(self, ea):
        logging.debug("##########ev_calc_cdecl_purged_bytes")
        return 0

    # Calculate number of purged bytes by the given function type.
    # 1, or 0 = not implemented
    #
    def ev_calc_purged_bytes(self, p_purged_bytes, fti):
        logging.debug( "##########ev_calc_purged_bytes" )
        logging.debug( fti.size() )
        logging.debug( fti.get_call_method() )
        logging.debug( fti.is_pure() )
        logging.debug( fti.rettype.get_size() )
        
        # Information about each argument IF there are any, NOTE that if the next instruction is unlink then NO purge is done
        ##########
        # NOTES:
        #   https://reverseengineering.stackexchange.com/questions/8870/extracting-arguments-from-ida
        #   https://github.com/gsmk/hexagon/blob/master/pmbase.h
        #   https://github.com/idapython/src/blob/master/pywraps/py_idp.hpp#L608
        #   LOCATION TYPE: https://www.hex-rays.com/products/ida/support/sdkdoc/group___a_l_o_c__.html
        #
        for i in xrange(fti.size()):
                logging.debug( "Arg %d: %s (of type %s, and of location: %s)" % (i, fti[i].name, idaapi.print_tinfo('', 0, 0, idaapi.PRTYPE_1LINE, fti[i].type, '', ''), fti[i].argloc.atype()) )

        # Sort of wrong, there could be shorts or other odd sized things on the stack
        p_purged_bytes = fti.size() * 4
        
        return 1

    # Calculate return value location.
    # 0 not implemented, 1 ok, -1 error
    #
    def ev_calc_retloc(self, retloc, rettype, cc):
        logging.debug( "##########ev_calc_retloc" )
        
        logging.debug( "retloc=" + str(retloc) ) 
        logging.debug( "rettype=" + str(rettype) )
        logging.debug( "cc=" + str(strcc) )
		
        # SEE: add_argregs in emu.cpp 
        # IF just a single reg then reg1, else if a range reg2 START##########END
        retloc.set_reg1(0)
        # IF its a range reg2 START##########END
        #retloc.set_reg2(0,0)
        # IF its a mix, then create a scattered_aloc_t, and push_back multiple part argpart_t
        #retloc.consume_scattered(0)
		
        #retloc.set_stkoff(0)
        #retloc.set_ea(0)
        #retloc.consume_rrel(0) # argloc_t_consume_rrel
        #argloc_t
        return 1


    # Calculate function argument locations.
    # This callback should fill retloc, all arglocs, and stkargs.
    # This callback is never called for ::CM_CC_SPECIAL functions.
    # 0=not implemented, 1=ok, -1=error
    #
    # See: alloc_args from arc emu.cpp in SDK
    def ev_calc_arglocs(self, fti):
        logging.debug(  "##########ev_calc_arglocs" )
        logging.debug(  "is_void() = " + str(fti.rettype.is_void()) )

        # Set the location of each argument
        #    NOTE: LOCATION TYPE: https://www.hex-rays.com/products/ida/support/sdkdoc/group___a_l_o_c__.html
        #
        for i in xrange(fti.size()):
            logging.debug(  "Arg %d: %s (of type %s, and of location: %s)" % (i, fti[i].name, idaapi.print_tinfo('', 0, 0, idaapi.PRTYPE_1LINE, fti[i].type, '', ''), fti[i].argloc.atype()) )
            # Set funciton argument #i location as register number "i"
#            fti[i].argloc.set_reg1(i)
            # Set funciton argument #i location as stack at location "i"*4
            fti[i].argloc.set_stkoff(i*4)
        # Return value is D0
        fti.retloc.set_reg1(0) # D0
        # Set size of stack arguments passed
        fti.stkargs = fti.size() * 4
        return 1

    # Calculate locations of the arguments that correspond to '...'
    # 0=not implemented, -1=error, 1=ok
    # 
    def ev_calc_varglocs(self, ftd, regs, stkargs, nfixed):
        logging.debug(  "##########ev_calc_varglocs" )
        return 0

    # Adjust argloc according to its type/size and platform endianess.
    # 0=not implemented, -1=error, 1=ok
    # 
    def ev_adjust_argloc(self, argloc, optional_type, size):
        logging.debug(  "##########ev_adjust_argloc" )
        return 0

    # Get function arguments which should be converted to pointers when lowering function prototype.
    # The processor module can also modify 'fti' in order to make non-standard conversion
    # 0=not implemented, 1=argnums was filled, 2 argnums was filled and made substantial changes to fti
    def ev_lower_func_type(self, argnums, fti):
        logging.debug(  "##########ev_lower_func_type" )
        return 0

    # Are 2 register arglocs the same?
    # 1=yes, -1=no, 0=not implemented
    # 
    def ev_equal_reglocs(self, a1, a2):
        logging.debug(  "##########ev_equal_reglocs" )
        return 0

    # Use information about a stack argument.
    #  retval <=0 failed, the kernel will create a comment with the
    #  argument name or type for the instruction
    #
    def ev_use_stkarg_type(self, ea, arg):
        logging.debug(  "##########ev_use_stkarg_type" )
        return 0

    # Use information about register argument.
    # 0=not implemented, 1=???
    # 
    def ev_use_regarg_type(self, ea, rargs):
        logging.debug(  "##########ev_use_regarg_type" )
        return 0

    # Use information about callee arguments.
    # 0=not implemented, 1 (and removes handled arguments from fti and rargs)
    # 
    def ev_use_arg_types(self, ea, fti, rargs):
        logging.debug(  "##########ev_use_arg_types" )
        return 0

    # Argument address info is ready.
    # <0: do not save into idb; other values mean "ok to save"
    #
    def ev_arg_addrs_ready(self, caller, n, tif, addrs):
        logging.debug(  "##########ev_arg_addrs_ready" )
        return 1

    # Decorate/undecorate a C symbol name, unlike C the return is the demanged name
    #   ev_decorate_name(self, name, mangle, cc, optional_type) -> PyObject *
    #
    def ev_decorate_name(self, name, mangle, cc, optional_type):
        logging.debug(  "##########ev_decorate_name" )
        logging.debug(  "NAME=" + str(name) )
        logging.debug(  "MANGLE?=" + str(mangle) )
        logging.debug(  "CC=" + str(cc) )
        logging.debug(  "OptionalType=" + str(optional_type) )
        logging.debug(  "procName=" + str(idaapi.get_inf_structure().procName) )
        
        # Compiler Info "compiler_info_t cc;                   ///< Target compiler" from ida.hpp
        logging.debug(  "cc.id=" + str(idaapi.get_inf_structure().cc.id) )
        
        #get_compiler_name
        # FROM: idaapi.gen_decorate_name(name, mangle, cc, type) -> bool 
        gen_decorate_name(name,mangle,cc,optional_type)
        logging.debug( "NAME POST Decoration:" + str(name) )
        return name

        
        
#--------------------------------------------------------------------------
# CTYPE mapping for global ph structure into python
#

# NOTE: Requires MSVCR90.dll, you will need the 2008 redist from MS for this to work right
#import ctypes
from ctypes import *
from binascii import hexlify
from sys import getsizeof
import ida_idp as ida_idp

# Partial structure information for accessing PH directly
#
class structPH(Structure):
        _fields_ = [("version", c_uint),
        ("id", c_uint),   
        ("flag", c_uint)]    


#--------------------------------------------------------------------------
class m68kstepover(idaapi.plugin_t):
    # Processor fix plugin module
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = ""
    wanted_hotkey = ""
    help = "Supports Step-Over for M68K CPU on BSR/JSR, and type information"
    wanted_name = "m68kstepover"
       
    def init(self):
        self.prochook = None
        
        # Enable controlable logging 
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(filename)s:%(funcName)s@%(lineno)s: %(message)s')
       
        logging.debug('Module for MC68000 class CPU Step-Overs, and type information')
        
        # Random Debug to analyze PH mapping support
        #
        #print cdll.ida.ph
        #ph = structPH.in_dll(cdll.ida, "ph")
        #ph = structPH()
        #ph.values = cast( cdll.ida.ph, POINTER(structPH) )
		
        # Map ida.dll into this Python module, and lets us change the flags to add TYPEINFO support.
        #
        # For O/S agnostic support this follow advice from: http://www.hexblog.com/?p=695
        #
        idaname = "ida64" if ida_idaapi.__EA64__ else "ida"
        try:
            logging.debug( "Platform for ida library loading: " + str(sys.platform) )
            if sys.platform == "win32":
                ida_dll = ctypes.windll[idaname + ".dll"]
            elif sys.platform == "linux2":
                ida_dll = ctypes.cdll["lib" + idaname + ".so"]
            elif sys.platform == "darwin":
                ida_dll = ctypes.cdll["lib" + idaname + ".dylib"]        
        except:
            logging.error( "Python CTYPES probably couldnt find the dll, OR the MSCVR90.dll or other system DLL is missing" )
            return idaapi.PLUGIN_SKIP
		
        # Access ph global in ida.dll using ctypes
        ph = structPH.in_dll(ida_dll, "ph")
        
        # Log Values via PH direct access
        logging.debug( "- - - - - - - - - - - - - - - - - -" )
        logging.debug( "  ph.version = %d" % ph.version )
        logging.debug( "  ph.id      = %d" % ph.id )
        logging.debug( "  ph.flag    = %d" % ph.flag )

        # Enable TYPEINFO support
        ph.flag = ph.flag | ida_idp.PR_TYPEINFO

        # Official API, confirms PH was correctly accessed
        logging.debug( "- - - - - - - - - - - - - - - - - -" )
        logging.debug( "  ph.version = %d" % idaapi.ph_get_version() )
        logging.debug( "  ph.id      = %d" % idaapi.ph_get_id() )
        logging.debug( "  ph.flag    = %d" % idaapi.ph_get_flag() )

        #print(hexlify(string_at(cdll.ida.ph, getsizeof(G))))
			
        if idaapi.ph_get_id() != idaapi.PLFM_68K: # or idaapi.cvar.inf.filetype != idaapi.f_ELF:
            logging.error("skipped this plugin because CPU being used is not 68000 derivative!")
            return idaapi.PLUGIN_SKIP

        # Connect the IDP hooks
        self.prochook = m68kstepover_idp_hook_t()
        self.prochook.hook()

        logging.debug( "succeeded, stepover support should now work for BSR/JSR!" )
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        logging.debug( "ida is terminating, removing step-over support event handling!" )
        if self.prochook:
            self.prochook.unhook()

#--------------------------------------------------------------------------
def PLUGIN_ENTRY():
    return m68kstepover()
