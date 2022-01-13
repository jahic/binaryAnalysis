import angr
import monkeyhex
import pyvex
import nose

proj = angr.Project('testArgs', auto_load_libs=False, default_analysis_mode='symbolic')

compiler_build_in_funcs = ["_init", "_start", "deregister_tm_clones", "register_tm_clones", "__do_global_dtors_aux", "frame_dummy", "__libc_csu_init", "__libc_csu_fini", "_fini", "__x86.get_pc_thunk.bx", "__x86.get_pc_thunk.dx", "__libc_start_main", "__stack_chk_fail", "__libc_start_main", "__gmon_start__", "__isoc99_scanf", "printf", "UnresolvableJumpTarget", "UnresolvableCallTarget"]

# when a binary has functions starting at [f1,f2,...,fn], this function will find the smallest value fk in [f1,...,fn] s.t. fk > func_addr.
def decide_upper_bound(func_addr, cfg):
    min_upper = max(cfg.kb.functions.keys())
    for key in cfg.kb.functions.keys():
        if key > func_addr and key < min_upper:
             min_upper = key
    return min_upper

def vfgAnalysis():
    print("CFG --- Start")
    cfg = proj.analyses.CFGEmulated(normalize=True)
    print("CFG --- End")
    
    entry_func = cfg.kb.functions[proj.entry]
    print("VFG --- Start")

    initState = proj.factory.entry_state(mode="static")
    # Make EDI register value symbolic:
    inputReg = initState.solver.BVS('edi', 32)
    initState.registers.store('edi', inputReg)
    # Make EDI register value concrete and equal to 1:
    #inputReg = initState.solver.BVV(1, 32)
    #initState.registers.store('edi', inputReg)

    # Get main to be the start function of the analysis.
    # IMPORTANT: Otherwise, there are issues with the init state.
    startFunction = ""
    for fn in cfg.kb.functions:
        if cfg.kb.functions[fn].name == "main":
            print("MAIN FOUND!!!")
            startFunction = fn
            break
    
    print("Start function = ", cfg.kb.functions[startFunction].name)
    vfg = proj.analyses.VFG(cfg, initial_state=initState, context_sensitivity_level=2, interfunction_level=4, start=startFunction, function_start=startFunction, remove_options={angr.options.OPTIMIZE_IR})
   
    print("\t Number of VFG nodes = ", len(vfg.graph.nodes()))
    print("VFG --- End")
    
    print("List all nodes from VFG --- START")
    for addr,func in cfg.kb.functions.items():
        if func.name not in compiler_build_in_funcs:
            print("VFG details for function = ", func.name)
            for _, state in vfg._nodes.items():
                vfg_node_addr = state.state.addr
                print("vfg node:", hex(vfg_node_addr))
                if vfg_node_addr >= addr and vfg_node_addr < decide_upper_bound(addr,cfg):
                    # if so, print the vfg node and the VSA information along with this vfg node:
                    #print("vfg node:", hex(vfg_node_addr))
                    vfgnode  = vfg.get_any_node(vfg_node_addr)

                    for state in vfgnode.final_states:
                        print("Print all initialized registers for vfg node", hex(vfg_node_addr), ":")
                            
                        #print("\t rbp: ", state.regs.rbp) 
                        #print("\t rsp: ", state.regs.rsp)
                        #print("\t edi: ", state.regs.edi)
                        #print("\t rsi: ", state.regs.rsi)
                        #print("\t eax: ", state.regs.eax)

                        for regName in state.regs.__dir__():
                            if not state.regs.__getattr__(regName).uninitialized:
                                print("\t ", regName, ": ", state.regs.__getattr__(regName)) 
    print("--------------------------------------------------\n\n")

    print("List all nodes from VFG --- END")
    return

vfgAnalysis()
