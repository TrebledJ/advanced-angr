from angr import *
import monkeyhex


p = Project('existing-tooling')
state = p.factory.entry_state()


state.inspect.b('mem_write', when=BP_AFTER, mem_write_address=0x404180, action=BP_IPYTHON)
# state.inspect.b('fork')

simgr = p.factory.simgr(state)
simgr.explore()

