from angr import *
from claripy import *


# p = Project(cle.Loader('existing-tooling', main_opts={'base_addr': 0x100000}))
p = Project('existing-tooling')

state = p.factory.entry_state()
# state.options |= sim_options.refs
simgr = p.factory.simgr(state)
# state.inspect.b('mem_write', when=BP_BEFORE, mem_write_address=0x404180)
simgr.explore(find=0x401206) # 0x401206 is just inside an if-block, after xor-ing is done.

s = simgr.found[0]
print(b''.join(s.mem[0x404180+i].char.concrete for i in range(73)))
# print(s.mem[0x404180].string.concrete)
# print(s.solver.eval(s.memory.load(0x404180, 72), cast_to=bytes))
# s.mem[0x404180].string.concrete
# b''.join(s.mem[0x404180+i].char.concrete for i in range(72))
# s.solver.eval(s.memory.load(0x404180, 72), cast_to=bytes)
# b''.join(s.solver.eval(d.data, cast_to=bytes) for d in [a for a in s.history.actions if 'mem/write' in repr(a)][-73:-1])

# gigem{im_curious_did_you_statically_or_dynamically_reverse_ping_addison}