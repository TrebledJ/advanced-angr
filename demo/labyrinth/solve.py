from angr import *
import monkeyhex
from pwn import *
import networkx


def solve():
    p = Project('elf')
    elf = ELF('elf')

    src_addr = 0x401155
    tar_addr = 0x4011c8

    regions = [(src_addr, 0x400000 + elf.sym['__libc_csu_init'])]
    cfg = p.analyses.CFGFast(regions=regions)

    src_node = cfg.model.get_any_node(src_addr, anyaddr=True)
    tar_node = cfg.model.get_any_node(tar_addr, anyaddr=True)

    path = networkx.shortest_path(cfg.graph, src_node, tar_node)

    state = p.factory.entry_state(addr=src_addr)
    for node in path[4:]:
        simgr = p.factory.simgr(state)
        simgr.explore(find=node.addr)
        assert len(simgr.found) > 0

        state = simgr.found[0]
    
    return state.posix.dumps(0)
