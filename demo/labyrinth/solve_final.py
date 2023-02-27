from angr import *
from pwn import *
from networkx import shortest_path
import monkeyhex

# import logging
# logging.getLogger('angr').setLevel(logging.INFO)


def solve(file='elf', interactive=False):
    p = Project(file)
    elf = ELF(file)

    start_addr = 0x4011b3
    tar_addr = 0x4011c8


    # Construct a CFG from the 1000 functions. Restrict analysis to the relevant region to reduce time.
    region = [(0x401155, 0x400000 + elf.sym['__libc_csu_init'])]
    cfg = p.analyses.CFGFast(regions=region)

    # Construct quickest way to get to our target address.
    src_node = cfg.model.get_any_node(start_addr, anyaddr=True)
    tar_node = cfg.model.get_any_node(tar_addr, anyaddr=True)

    # Ensure nodes exist. shortest_path works differently if a node is None.
    assert src_node is not None and tar_node is not None

    # Construct the shortest path from src to tar. This will be a list of CFGNodes.
    path = shortest_path(cfg.graph, src_node, tar_node)


    # Method 1:
    # Walk through the rest of the path.
    state = p.factory.blank_state(addr=start_addr)
    for node in path:
        # Let the simulator engine works its magic.
        simgr = p.factory.simgr(state)
        simgr.explore(find=node.addr)
        assert len(simgr.found) > 0
        
        # Keep the found state for next iteration.
        state = simgr.found[0]
    # End of Method 1


    # # Method 2:
    # path_blocks = [n.addr for n in path]
    # state = p.factory.blank_state(addr=start_addr)
    # simgr = p.factory.simgr(state)
    
    # # Avoid if s.addr is not in our path. (Disregards checks when in libc calls.)
    # simgr.explore(find=tar_addr, avoid=lambda s: region[0][0] <= s.addr <= region[0][1] and s.addr not in path_blocks)

    # state = simgr.found[0]
    # # End of Method 2


    chain = state.posix.dumps(0)
    print(chain)

    if interactive:
        # If you want to play around with the above variables a bit more: `python -i solve.py`.
        globals().update(locals())

    return chain

from time import time

if __name__ == '__main__':
    start = time()
    solve(interactive=True)
    print(f'solve time: {time() - start:.2f}s')
