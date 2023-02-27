# advanced-angr
Memeful CTF training presentation on Angr and Control Flow Graphs made with ❤️ using LaTeX Beamer for the HKUST Firebird CTF Team.

[Handout][handout] • [Slides][slides]

[handout]: handout.pdf
[slides]: slides.pdf

## Contents
* SOMP1010: angr Management
    * A 1.5 hour course dedicated to the cultivation of Societal elements in a cOMPuting context.
* Intro - 3min
    * What is angr?
    * Motivation

* Back to the Basics - 5min
    * General Idea of Symbolic Solving (COMP4901N Review)
    * angr Level 1 Code
    * angr Flow 1 - Level 1
        * Existing Stuff:
            * Project, SimState, Simulation Manager, claripy
            * Simulation Box
            * `state.solver.add`
            * `simgr.explore`
            * `simgr.posix.dumps`
    * angr Flow 2 - Expanded 1
        * What's new? In the next section...
            * `state.memory`
            * `state.mem`
            * `state.regs`
            * `state.solver.eval`
            * `simgr.stashes`

* Training Your Angr - 20min
    * Terminology
    * Concepts - SimState
        * `state.memory`
        * `state.mem`
        * `state.regs`
        * Concretisation
            * `state.solver.eval`
            * `state.posix.dumps`
    * Concepts - Simulation Manager
        * `simgr.explore` - More parameters
        * `simgr.run` - More parameters
        * `simgr.stashes` - Different stashes
    * Demo (SOMP1010 Midterm): "Tooling"
        * What is the address of the secret?
        * What is the length of the secret?
        * Which of these will correctly concretise and print out the secret, assuming there are no null bytes in the middle?
    * More on symbolic execution
    * angr Flow 3 - Expanded 2
        * What's new? Left as an exercise for the reader...
            * `cle.Loader`
            * State Presets
            * Execution Engine
            * `SimProcedure`
            * `state.options`
            * Analysis
    
* Analysing Angr Programs - 30min
    * Path explosion
        * Why analysis? Simple `simgr.explore()` not enough.
    * Graphs Redux
    * What are Control Flow Graphs (CFGs)?
    * CFGs in angr
        * `CFGFast`
        * `CFGEmulated`
    * Demo (SOMP1010 Final): "Labyrinth"
    * More on analysis
    
* Debugging Angr Programs - 5min
    * angr Flow 4
    * `logging`
    * `state.callstack`
    * `state.history`
    * `state.inspect.b`

* Tips - 3min

## Notes
* Credits for the demo challenges ([existing-tooling](https://github.com/tamuctf/tamuctf-2022/tree/master/reversing/existing-tooling) and [labyrinth](https://github.com/tamuctf/tamuctf-2022/tree/master/reversing/labyrinth)) goes to TAMUctf organisers.
* Graphs were made using [TikZiT](https://tikzit.github.io/) (recommend using!).
* Presentation was delivered over Zoom with [SlidePilot](https://github.com/SlidePilot/SlidePilot-macOS) (also recommend!).
* Firebird Beamer template was provided by a senior member, with some minor adjustments on my end.





