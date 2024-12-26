# ida_kernelcache_ng
An IDA Plugin for analyzing iOS kernelcaches. **Currently, this is still WIP.**

* The goal is to support latest kernelcaches and IDA releases, improve accuracy, UI and add important features.
* Because this is a major refactor (This is now an actual IDA plugin!) and seems like the original authors no longer maintain their repository I've created this one.
* Hopefully this could gain more traction as more researchers will contribute with their ideas to automate the tedious reversing process.

## Credits
* This repository is based upon the original toolkit created by Brandon Azad, [repo](https://github.com/bazad/ida_kernelcache).
  * The original tool was written for iOS versions 10,11,12 (we are currently at 18.0). While most of the libkern++ runtime hasn't changed there have been some major changes.
* The repository was also maintained for some time by multiple employees from Cellebrite, [repo](https://github.com/cellebrite-labs/ida_kernelcache).
* The commit history has been reserved.

## License
ida_kernelcache is released under the MIT license.

Much of the functionality in ida_kernelcache is borrowed from [memctl], which is also released
under the MIT license. Other sources are noted in the comments in the corresponding files.

## TODO:
- [X] Implement AddClassInfoSymbols phase
- [X] Adapt to the new Plugin API 
- [X] Add a test script to analyze the kernelcache using the new idalib (headless mode)
- [X] Implement ColorizeVtables phase: set colors for vtable vmethods (which one overrides, which is new, which is inherited from super)
  The drawback here is that in order to set a color for each vtable entry I cannot retype the to the corresponding structure
- [ ] Get rid of old code! 
  - [X] Delete old and unused scripts!
  - [ ] Remove all methods in ida_utilities.py and remove the module
  - [ ] Replace and remove build_struct.py
  - [ ] the OneToOneMap not really needed anymore (add checks are raise PhaseException upon duplicates!) utils.py
- [X] Rename SetClassInfoSymbols phase to UseRTTIInfoPhase and improve it
  - [ ] Change the global instances type to OSMetaClass * type (requires to create this type a-prior)
  - [X] Change the types of every vtable it the Class_vtbl type - *WON'T DO, will break ColorizeVtables*
  - [X] Set the this argument type for every vtable function
- [X] Implement creation of C++ types (conforming to IDA 7.2 new C++ types), actually in IDA 9.0 the API has been improved 
  - [X] Implement detecting overridden functions and functions that are pure virtual
  - [X] Implement getting the PAC diversifier of every vtable entry
  - [X] Fix errors "does not seem to be a signed PAC pointer". UPDATE: seems like some objects are subject to multiple inheritance? In the past this was not supported by libkern++ 
        according to Apple's documentation. There are these sentinels and non virtual thunks, weird. On a recent kernelcache there are 93 classes that contain a sentinel.
  - [ ] Implement fetching function names if they are already set
  - [ ] Implement fetching function signatures
- [ ] Add CollectPACCallSites Phase (search for MOVKS followed by BLRAAs)
- [ ] Kernel fixups (auto analysis)
  - [ ] stack_chk_fail and panic
- [ ] Change return type of OSMetaClassBase::safeMetaCast calls according to the metaclass operand
- [ ] Improve Data flow analysis
  - [ ] Reimplement equivalent of class_struct.py (_propagate_virtual_method_types_for_class, process_functions)
  - [X] No more gaps in structures (just handled now in the way that I build the structures, might break in the future)
  - [ ] Scrape type information from kalloc_type/kalloc_type_var signatures?
- [ ] Add an ida_undo point and restore IDB in case of an exception
- [ ] Interactive renaming of methods that are related to a vtable, change the related function struct (See vds_hooks.py example in IDAPython repository)
- [ ] Improve the name mangling
- [ ] Symbolicate using panic strings and os_log strings
  - [X] Implement caching of the vtables contents using a VtableEntry abstraction
- [ ] Modify the install.sh script so that it will create a symlink to this plugin source instead of placing a stub.
- [X] Handle opcodes that IDA fails to decode. Currently done via a procmodule extension
- [X] Add a test script that can be used to search for more undecoded bytes in code segments (ida_bytes.get_flags(ea)) after a binary has completed auto analysis (for development purposes..)
- [ ] Resolve TODOs for edge cases in all of the phases
- [ ] Improve plugin GUI
  - [ ] Fix the wait box for updating the current phase that is executing
  - [ ] Add a Widget to select the phases which the user may run
  - [ ] Add a button to dump the findings to file outside of IDA
  - [ ] A feature I think is nice is to show class hierarchy in a Graph View
  - [ ] Another feature that could be nice is to show all the classes in a given kext
  - [ ] Add context-menu xrefs from and to vtables
- [ ] Fix the mangling issue when classnames contain '::'...
- [ ] Add external method processing phase
- [ ] Add support for multiple inheritance in CollectVtables?
- [ ] Change types of IOMallocType invocations?
- [ ] Generate TIL from the XNU sources, that will fit iOS compilations and load it into IDA.
  - [ ] CreateTypesPhase must align with it!
- [ ] Load basic types from KDK DWARF information?