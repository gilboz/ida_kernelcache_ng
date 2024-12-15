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
- [ ] CollectClass phase resolve TODOs in the module
- [ ] CollectVtables phase resolve TODOs in the module
- [ ] Implement AddClassInfoSymbols phase
  - [ ] Change the global instances type to OSMetaClass * type (requires to create this type a-prior)
- [ ] Implement create C++ types (conforming to IDA 7.2 new C++ types)
- [ ] Improve Data flow analysis
  - [ ] No more gaps in structures
  - [ ] Scrape type information from kalloc_type/kalloc_type_var signatures?
- [ ] Add an ida_undo point and restore IDB in case of an exception
- [ ] Add a script to analyze the kernelcache using the new idalib (headless mode)
- [ ] Improve plugin GUI
- [ ] Kernel fixups 