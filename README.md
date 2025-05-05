# IDA KernelCache NG
An IDA Plugin for analyzing iOS kernelcaches. **Currently, this is still WIP.**

* The goal is to support latest kernelcaches and IDA releases, improve accuracy, UI and add important features.
* Because this is a major refactor (This is now an actual IDA plugin!) and seems like the original authors no longer maintain their repository I've created this one.
* Hopefully this could gain more traction as more researchers will contribute with their ideas to automate the tedious reversing process.

## Installation
You have three options:
1. If you just wanna use it as an IDA plugin install it to your `~/.idapro/plugins` directory.
2. If you wish write scripts you may install it as a pip package 
3. If you want to contribute see CONTRIBUTING.md

For now it is better that you install it as a pip package and then run `cli.py`

## Credits
* This repository is based upon the original toolkit created by Brandon Azad, [repo](https://github.com/bazad/ida_kernelcache).
  * The original tool was written for iOS versions 10,11,12 (we are currently at 18.0). While most of the libkern++ runtime hasn't changed there have been some major changes.
* The repository was also maintained for some time by multiple employees from Cellebrite, [repo](https://github.com/cellebrite-labs/ida_kernelcache).
* The commit history has been reserved.

## License
ida_kernelcache is released under the MIT license.

## Improvements Needed
- [ ] Resolve TODOs for edge cases in all of the phases

## Tracking Known Issues
1. 93 Classes are subject to multiple inheritance
2. 70 Virtual methods that have wrong function boundaries
3. Classes that don't have a vtable, "optimized" classes
4. Vtable entries with a non-unique source