"""
plugin_entry.py
A script to load ida_kernelcache module and create a KernelCache instance
To start analyzing call kc.process()

@Author: Brandon Azad
"""
import ida_kernelcache
kc = ida_kernelcache.KernelCache()
