"""
Register a new IDA Plugin using the python api.
Updated to conform to the new plugin API: https://docs.hex-rays.com/developer-guide/idapython/how-to-create-a-plugin

See: https://hex-rays.com/blog/scriptable-plugins/ and loader.hpp in the IDA SDK
See: https://hex-rays.com/blog/augmenting-ida-ui-with-your-own-actions/ and the Pacxplorer plugin by Lipner..
"""
import idaapi
from ida_kernelcache.kernelcache import KernelCache
from ida_kernelcache.ida_helpers.hooks import IDPHooks


class IDAKernelCachePluginMod(idaapi.plugmod_t):

    def __init__(self):
        super().__init__()
        print('[ida_kernelcache_ng] plugmod constructor called!')
        self.kc = KernelCache()
        self.idp_hooks = IDPHooks()
        self.idp_hooks.hook()
        print('[ida_kernelcache_ng] placed procmod hooks..')

    def __del__(self):
        print('[ida_kernelcache_ng] plugmod destructor called!')
        if self.idp_hooks is not None:
            print('[ida_kernelcache_ng] unhooking procmod..')
            self.idp_hooks.unhook()

    def run(self, arg):
        print('[ida_kernelcache_ng] plugmod run called starting to process!!')
        self.kc.process()


class IDAKernelCachePlugin(idaapi.plugin_t):
    """
    TODO: add more menu items to improve UI/UX
    TODO: cache data in the IDB for persistency?
    """
    wanted_name = "IDA KernelCache NG"
    # wanted_hotkey = "Meta-K"

    flags = idaapi.PLUGIN_MULTI | idaapi.PLUGIN_MOD

    comment = "Based on ida_kernelcache_ng by @_bazad! Now maintained by gilboz"
    help = "Helps with iOS KernelCache reversing"

    def init(self) -> idaapi.plugmod_t | None:
        """
        TODO: when I set the PLUGIN_PROC flag the plugin is initialized too early, IDA still doesn't detect the input file as a kernelcache and we alawys skip it
        """
        # We only want to be loaded when analyzing kernelcaches
        if not KernelCache.is_supported():
            print('[ida_kernelcache_ng] not a kernelcache, skipping..')
            return None  # None is the same as PLUGIN_SKIP

        print('[ida_kernelcache_ng] input file is supported loading plugin..')
        return IDAKernelCachePluginMod()


def PLUGIN_ENTRY():
    return IDAKernelCachePlugin()
