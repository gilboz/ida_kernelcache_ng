from ida_kernelcache.ida_utilities import make_log
from abc import ABC, abstractmethod

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ida_kernelcache.kernelcache import KernelCache


class BasePhase(ABC):
    LOG_LEVEL = 2

    def __init__(self, kc: 'KernelCache'):
        self._kc = kc
        self.log = make_log(self.LOG_LEVEL, self.__class__.__name__)

    @abstractmethod
    def run(self):
        pass
