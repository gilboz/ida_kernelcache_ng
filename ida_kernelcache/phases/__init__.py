# TaggedPointers: Not needed anymore since IDA 7.2 https://hex-rays.com/products/ida/news/7_2/
# RenameSegments:  # Not needed after IDA 7.5SP2? https://hex-rays.com/products/ida/news/7_5sp2/

from .collect_classes import CollectClasses
from .collect_vtables import CollectVtables
from .apply_rtti_info import ApplyRTTIInfoPhase
from .create_types import CreateTypes

ALL_PHASES = [CollectClasses, CollectVtables, ApplyRTTIInfoPhase, CreateTypes]
