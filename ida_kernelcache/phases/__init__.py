# TaggedPointers: Not needed anymore since IDA 7.2 https://hex-rays.com/products/ida/news/7_2/
# RenameSegments:  # Not needed after IDA 7.5SP2? https://hex-rays.com/products/ida/news/7_5sp2/


from .collect_classes import CollectClasses
from .collect_vtables import CollectVtables
from .set_class_info_symbols import SetClassInfoSymbols

ALL_PHASES = [CollectClasses, CollectVtables, SetClassInfoSymbols]