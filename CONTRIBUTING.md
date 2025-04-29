# Development Setup
* Configure python idalib by following the README instructions in your IDA installation.
* Install the python package in editable mode (make sure to use the same python version as you chose with `idapyswitch`)
* Make sure that you're adding the IDA's python directory to your editor's PYTHONPATH so that it will index the relevant modules that are part of the IDA python sdk (`ida_*.py`)

```bash
# Execute at the project's root dir
python3 -m pip install --user -e .
```

When you wish to write some new phase, you may add a new subclass of `BasePhase` and then use it in the same manner as the 
the other scripts in the `tests/` directory.

For example `test_collect_classes.py` contains:
```python
from test_utils import get_kc, groupby_segment
import ida_kernelcache.phases

DB_PATH = r'./kernelcache_testing.i64'


def main():
    with get_kc(load=False) as kc:
        kc.process(phases=[ida_kernelcache.phases.CollectClasses])
        print(f'Found a total of {len(kc.class_info_map)}')
        groupby_segment(kc)


if __name__ == '__main__':
    main()
```

```bash
# From the tests/ directory
python3 test_collect_classes.py
```
