"""The ARVO mini benchmark: five bugs per project.

Copied verbatim from ``MetaC/benchmarks/arvo/scripts/minibenchmark.py``
so the two code bases select the same instances.

All 25 pass the standard ARVO row filters, ``ffmpeg`` included.
"""

ARVO_MINI = {
    'ffmpeg': {'42513082', '42525131', '42512041', '42525159', '42528991'},
    'gpac': {'42531361', '42532234', '42533223', '42531339', '414916080'},
    'libxml2': {'42510333', '42525210', '42533922', '42522530', '392687022'},
    'mruby': {'42511322', '42513781', '42509077', '42517443', '42522938'},
    'ndpi': {'42510718', '42514313', '42522544', '42531416', '379180960'},
}
