# Packet headers
# \______________


DATA_TESSLA: str = "data/tessla/"
DATA_JSON: str = "data/json/"

# libc set up and teardown
AVOIDED_FUNC_NAMES: tuple[str, ...] = (
    "_start",
    "__libc_start_main",
    ".plt",
    "call_weak_fn",
    "_init",
    "frame_dummy",
    "register_tm_clones",
    "deregister_tm_clones",
    "__cxa_finalize",
    "__do_global_dtors_aux",
    "_fini",
)
