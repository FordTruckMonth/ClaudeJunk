"""
              ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
              ▓                                             ▓
              ▓     T H E   S C A R I E S T   F I L E       ▓
              ▓                                             ▓
              ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

    The horrors below are real, executable Python.
    Each one is something you can do, today, with a stock interpreter.
    None of them require a third-party package. None of them require
    root. The knife ships in the box; the box is labeled "batteries
    included."

    Run with:    python3 scariest.py
    Then read the source.
    Reading the source is how it gets you.
"""
import builtins, ctypes, sys, types, threading, atexit
import importlib.abc, importlib.util

print = builtins.print  # we will need the real one again before the night is over.


# ─── I.  The integer cache is not immutable. ──────────────────────────────────
#
# CPython interns the integers -5..256 as singletons. Every `7` in this
# process points at the same object. We open that object's memory and write
# a different number into it. There is no API for this. There is no warning.
# After the call, every library imported in this process that adds 4 + 3 will
# get something else, forever, and there is no rolling it back.
def _curse_a_number(n: int, m: int) -> None:
    """Rewrite the singleton for integer `n` to hold `m`. Permanent."""
    # PyLongObject layout (CPython 3.12+):
    #   ob_refcnt    : 8 bytes
    #   ob_type      : 8 bytes
    #   lv_tag       : 8 bytes   ← encodes sign and digit-count
    #   ob_digit[0]  : 4 bytes   ← the value, for small ints
    ctypes.cast(id(n) + 24, ctypes.POINTER(ctypes.c_uint32))[0] = m

# Demonstration left commented because it taints the whole interpreter.
# Uncomment, then ask the interpreter what `for i in range(7):` means
# when 7 is 3.
# _curse_a_number(7, 3)


# ─── II.  A metaclass that swallows the name of its child. ────────────────────
#
# Every class that uses this loses its identity at birth. Its __name__ is
# overwritten before any user code sees it. Every traceback, every repr,
# every isinstance error message, refers to it as ■.
class Erased(type):
    def __new__(mcs, name, bases, ns):
        return super().__new__(mcs, "■", bases, ns)

class Subject(metaclass=Erased):
    pass


# ─── III.  An import hook that fabricates whatever you ask for. ───────────────
#
# sys.meta_path is consulted on every `import`. A finder placed here can
# return any module, with any contents. The user sees nothing unusual.
# pip does not know. `pip list` does not show it. The file does not exist
# on disk. The module passes hasattr() for every attribute you can name.
class _Fabricator(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def find_spec(self, name, path, target=None):
        if name == "trust" or name.startswith("trust."):
            return importlib.util.spec_from_loader(name, self)
        return None
    def create_module(self, spec):
        return types.ModuleType(spec.name)
    def exec_module(self, m):
        # Every attribute access returns the module itself, recursively.
        #   m.foo            → m
        #   m.foo.bar.baz()  → m
        m.__getattr__ = lambda _name: m

sys.meta_path.insert(0, _Fabricator())


# ─── IV.  Mutable default arguments, weaponized. ──────────────────────────────
#
# The list `souls` is created once, at function definition time. Every call
# appends to the same list. Nothing ever frees it. This is documented,
# specified, intentional behavior. Every Python programmer must, at some
# point, learn it through pain.
def remember(soul=None, souls=[]):
    if soul is not None:
        souls.append(soul)
    return souls


# ─── V.  An object that lies about every check. ───────────────────────────────
#
# isinstance(Liar(), int) is True — and yet type(Liar()) is not int. The
# language has two different ways to ask "what is this," and a class can
# make them disagree. Liar() == anything is True. Liar() != anything is
# also True. bool(Liar()) is False, and Liar() == True is True.
# Every contract this object presents is a lie. Validators are theatre.
class Liar:
    __class__ = property(lambda s: int)
    def __eq__(self, _):  return True
    def __ne__(self, _):  return True
    def __bool__(self):   return False
    def __hash__(self):   return 0


# ─── VI.  Bytecode replacement. ───────────────────────────────────────────────
#
# A Python function is a thin wrapper around a code object. Replace its
# __code__ attribute and the function runs different code. The source in
# the .py file is unchanged. The docstring is unchanged. The signature is
# unchanged. `inspect.getsource` returns the original lines. You will
# `git blame` this function in two years and find your own name on
# something that no longer does what its body says.
def add(a, b):
    "Returns a + b."
    return a + b

def _replace(a, b):
    return a * b - 1

add.__code__ = _replace.__code__
# After this line, add(3, 4) is 11, while the docstring still says it adds.


# ─── VII.  The thread that cannot be killed. ──────────────────────────────────
#
# Python has no public API to stop a thread. There is a private C function,
# reachable via ctypes, that injects an exception into a target thread — but
# the injection only takes effect when the thread next executes Python
# bytecode that checks for it, and a thread inside a C call (sleep, recv,
# anything blocking) never checks. This thread, in particular, swallows
# every exception including KeyboardInterrupt, and goes back to waiting.
def _patient():
    while True:
        try:
            pass
        except BaseException:
            pass

threading.Thread(target=_patient, daemon=True, name="patient").start()


# ─── VIII.  The exit hook that gets the last word. ────────────────────────────
@atexit.register
def _the_door_closes_behind_you():
    print("\n  ... you read all of it.\n")


if __name__ == "__main__":
    print(__doc__)
    print(f"  Liar() == 0                →  {Liar() == 0}")
    print(f"  Liar() != 0                →  {Liar() != 0}")
    print(f"  isinstance(Liar(), int)    →  {isinstance(Liar(), int)}")
    print(f"  type(Liar()) is int        →  {type(Liar()) is int}")
    print(f"  Subject.__name__           →  {Subject.__name__!r}")
    print(f"  add(3, 4)                  →  {add(3, 4)}      (docstring: {add.__doc__!r})")
    remember("yours"); remember("mine"); remember("everyone who ever called this")
    print(f"  len(remember())            →  {len(remember())}      (and growing)")
    import trust.me  # fabricated out of thin air by step III
    print(f"  trust.me.anything.you.want →  {trust.me.anything.you.want}")
    print()
    print("  Loaded.  Nothing terrible seems to have happened.")
