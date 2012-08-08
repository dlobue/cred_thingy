
from types import FunctionType

def register_subcommand(f):
    f._subcommand = True
    return f

def collect_subcmds_from_class(klass):
    all_methods = (getattr(klass, _) for _ in dir(klass) if not _.startswith('_'))
    subcommands = (_ for _ in all_methods if hasattr(_, '_subcommand') and getattr(_, '_subcommand') is True)
    return subcommands

def _get_kwarg_count(f):
    if f.func_defaults is None:
        return 0
    return len(f.func_defaults)

def _get_kwarg_names(f, kwcount):
    argcount = f.func_code.co_argcount
    return f.func_code.co_varnames[argcount - kwcount:argcount]

def _get_arg_names(f, kwcount, method=False):
    start = 1 if method else 0
    return f.func_code.co_varnames[start : f.func_code.co_argcount - kwcount]

def generate_subcmd_parser(subparsers, subcommands):
    for subcmd in subcommands:

        if isinstance(subcmd, FunctionType):
            subcmd_f = subcmd
        elif hasattr(subcmd, 'im_func'):
            subcmd_f = subcmd.im_func
        else:
            raise TypeError, ("subcommand %r is not a method or a function!" % subcmd, subcmd)

        kwcount = _get_kwarg_count(subcmd_f)
        sp = subparsers.add_parser(subcmd_f.func_name, help=subcmd_f.func_doc)
        for arg in _get_arg_names(subcmd_f, kwcount, True):
            sp.add_argument(arg)

        if kwcount:
            kwarg_names = _get_kwarg_names(subcmd_f, kwcount)
            kwargs = zip(kwarg_names, subcmd_f.func_defaults)
            for kwarg,default in kwargs:
                sp.add_argument('--' + kwarg, default=default)

