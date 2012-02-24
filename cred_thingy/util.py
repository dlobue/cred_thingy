
from functools import wraps

def memoize_attr(func):
    @wraps(func)
    def wrapper(self):
        cache_attr = '_' + func.im_func.func_name
        if hasattr(self, cache_attr):
            return getattr(self, cache_attr)
        result = func(self)
        setattr(self, cache_attr, result)
        return result
    return wrapper

