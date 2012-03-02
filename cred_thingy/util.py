
from functools import wraps

def memoize_attr(func):
    @wraps(func)
    def wrapper(self):
        cache_attr = '_' + func.func_name
        if hasattr(self, cache_attr):
            return getattr(self, cache_attr)
        result = func(self)
        setattr(self, cache_attr, result)
        return result
    return wrapper

class Singleton(object):
    _instance = None
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Singleton, cls).__new__(
                                cls, *args, **kwargs)
        return cls._instance

