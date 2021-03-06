
from functools import wraps
from collections import Iterable

from gevent.core import timer

def flattener(*list_of_lists):
    stack = [list_of_lists]
    iteree = iter(stack)
    while 1:
        try:
            item = iteree.next()
        except StopIteration:
            try:
                iteree = iter(stack.pop())
                continue
            except IndexError:
                break

        if isinstance(item, Iterable) and not isinstance(item, basestring):
            stack.append(iteree)
            iteree = iter(item)
            continue
        yield item

def schedule(time, f, *args, **kwargs):
    try:
        f(*args, **kwargs)
    finally:
        timer(time, schedule, time, f, *args, **kwargs)

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

