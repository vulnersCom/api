"""
    by oPromessa, 2017
    Published on https://github.com/oPromessa/flickr-uploader/

    Inspired by: https://gist.github.com/gregburek/1441055

    Helper class and functions to rate limiting function calls with Python Decorators

    Modified by isox@vulners.com for Vulners API wrapper
"""

# ----------------------------------------------------------------------------
# Import section for Python 2 and 3 compatible code
# from __future__ import absolute_import, division, print_function, unicode_literals
from __future__ import division    # This way: 3 / 2 == 1.5; 3 // 2 == 1

# ----------------------------------------------------------------------------
# Import section
#
import sys
import logging
import multiprocessing
import time
from functools import wraps


# -----------------------------------------------------------------------------
# class LastTime to be used with rate_limited
#
class LastTime:

    def __init__(self, name='LT'):
        # Init variables to None
        self.name = name
        self.ratelock = None
        self.cnt = None
        self.last_time_called = None

        # Instantiate control variables
        self.ratelock = multiprocessing.Lock()
        self.cnt = multiprocessing.Value('i', 0)
        self.last_time_called = multiprocessing.Value('d', 0.0)

        logging.debug('\t__init__: name=[{!s}]'.format(self.name))

    def acquire(self):
        self.ratelock.acquire()

    def release(self):
        self.ratelock.release()

    def set_last_time_called(self):
        self.last_time_called.value = time.time()
        # self.debug('set_last_time_called')

    def get_last_time_called(self):
        return self.last_time_called.value

    def add_cnt(self):
        self.cnt.value += 1

    def get_cnt(self):
        return self.cnt.value

    def debug(self, debugname='LT'):
        now=time.time()
        logging.debug('___Rate name:[{!s}] '
                      'debug=[{!s}] '
                      '\n\t        cnt:[{!s}] '
                      '\n\tlast_called:{!s} '
                      '\n\t  timenow():{!s} '
                      .format(self.name,
                              debugname,
                              self.cnt.value,
                              time.strftime(
                                '%T.{}'
                                .format(str(self.last_time_called.value -
                                            int(self.last_time_called.value))
                                            .split('.')[1][:3]),
                                time.localtime(self.last_time_called.value)),
                              time.strftime(
                                '%T.{}'
                                .format(str(now -
                                            int(now))
                                            .split('.')[1][:3]),
                                time.localtime(now))))


# -----------------------------------------------------------------------------
# rate_limited
#
# retries execution of a function
def rate_limited(ratelimit_dict):

    LT = LastTime('rate_limited')

    def decorate(func):
        LT.acquire()
        if LT.get_last_time_called() == 0:
            LT.set_last_time_called()
        LT.debug('DECORATE')
        LT.release()

        @wraps(func)
        def rate_limited_function(*args, **kwargs):

            # Not very good way, but actually it works
            api_short_name = args[1]
            max_per_second = ratelimit_dict.get(api_short_name, ratelimit_dict.get('default'))
            min_interval = 1.0 / max_per_second

            logging.debug('___Rate_limited f():[{!s}]: '
                            'Max_per_Second:[{!s}]'
                            .format(func.__name__, max_per_second))

            try:
                LT.acquire()
                LT.add_cnt()
                xfrom = time.time()

                elapsed = xfrom - LT.get_last_time_called()
                left_to_wait = min_interval - elapsed
                logging.debug('___Rate f():[{!s}] '
                              'cnt:[{!s}] '
                              '\n\tlast_called:{!s} '
                              '\n\t time now():{!s} '
                              'elapsed:{:6.2f} '
                              'min:{!s} '
                              'to_wait:{:6.2f}'
                              .format(func.__name__,
                                      LT.get_cnt(),
                                      time.strftime(
                                            '%T',
                                            time.localtime(
                                                LT.get_last_time_called())),
                                      time.strftime('%T',
                                                    time.localtime(xfrom)),
                                      elapsed,
                                      min_interval,
                                      left_to_wait))
                if left_to_wait > 0:
                    time.sleep(left_to_wait)

                ret = func(*args, **kwargs)

                LT.debug('OVER')
                LT.set_last_time_called()
                LT.debug('NEXT')

            except Exception as ex:
                # CODING: To be changed once reportError is on a module
                sys.stderr.write('+++000 '
                                 'Exception on rate_limited_function: [{!s}]\n'
                                 .format(ex))
                sys.stderr.flush()
                # reportError(Caught=True,
                #              CaughtPrefix='+++',
                #              CaughtCode='000',
                #              CaughtMsg='Exception on rate_limited_function',
                #              exceptUse=True,
                #              # exceptCode=ex.code,
                #              exceptMsg=ex,
                #              NicePrint=False,
                #              exceptSysInfo=True)
                raise
            finally:
                LT.release()
            return ret

        return rate_limited_function

    return decorate
