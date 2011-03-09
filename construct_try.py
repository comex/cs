import sys
def construct_try(func):
    try:
        return func()
    except Exception, e:
        tb = sys.exc_traceback
        while tb is not None:
            self = tb.tb_frame.f_locals.get('self')
            if self is not None:
                print >> sys.stderr, 'self tb:', self
            tb = tb.tb_next
        raise

