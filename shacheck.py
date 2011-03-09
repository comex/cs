# usage: python shacheck.py file sha1
# very slow
import sys, hashlib
data = open(sys.argv[1], 'rb').read()
assert len(sys.argv[2]) == 40
sha = sys.argv[2].decode('hex')
for i in xrange(len(data)):
    print i, '/', len(data)
    for j in xrange(0, len(data) - i):
        if hashlib.sha1(buffer(data, i, j)).digest() == sha:
        #if hashlib.sha1(data[i:i+j]).digest() == sha:
            print 'got it: %d+%d' % (i, j)
            sys.exit(0)
sys.exit(1)
