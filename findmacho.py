import sys, os
import cs

fp = open(sys.argv[1], 'rb')
fp.seek(4)
subfiles = sys.argv[1] + '_subfiles'
if not os.path.exists(subfiles): os.mkdir(subfiles)
while True:
    s = fp.read(1024)
    if s == '': break
    z = s.find('\xce\xfa\xed\xfe')
    if z != -1:
        offset = fp.tell() - 1024 + z
        print 'offset %d:' % offset,
        fp.seek(offset)
        try:
            result = cs.MachO.parse_stream(fp)
        except:
            print 'error'
        else:
            maxpos = max(cmd['data']['fileoff'] + cmd['data']['filesize'] for cmd in result['LoadCommand'] if cmd['cmd'] == 'LC_SEGMENT')
            print maxpos
            fp.seek(offset)
            open('%s/%d' % (subfiles, offset), 'wb').write(fp.read(maxpos))
