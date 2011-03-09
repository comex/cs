import sys, os, re
from optparse import OptionParser
import macho, macho_cs
import construct
from construct_try import construct_try

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-H', '--hashes', dest='hashes', action='store_true', default=False, help='print the actual hashes')
    options, args = parser.parse_args()
    filename = args[0]

    if not options.hashes:
        macho_cs.Hashes_ = construct.Struct('Hashes')

    f = open(filename, 'rb')
    data = construct_try(lambda: macho.MachOOrFat.parse_stream(f))
    print data
