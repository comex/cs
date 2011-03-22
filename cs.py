import sys, os, re
from optparse import OptionParser
import macho, macho_cs
import construct
from construct_try import construct_try

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-H', '--hashes', dest='hashes', action='store_true', default=False, help='print the actual hashes')
    parser.add_option('-c', '--certs', dest='certs', default=None, help='save the certificates blob (DER-encoded PKCS#7) to a file')
    options, args = parser.parse_args()
    filename = args[0]

    if not options.hashes:
        macho_cs.Hashes_ = construct.Struct('Hashes')

    f = open(filename, 'rb')
    data = construct_try(lambda: macho.MachOOrFat.parse_stream(f))
    for cmd in data.data.commands:
        if cmd.cmd == 'LC_CODE_SIGNATURE':
            print cmd
            if options.certs:
                try:
                    for blob in cmd.data.blob.data.BlobIndex:
                        if blob.blob.magic == 'CSMAGIC_BLOBWRAPPER':
                            open(options.certs, 'wb').write(blob.blob.data.data.value)
                            break
                except:
                    pass

