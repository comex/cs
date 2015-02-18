import sys, os, re, hashlib
from optparse import OptionParser
import construct
import macho, macho_cs
from construct_try import construct_try

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-H', '--hashes', dest='hashes', action='store_true', default=False, help='print the actual hashes')
    parser.add_option('', '--verify-hashes', dest='verify_hashes', action='store_true', default=False, help='and verify them')
    parser.add_option('-c', '--certs', dest='certs', default=None, help='save the certificates blob (DER-encoded PKCS#7) to a file')
    options, args = parser.parse_args()
    filename = args[0]

    should_print = not options.hashes and not options.verify_hashes

    if not options.hashes:
        macho_cs.Hashes_ = construct.OnDemand(macho_cs.Hashes_)

    f = open(filename, 'rb')
    data = construct_try(lambda: macho.MachOOrFat.parse_stream(f)).data
    try:
        data = data.FatArch[0].MachO
    except:
        pass
    for cmd in data.commands:
        if cmd.cmd == 'LC_CODE_SIGNATURE':
            if should_print:
                print cmd
            if options.certs:
                try:
                    for blob in cmd.data.blob.data.BlobIndex:
                        if blob.blob.magic == 'CSMAGIC_BLOBWRAPPER':
                            open(options.certs, 'wb').write(blob.blob.data.data.value)
                            break
                except:
                    pass
            if options.verify_hashes:
                cd = cmd.data.blob.data.BlobIndex[0].blob.data
                end_offset = (cd.codeLimit + 0xfff) & ~0xfff
                start_offset = end_offset - cd.nCodeSlots * 0x1000
                hashes = cd.hashes
                if hasattr(hashes, 'value'): hashes = hashes.value
                for i in xrange(cd.nCodeSlots):
                    expected = hashes[cd.nSpecialSlots + i]
                    f.seek(start_offset + 0x1000 * i)
                    actual_data = f.read(min(0x1000, cd.codeLimit - f.tell()))
                    actual = hashlib.sha1(actual_data).digest()
                    print '[%s] exp=%s act=%s' % (
                        ('bad', 'ok ')[expected == actual],
                        expected.encode('hex'),
                        actual.encode('hex')
                    )

