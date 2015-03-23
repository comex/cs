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

    should_print = not options.verify_hashes

    if not options.hashes:
        macho_cs.Hashes_ = construct.OnDemand(macho_cs.Hashes_)

    f = open(filename, 'rb')
    odata = construct_try(lambda: macho.InputFile.parse_stream(f)).data
    try:
        data = odata.FatArch[0].MachO
    except:
        data = odata

    def do_blob(sblob):
        if should_print:
            print sblob
        if options.certs:
            try:
                for blob in sblob.data.BlobIndex:
                    if blob.blob.magic == 'CSMAGIC_BLOBWRAPPER':
                        open(options.certs, 'wb').write(blob.blob.data.data.value)
                        break
            except:
                pass
        if options.verify_hashes:
            cd = sblob.data.BlobIndex[0].blob.data
            end_offset = cd.codeLimit
            if hasattr(odata, 'FatArch'):
                end_offset += odata.FatArch[0].offset
            start_offset = ((end_offset + 0xfff) & ~0xfff)- cd.nCodeSlots * 0x1000
            hashes = cd.hashes
            if hasattr(hashes, 'value'): hashes = hashes.value
            for i in xrange(cd.nCodeSlots):
                expected = hashes[cd.nSpecialSlots + i]
                f.seek(start_offset + 0x1000 * i)
                actual_data = f.read(min(0x1000, end_offset - f.tell()))
                actual = hashlib.sha1(actual_data).digest()
                print '[%s] exp=%s act=%s' % (
                    ('bad', 'ok ')[expected == actual],
                    expected.encode('hex'),
                    actual.encode('hex')
                )

    if hasattr(data, 'commands'):
        for cmd in data.commands:
            if cmd.cmd == 'LC_CODE_SIGNATURE':
                do_blob(cmd.data.blob)
    else:
        do_blob(data)
