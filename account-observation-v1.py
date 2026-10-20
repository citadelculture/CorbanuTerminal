"""Pure exact local-record observation. No account APIs or subprocess calls."""
import hashlib
import re
import xml.etree.ElementTree as ET

MAX_BYTES = 16384
NOT_FOUND = b'<dscl_cmd> DS Error: -14136 (eDSRecordNotFound)\n'
ATTRIBUTES = ('RecordName', 'GeneratedUID', 'UniqueID', 'PrimaryGroupID')


def classify_directory(stdout, stderr, row, owned):
    error = {'state': 'error', 'absent': False}
    if type(stdout) is not bytes or type(stderr) is not bytes:
        return error
    if len(stdout) > MAX_BYTES or len(stderr) > MAX_BYTES:
        return error
    if (row.get('captureComplete') is not True or row.get('groupGone') is not True
            or row.get('stopReason') is not None):
        return error
    for key, data in (('stdout', stdout), ('stderr', stderr)):
        capture = row.get('capture', {}).get(key, {})
        if (capture.get('truncated') is not False
                or capture.get('observedBytes') != len(data)
                or capture.get('retainedBytes') != len(data)
                or row.get(key + 'Bytes') != len(data)
                or row.get(key + 'Sha256') != hashlib.sha256(data).hexdigest()):
            return error
    if (re.fullmatch(r'_ncap[0-9]{8,16}', owned.get('name', '')) is None
            or re.fullmatch(r'[0-9A-F]{8}-(?:[0-9A-F]{4}-){3}[0-9A-F]{12}',
                            owned.get('uuid', '')) is None
            or type(owned.get('uid')) is not int or not 60000 <= owned['uid'] < 64000
            or owned.get('gid') != owned['uid']):
        return error
    if row.get('exitCode') == 56 and stdout == b'' and stderr == NOT_FOUND:
        return {'state': 'absent', 'absent': True}
    if row.get('exitCode') != 0 or stderr or not stdout:
        return error
    # Allow the standard XML plist declaration, never entities or arbitrary DTDs.
    clean = stdout.replace(
        b'<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        b'"http://www.apple.com/DTDs/PropertyList-1.0.dtd">', b'')
    if b'<!' in clean:
        return error
    try:
        plist = ET.fromstring(clean)
        if plist.tag != 'plist' or plist.attrib != {'version': '1.0'} or len(plist) != 1:
            return error
        dictionary = plist[0]
        if dictionary.tag != 'dict' or dictionary.attrib or len(dictionary) != 8:
            return {'state': 'identity-mismatch', 'absent': False}
        values = {}
        for key, value in zip(dictionary[::2], dictionary[1::2]):
            if (key.tag != 'key' or key.attrib or len(key)
                    or key.text in values or value.tag != 'array' or value.attrib
                    or len(value) != 1 or value[0].tag != 'string'
                    or value[0].attrib or len(value[0])):
                return {'state': 'identity-mismatch', 'absent': False}
            values[key.text] = value[0].text
        expected = dict(zip(('dsAttrTypeStandard:' + k for k in ATTRIBUTES),
                            (owned['name'], owned['uuid'], str(owned['uid']), str(owned['gid']))))
        matches = {key: values.get('dsAttrTypeStandard:' + key) == expected['dsAttrTypeStandard:' + key]
                   for key in ATTRIBUTES}
        same = set(values) == set(expected) and all(matches.values())
        return {'state': 'owned-present' if same else 'identity-mismatch',
                'absent': False, 'identityMatches': matches}
    except (ET.ParseError, ValueError, TypeError):
        return error


def removed(libc, directory):
    return (libc.get('state') == 'absent' and libc.get('removed') is True
            and directory.get('state') == 'absent' and directory.get('absent') is True)
