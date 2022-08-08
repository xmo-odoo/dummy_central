import base64
import itertools
import hashlib
import string

import pytest
import requests

def blob(data):
    data = data.encode()
    return hashlib.sha1(b'blob %d\0%s' % (len(data), data)).hexdigest()

def test_create_blob(repo):
    data = "blobish"
    b0 = repo.create_git_blob(data, "utf-8")
    # reloads because pygithub doesn't do that correctly as of this writing
    b0 = repo.get_git_blob(b0.sha)
    assert b0.encoding == 'base64', "github always returns base64"
    assert b0.size == len(data), "check that the size is that of the decoded payload"
    assert b0.sha == blob(data)
    assert base64.b64decode(b0.content) == b'blobish'

    b1 = repo.create_git_blob(base64.b64encode(b"blobish").decode(), "base64")
    # NOTE: works because pygithub only compares the url
    assert b0 == b1

    contents = "Blòb created by PyGithub"
    b0 = repo.create_git_blob(contents, 'utf-8')
    b1 = repo.create_git_blob(contents, '')
    assert b0.sha == b1.sha
    assert b1.sha == blob(contents)

    # utf8:   'Oh l\xc3\xa0 l\xc3\xa0'
    # latin1: 'Oh l\xe0 l\xe0'
    content = 'Oh là là'
    weird = repo.create_git_blob(content, 'latin1')
    weird = repo.get_git_blob(weird.sha)
    assert base64.b64decode(weird.content) == content.encode('utf-8'),\
        "github treats any `encoding` other than base64 as `utf-8`, which" \
        " effectively means literal text"
    assert weird.sha == blob(content)

@pytest.mark.parametrize('n', range(35, 40))
def test_blob_encoding(repo, n):
    """github apparently returns the result of Base64.encode64: 
    newline-terminated segments of 60 encoded characters
    """
    val = 'a'*n
    b = repo.create_git_blob(val, 'utf-8')
    blob_obj = requests.get(b.url).json()
    assert blob_obj['size'] == n
    encoded = base64.b64encode(val.encode())
    formatted = ''.join(
        encoded[i:i+60].decode() + '\n'
        for i in range(0, len(encoded), 60)
    )
    assert blob_obj['content'] == formatted


chars = {
    c: v
    for v, c in enumerate(
        string.ascii_uppercase + string.ascii_lowercase + string.digits + '+/'
    )
}
def get_data(bs, *, padding_stop=False):
    for c in bs:
        v = chars.get(c)
        if v is not None or (c == '=' and padding_stop):
            return v

def decode64(input):
    buf = bytearray()
    bs = iter(input)
    while True:
        a = get_data(bs)
        if a is None:
            break
        b = get_data(bs)
        if b is None:
            break
        buf.append(a << 2 | b >> 4)
        c = get_data(bs, padding_stop=True)
        if c is None:
            break
        buf.append((b << 4 | c >> 2) & 0xff)
        d = get_data(bs, padding_stop=True)
        if d is None:
            break
        buf.append((c << 6 | d) & 0xff)

    return bytes(buf)

@pytest.mark.parametrize('encoded,transcoded', [
    ("a", b''),
    ("ab", b'aQ=='),
    ("abc", b'abc='),
    ("abcd", b'abcd'),
    ("abcde", b'abcd'),
    ("abcdef", b'abcdeQ=='),
    ("a=bcdefg", b'abcdefg='),
    ("a=b=cdefg", b'aQ=='),
    ("ab=cdefg", b'aQ=='),
    ("abc=defg", b'abc='),
    ("abcd=efg", b'abcdefg='),
])
def test_decode64(encoded, transcoded):
    """Ruby's decode64 is even more lenient (and weird) than Python's:

    - it skips all non-base64 content
    - it stops when the source ends (so doesn't care *at all* for padding)
    - it stops iff the 3rd or 4th character of a chunk (of 4) is an `=`, 
      otherwise it skips the `=`
    """
    assert base64.b64encode(decode64(encoded)) == transcoded

@pytest.mark.parametrize('encoded', [
    "this is a test",
    '<a href="https://www.mozilla.org/en-US/"><img src="mozilla-image.png" alt="Mozilla homepage"></a>',
    '{ "face": "😐" }',
    'a=b=cdefg',
])
def test_blob_decoding(repo, encoded):
    """github apparently decodes base64 using Ruby's Base64::decode64 which
    is similar to but even more lenient than Python's b64decode
    """
    b = repo.get_git_blob(repo.create_git_blob(encoded, "base64").sha)
    assert decode64(encoded) == base64.b64decode(b.content)