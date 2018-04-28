from __future__ import print_function

import json
from Cookie import SimpleCookie

from cryptography.fernet import Fernet, InvalidToken


#__all__ = ['SessionMiddleware']


class Session(dict):

    def __init__(self, values={}):
        super(Session, self).__init__(values)

        self._dirty = False
        self._valid = True

    @property
    def dirty(self):
        return self._dirty

    @property
    def valid(self):
        return self._valid

    def touch(self):
        self._dirty = True

    def __setitem__(self, key, value):
        super(Session, self).__setitem__(key, value)
        self.touch()

    def __delitem__(self, key):
        super(Session, self).__delitem__(key)
        self.touch()

    def clear(self):
        super(Session, self).clear()
        self.touch()

    def pop(self, key, *args):
        result = super(Session, self).pop(key, *args)
        self.touch()
        return result

    def popitem(self):
        result = super(Session, self).popitem()
        self.touch()
        return result

    def setdefault(self, key, *args):
        result = super(Session, self).setdefault(key, *args)
        self.touch()
        return result

    def update(self, other=None):
        super(Session, self).update(other)
        self.touch()
        return result

    def invalidate(self):
        self.clear()
        self._valid = False


class SessionSerializer(object):

    def encode(self, session):
        return json.dumps(session, separators=(',', ':'), sort_keys=True)

    def decode(self, input):
        return json.loads(input)


class SessionMiddleware(object):

    def __init__(self, application, secret_key,
                 environ_key='flup.session',
                 cookie_key='flup.session.id',
                 cookie_domain=None, # Default: current domain
                 cookie_path=None, # Default: current SCRIPT_NAME
                 cookie_expires=None, # Default: end-of-session
                 httponly=True,
                 secure=None # Default: True if https, False otherwise
    ):
        self._application = application
        self._secret_key = secret_key
        self._environ_key = environ_key
        self._cookie_key = cookie_key
        self._cookie_domain = cookie_domain
        self._cookie_path = cookie_path
        self._cookie_expires = cookie_expires
        self._httponly = httponly
        self._secure = secure

        self._session_cls = Session # TODO configurable
        self._serializer = SessionSerializer() # TODO configurable
        self._crypto = Fernet(secret_key)

    def __call__(self, environ, start_response):
        session = None

        # Attempt to load existing cookie from environ
        C = SimpleCookie(environ.get('HTTP_COOKIE'))
        morsel = C.get(self._cookie_key, None)
        if morsel is not None:
            try:
                # Attempt to decrypt and decode
                session_data = self._crypto.decrypt(morsel.value)
                session = self._session_cls(self._serializer.decode(session_data))
            except InvalidToken:
                pass

        if session is None:
            session = self._session_cls()

        environ[self._environ_key] = session

        def my_start_response(status, headers, exc_info=None):
            self._add_cookie(environ, session, headers)
            return start_response(status, headers, exc_info)

        return self._application(environ, my_start_response)

    def _add_cookie(self, environ, session, headers):
        if not session.dirty: return

        encoded_data = self._serializer.encode(session)
        session_data = self._crypto.encrypt(encoded_data)

        # Check size since generally headers should be < 4KB
        data_limit = 4000
        if len(session_data) > data_limit:
            print('WARNING: Encoded session data exceeds {} bytes'.format(data_limit), file=environ['wsgi.errors'])

        C = SimpleCookie()
        name = self._cookie_key
        C[name] = session_data
        if self._cookie_domain:
            C[name]['domain'] = self._cookie_domain

        # If no cookie path is configured, use this requests's SCRIPT_NAME
        cookie_path = self._cookie_path
        if cookie_path is None:
            cookie_path = environ['SCRIPT_NAME']
            if not cookie_path:
                cookie_path = '/'
        C[name]['path'] = cookie_path

        if self._httponly:
            C[name]['httponly'] = True

        # If secure isn't configured, base it off current URL scheme
        if (self._secure is None and environ['wsgi.url_scheme'] == 'https') \
           or self._secure:
            C[name]['secure'] = True

        if self._cookie_expires is not None:
            C[name]['expires'] = self._cookie_expires

        if not session.valid:
            C[name]['expires'] = -365*24*60*60 # A year ago
            C[name]['max-age'] = 0

        headers.append(('Set-Cookie', C[name].OutputString()))
