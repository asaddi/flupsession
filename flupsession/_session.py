import json
import warnings
import zlib

from six.moves.http_cookies import SimpleCookie, CookieError
from six.moves import cPickle as pickle

from cryptography.fernet import Fernet, InvalidToken


__all__ = ['SessionMiddleware']


class Session(dict):

    def __init__(self, values={}):
        super(Session, self).__init__(values)

        self._dirty = False
        self._valid = True
        self.path = None

    @property
    def dirty(self):
        return self._dirty

    @property
    def valid(self):
        return self._valid

    def save(self):
        self._dirty = True

    def invalidate(self):
        self.clear()
        self._valid = False

    def __setitem__(self, key, value):
        super(Session, self).__setitem__(key, value)
        self.save()

    def __delitem__(self, key):
        super(Session, self).__delitem__(key)
        self.save()

    def clear(self):
        super(Session, self).clear()
        self.save()

    def pop(self, key, *args):
        result = super(Session, self).pop(key, *args)
        self.save()
        return result

    def popitem(self):
        result = super(Session, self).popitem()
        self.save()
        return result

    def setdefault(self, key, *args):
        result = super(Session, self).setdefault(key, *args)
        self.save()
        return result

    def update(self, other=None):
        super(Session, self).update(other)
        self.save()
        return result


class SessionSerializerException(Exception):
    pass


class JSONSessionSerializer(object):

    def encode(self, session):
        return json.dumps(session, separators=(',', ':'), sort_keys=True)

    def decode(self, input):
        try:
            return json.loads(input)
        except Exception as e:
            raise SessionSerializerException(e)


class PickleSessionSerializer(object):

    def encode(self, session):
        # Only serialize a plain dict
        return pickle.dumps(dict(session), protocol=pickle.HIGHEST_PROTOCOL)

    def decode(self, input):
        try:
            return pickle.loads(input)
        except pickle.PickleError as e:
            raise SessionSerializerException(e)


class SessionMiddleware(object):

    def __init__(self, application,
                 secret_key=None, # Default: randomly generated
                 environ_key='flup.session',
                 cookie_key='flup.session.id',
                 cookie_domain=None, # Default: current domain
                 cookie_path=None, # Default: current SCRIPT_NAME
                 cookie_expires=None, # Default: end-of-session
                 httponly=True,
                 secure=None, # Default: True if https, False otherwise
                 session_ttl=None, # Default: Same as cookie_expires
                 serializer='json',
                 compression=-1,
    ):
        self._application = application
        if secret_key is None:
            # Only good for cookies for that expire at end-of-session
            secret_key = Fernet.generate_key()
            # TODO emit warning if cookie_expires is set
        self._secret_key = secret_key
        self._environ_key = environ_key

        self._cookie_key = cookie_key
        self._cookie_domain = cookie_domain
        self._cookie_path = cookie_path
        self._cookie_expires = cookie_expires
        self._httponly = httponly
        self._secure = secure

        self._session_ttl = session_ttl is not None and session_ttl or cookie_expires

        if serializer == 'json':
            self._serializer = JSONSessionSerializer()
        elif serializer == 'pickle':
            self._serializer = PickleSessionSerializer()
        else:
            raise ValueError('Unknown serializer')

        if compression is not None:
            def compress(data):
                return zlib.compress(data, compression)
            self._compressor = (compress, zlib.decompress)
        else:
            def noop(data):
                return data
            self._compressor = (noop, noop)

        self._session_cls = Session # TODO configurable
        self._crypto = Fernet(secret_key)

    def __call__(self, environ, start_response):
        session_holder = []
        def session_factory():
            if not session_holder:
                session_holder[:] = [self._load_session(environ)]
            return session_holder[0]

        environ[self._environ_key] = session_factory

        def my_start_response(status, headers, exc_info=None):
            self._add_cookie(environ, session_holder, headers)
            return start_response(status, headers, exc_info)

        return self._application(environ, my_start_response)

    def _load_session(self, environ):
        session = None

        try:
            # Attempt to load existing cookie from environ
            C = SimpleCookie(environ.get('HTTP_COOKIE'))
            morsel = C.get(self._cookie_key)
        except CookieError:
            morsel = None

        if morsel is not None:
            try:
                # Attempt to decrypt and decode
                session_data = self._crypto.decrypt(morsel.value, ttl=self._session_ttl)
                session = self._session_cls(self._serializer.decode(self._compressor[1](session_data)))
            except (InvalidToken, SessionSerializerException, zlib.error):
                # Start anew
                session = self._session_cls()
                # And ensure invalid cookie is overwritten
                session.save()
            session.path = morsel['path']

        if session is None:
            session = self._session_cls()
            session.path = self._cookie_path

        return session

    def _add_cookie(self, environ, session_holder, headers):
        if not session_holder: return
        session = session_holder[0]
        if not session.dirty: return

        encoded_data = self._compressor[0](self._serializer.encode(session))
        session_data = self._crypto.encrypt(encoded_data)

        # Check size since generally headers should be < 4KB
        data_limit = 4000
        if len(session_data) > data_limit:
            warnings.warn('Encoded session data exceeds {} bytes'.format(data_limit))

        C = SimpleCookie()
        name = self._cookie_key
        C[name] = session_data

        if self._cookie_domain:
            C[name]['domain'] = self._cookie_domain

        # If no cookie path is configured, use this requests's SCRIPT_NAME
        cookie_path = session.path
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
