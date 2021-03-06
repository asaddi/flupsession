from flupsession import SessionMiddleware


def test_app(environ, start_response):
    session = environ['flup.session']()

    path_info = environ.get('PATH_INFO', '')
    if path_info == '/reset':
        session.invalidate()
        start_response('200 OK', [
            ('Content-Type', 'text/plain')
        ])
        return ['reset\n']

    if 'count' not in session:
        session['count'] = 0

    session['count'] = session['count'] + 1

    start_response('200 OK', [
        ('Content-Type', 'text/plain')
    ])
    return ['count is now {}\n'.format(session['count'])]


app = SessionMiddleware(test_app)
