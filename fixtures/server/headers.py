# Representative server-side cookie abstractions; not executed by scans.
response.set_cookie('session_id', generated_session)
headers.append('Set-Cookie', 'visitor=synthetic; Domain=.example.test; Path=/; Secure; HttpOnly')
