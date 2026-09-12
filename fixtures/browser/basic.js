// Values are synthetic fixture data, never real credentials.
document.cookie = 'theme=dark; Path=/; SameSite=Lax';
const current = document.cookie;
cookieStore.set('visitor', 'synthetic'); cookieStore.delete('obsolete');
document.cookie = name + '=' + value;
const docs = 'document.cookie is an API';
