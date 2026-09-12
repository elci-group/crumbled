//! A bounded lexical layer, not an AST or proof of reachability.
#[derive(Clone, Debug, PartialEq)]
pub enum Kind {
    Word,
    Literal,
    Dynamic,
    Symbol,
}
#[derive(Clone, Debug)]
pub struct Token {
    pub text: String,
    pub kind: Kind,
    pub offset: usize,
    pub line: usize,
    pub column: usize,
}

pub fn tokenize(source: &str, hash_comments: bool) -> Vec<Token> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let (mut i, mut line, mut column) = (0, 1, 1);
    while i < bytes.len() {
        let start = i;
        let start_line = line;
        let start_column = column;
        let mut advance = |end: usize| {
            for character in source[start..end].chars() {
                if character == '\n' {
                    line += 1;
                    column = 1;
                } else {
                    column += 1;
                }
            }
        };
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            advance(i);
            continue;
        }
        if (bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'/'))
            || (hash_comments && bytes[i] == b'#')
        {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            advance(i);
            continue;
        }
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i < bytes.len() && !(bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/')) {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            advance(i);
            continue;
        }
        let (kind, text) = if matches!(bytes[i], b'\'' | b'"' | b'`') {
            let quote = bytes[i];
            i += 1;
            let content_start = i;
            let mut dynamic = false;
            while i < bytes.len() && bytes[i] != quote {
                if bytes[i] == b'\\' {
                    dynamic = true;
                    i += 1;
                    if i < bytes.len() {
                        i += 1;
                    }
                } else {
                    if bytes[i] == b'$' && bytes.get(i + 1) == Some(&b'{') {
                        dynamic = true;
                    }
                    i += 1;
                }
            }
            let content = source[content_start..i].to_string();
            if i < bytes.len() {
                i += 1;
            } else {
                dynamic = true;
            }
            (
                if dynamic {
                    Kind::Dynamic
                } else {
                    Kind::Literal
                },
                content,
            )
        } else if bytes[i].is_ascii_alphanumeric()
            || bytes[i] == b'_'
            || bytes[i] == b'$'
            || bytes[i] >= 128
        {
            i += 1;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric()
                    || matches!(bytes[i], b'_' | b'$')
                    || bytes[i] >= 128)
            {
                i += 1;
            }
            (Kind::Word, source[start..i].to_string())
        } else {
            i += 1;
            (Kind::Symbol, source[start..i].to_string())
        };
        advance(i);
        tokens.push(Token {
            text,
            kind,
            offset: start,
            line: start_line,
            column: start_column,
        });
    }
    tokens
}
