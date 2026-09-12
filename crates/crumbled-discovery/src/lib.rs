//! Sorted, bounded filesystem discovery. No target code is executed.
mod lexer;
use crumbled_core::*;
use lexer::{Kind, Token};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};

pub const MAX_SOURCE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;
const EXT: &[&str] = &[
    "js", "jsx", "ts", "tsx", "mjs", "cjs", "rs", "py", "php", "go", "java", "conf", "yaml", "yml",
    "toml", "html", "vue", "svelte", "astro",
];
const EXCLUDED: &[&str] = &[
    ".git",
    ".agents",
    ".codex",
    "target",
    "node_modules",
    ".crumbled",
    ".amber",
    ".next",
    "dist",
    "build",
    ".venv",
    "vendor",
];

pub struct LexicalDetector;
impl Detector for LexicalDetector {
    fn detect(&self, source: &Path) -> Result<Vec<Finding>, String> {
        scan_repository(source, "application")
    }
}
pub fn scan_repository(source: &Path, application: &str) -> Result<Vec<Finding>, String> {
    let mut files = Vec::new();
    let mut visited = 0;
    collect(source, &mut files, &mut visited, 0)?;
    files.sort();
    let base = if source.is_dir() {
        source
    } else {
        source.parent().unwrap_or(Path::new("."))
    };
    let mut findings = Vec::new();
    for path in files {
        let metadata =
            fs::symlink_metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if !metadata.is_file() {
            return Err(format!("source changed type: {}", path.display()));
        }
        let text = read_bounded(&path)?;
        let relative = path.strip_prefix(base).map_err(|e| e.to_string())?;
        let relative = relative
            .to_str()
            .ok_or("non-UTF-8 source path is unsupported")?;
        let timestamp = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|t| t.as_secs());
        findings.extend(scan_text(relative, &text, application, timestamp));
    }
    Ok(findings)
}

pub fn read_bounded(path: &Path) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "expected regular file, refusing symlink/special file: {}",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_SOURCE_BYTES {
        return Err(format!(
            "source exceeds {MAX_SOURCE_BYTES} byte analysis budget: {}",
            path.display()
        ));
    }
    String::from_utf8(bytes).map_err(|e| format!("{} is not UTF-8: {e}", path.display()))
}

fn collect(
    path: &Path,
    out: &mut Vec<PathBuf>,
    visited: &mut usize,
    depth: usize,
) -> Result<(), String> {
    *visited += 1;
    if *visited > MAX_ENTRIES || depth > 128 {
        return Err("repository exceeds traversal budget".into());
    }
    let metadata = fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "symlink is outside the supported analysis scope: {}",
            path.display()
        ));
    }
    if metadata.is_file() {
        if path
            .extension()
            .and_then(|x| x.to_str())
            .is_some_and(|e| EXT.contains(&e))
        {
            out.push(path.to_owned());
        } else if depth == 0 {
            return Err(format!("unsupported source type: {}", path.display()));
        }
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(format!("special file is unsupported: {}", path.display()));
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
        if entries.len() + *visited >= MAX_ENTRIES {
            return Err("repository exceeds traversal budget".into());
        }
        entries.push(entry.map_err(|e| e.to_string())?);
    }
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| EXCLUDED.contains(&name) || name == "crumbled.lock")
        {
            continue;
        }
        collect(&entry.path(), out, visited, depth + 1)?;
    }
    Ok(())
}

/// Public fixture entry point. Timestamp is source metadata; it does not affect IDs.
pub fn scan_text(
    path: &str,
    source: &str,
    application: &str,
    timestamp: Option<u64>,
) -> Vec<Finding> {
    let extension = Path::new(path)
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or("");
    let tokens = lexer::tokenize(
        source,
        matches!(extension, "py" | "php" | "conf" | "yaml" | "yml" | "toml"),
    );
    let digest = sha256(source.as_bytes());
    let mut out = Vec::new();
    let browser = matches!(
        extension,
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" | "html" | "vue" | "svelte" | "astro"
    );
    for (i, token) in tokens.iter().enumerate() {
        let mut operation = Operation::Read;
        let mut literal = None;
        let mut api = "";
        let mut header_cookie = false;
        if browser
            && word(&tokens, i, "document")
            && !preceded_by_member(&tokens, i)
            && let Some(end) = member(&tokens, i, "cookie")
        {
            api = "document.cookie";
            if symbol(&tokens, end, "=")
                && !symbol(&tokens, end + 1, "=")
                && !symbol(&tokens, end + 1, ">")
            {
                operation = Operation::Create;
                literal = constant_expression(&tokens, end + 1, &[";", ")", "}"]);
                header_cookie = true;
            } else if symbol(&tokens, end, "+") && symbol(&tokens, end + 1, "=") {
                operation = Operation::Modify;
            }
        }
        if browser && word(&tokens, i, "cookieStore") && !preceded_by_member(&tokens, i) {
            for (method, op) in [
                ("set", Operation::Create),
                ("get", Operation::Read),
                ("getAll", Operation::Read),
                ("delete", Operation::Delete),
            ] {
                if let Some(end) =
                    member(&tokens, i, method).filter(|end| symbol(&tokens, *end, "("))
                {
                    api = match op {
                        Operation::Create => "cookieStore.set",
                        Operation::Delete => "cookieStore.delete",
                        _ => "cookieStore.get",
                    };
                    operation = op;
                    literal = constant_expression(&tokens, end + 1, &[",", ")"]);
                }
            }
        }
        if token.kind == Kind::Word
            && matches!(
                token.text.as_str(),
                "set_cookie" | "add_cookie" | "setCookie" | "setcookie"
            )
            && symbol(&tokens, i + 1, "(")
        {
            api = "server cookie abstraction";
            operation = Operation::Create;
            literal = constant_expression(&tokens, i + 2, &[",", ")"]);
        }
        // Header names must be exact literals or constants in an argument/config context.
        // Arbitrary Cookie identifiers and prose strings do not count as HTTP access.
        if !(browser && i >= 2 && word(&tokens, i - 2, "document") && symbol(&tokens, i - 1, "["))
            && ((token.kind == Kind::Literal
                && (token.text.eq_ignore_ascii_case("set-cookie")
                    || token.text.eq_ignore_ascii_case("cookie")))
                || (token.kind == Kind::Word
                    && matches!(token.text.as_str(), "SET_COOKIE" | "COOKIE")))
            && (i > 0
                && (symbol(&tokens, i - 1, "(")
                    || symbol(&tokens, i - 1, "[")
                    || symbol(&tokens, i - 1, ",")
                    || symbol(&tokens, i - 1, "{")))
        {
            let set = token.text.eq_ignore_ascii_case("set-cookie") || token.text == "SET_COOKIE";
            api = if set {
                "HTTP Set-Cookie"
            } else {
                "HTTP Cookie"
            };
            operation = if set {
                Operation::Receive
            } else {
                Operation::Send
            };
            if set && (symbol(&tokens, i + 1, ",") || symbol(&tokens, i + 1, ":")) {
                literal = constant_expression(&tokens, i + 2, &[",", ")", "]", "}"]);
                header_cookie = true;
            }
        }
        if api.is_empty() {
            continue;
        }
        let mut cookie = CookieIdentity {
            name: literal.map(str::to_owned),
            domain: None,
            path: None,
            origin: format!("repository:{path}"),
            application: application.into(),
            attributes: BTreeMap::new(),
        };
        if header_cookie {
            cookie.name = None;
            if let Some(value) = literal {
                parse_cookie(value, &mut cookie);
            }
        }
        // Distinguish independent dynamic accesses; unresolved names must not be merged.
        if cookie.name.is_none() {
            cookie.origin = format!("repository:unresolved:{path}:{}", token.offset);
        }
        let evidence = Evidence {
            source: format!("detector:{api}:v2"),
            method: Method::StaticRule,
            confidence: Confidence::Possible,
            location: Some(Location {
                path: PathBuf::from(path),
                line: token.line,
                column: token.column,
                byte_offset: token.offset,
            }),
            timestamp,
            content_sha256: digest.clone(),
            detail: format!("Lexical {api} access; execution and purpose are unproven"),
        };
        let policy_evidence = Evidence {
            detail: "No explicit user policy matches this identity; purpose remains unknown".into(),
            ..evidence.clone()
        };
        let cookie_id = cookie.id();
        out.push(Finding {
            id: format!(
                "behaviour:{}",
                identity_hash(&[
                    application,
                    path,
                    &token.offset.to_string(),
                    api,
                    &cookie_id
                ])
            ),
            cookie,
            operation,
            technical_classification: api.into(),
            classification: Classification {
                value: PermissionClass::Unknown,
                confidence: Confidence::Unknown,
                method: Method::StaticRule,
                evidence: vec![policy_evidence],
            },
            confidence: Confidence::Possible,
            declared: true,
            observed: false,
            correlated: false,
            evidence: vec![evidence],
        });
    }
    out
}
fn word(tokens: &[Token], i: usize, text: &str) -> bool {
    tokens
        .get(i)
        .is_some_and(|t| t.kind == Kind::Word && t.text == text)
}
fn symbol(tokens: &[Token], i: usize, text: &str) -> bool {
    tokens
        .get(i)
        .is_some_and(|t| t.kind == Kind::Symbol && t.text == text)
}
fn preceded_by_member(tokens: &[Token], i: usize) -> bool {
    i > 0 && symbol(tokens, i - 1, ".")
}
fn member(tokens: &[Token], i: usize, property: &str) -> Option<usize> {
    if symbol(tokens, i + 1, ".") && word(tokens, i + 2, property) {
        Some(i + 3)
    } else if symbol(tokens, i + 1, "[")
        && tokens
            .get(i + 2)
            .is_some_and(|t| t.kind == Kind::Literal && t.text == property)
        && symbol(tokens, i + 3, "]")
    {
        Some(i + 4)
    } else {
        None
    }
}
fn constant_expression<'a>(tokens: &'a [Token], i: usize, delimiters: &[&str]) -> Option<&'a str> {
    let token = tokens.get(i)?;
    if token.kind != Kind::Literal {
        return None;
    }
    if tokens.get(i + 1).is_none_or(|t| {
        (t.kind == Kind::Symbol && delimiters.contains(&t.text.as_str()))
            || (t.line > token.line
                && t.kind == Kind::Word
                && matches!(
                    t.text.as_str(),
                    "const" | "let" | "var" | "return" | "document" | "cookieStore"
                ))
    }) {
        Some(&token.text)
    } else {
        None
    }
}
fn parse_cookie(value: &str, cookie: &mut CookieIdentity) {
    let mut parts = value.split(';');
    let Some((name, _)) = parts.next().and_then(|p| p.split_once('=')) else {
        return;
    };
    let name = name.trim();
    if name.is_empty() || name.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return;
    }
    cookie.name = Some(name.into());
    for part in parts {
        let (key, value) = part.trim().split_once('=').unwrap_or((part.trim(), "true"));
        let key = key.to_ascii_lowercase();
        let value = value.trim();
        match key.as_str() {
            "domain" => cookie.domain = Some(value.trim_start_matches('.').to_ascii_lowercase()),
            "path" => cookie.path = Some(value.into()),
            "secure" | "httponly" | "samesite" | "max-age" | "expires" | "partitioned" => {
                cookie.attributes.insert(key, value.into());
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scan(s: &str) -> Vec<Finding> {
        scan_text("app.js", s, "shop", None)
    }
    #[test]
    fn comments_and_prose_are_not_behaviours() {
        assert!(scan("// document.cookie = 'a=b'\n/* cookieStore.set('a','b') */\nconst help = \"document.cookie\"; const Cookie = 1;").is_empty());
    }
    #[test]
    fn reads_writes_and_same_line_calls_are_distinct() {
        let f = scan(
            "document.cookie = 'a=secret; Domain=.A.test; Path=/'; const c = document['cookie']; cookieStore.delete('a'); cookieStore.get('b');",
        );
        assert_eq!(f.len(), 4);
        assert_eq!(f[0].operation, Operation::Create);
        assert_eq!(f[1].operation, Operation::Read);
        assert_eq!(f[2].operation, Operation::Delete);
        assert_eq!(f[0].cookie.name.as_deref(), Some("a"));
        assert_eq!(f[0].cookie.domain.as_deref(), Some("a.test"));
        assert_eq!(f[0].cookie.path.as_deref(), Some("/"));
        assert!(!format!("{:?}", f).contains("secret"));
    }
    #[test]
    fn multiline_and_comparisons() {
        let f = scan(
            "document /* gap */ . cookie\n = 'x=y';\nif (document.cookie === 'x=y') {}\ncookieStore\n.set(\n'x', 'y');",
        );
        assert_eq!(f.len(), 3);
        assert_eq!(f[1].operation, Operation::Read);
        assert_eq!(f[2].cookie.name.as_deref(), Some("x"));
    }
    #[test]
    fn dynamic_names_are_never_partial_literals() {
        let f = scan(
            "document.cookie = 'session=' + input; cookieStore.set(name, value); document.cookie = `x=${value}`;",
        );
        assert_eq!(f.len(), 3);
        assert!(f.iter().all(|f| f.cookie.name.is_none()));
        assert_ne!(f[0].cookie.id(), f[2].cookie.id());
        assert!(
            scan("document.cookie = 'session='\n + input;")[0]
                .cookie
                .name
                .is_none()
        );
    }
    #[test]
    fn http_header_evidence_is_specific() {
        let f = scan_text(
            "server.py",
            "# set_cookie('bad','x')\nresponse.set_cookie('sid', secret)\nheaders['Set-Cookie'] = value\nobj = 'Cookie'",
            "api",
            None,
        );
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].cookie.name.as_deref(), Some("sid"));
        let f = scan_text(
            "server.rs",
            "response.insert_header((\"Set-Cookie\", \"sid=redacted; HttpOnly; Secure\"));",
            "api",
            None,
        );
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].cookie.name.as_deref(), Some("sid"));
    }
    #[test]
    fn unicode_locations_and_arbitrary_lexical_input_are_safe() {
        let f = scan("const word = 'é'; document.cookie = 'x=y';");
        assert_eq!(f[0].evidence[0].location.as_ref().unwrap().column, 19);
        let alphabet = [
            'é', '中', '😀', '\\', '\'', '"', '`', '/', '*', '\n', '$', '{', '}', '\0', 'a',
        ];
        let mut state = 42_u64;
        for _ in 0..500 {
            let mut input = String::new();
            for _ in 0..100 {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                input.push(alphabet[(state >> 32) as usize % alphabet.len()]);
            }
            let one = scan(&input);
            assert_eq!(one, scan(&input));
        }
    }
}
