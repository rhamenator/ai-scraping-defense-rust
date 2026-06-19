use chrono::Utc;
use rand::{distributions::Alphanumeric, prelude::*};

const PREFIXES: &[&str] = &[
    "analytics_bundle",
    "vendor_lib",
    "core_framework",
    "ui_component_pack",
    "runtime_utils",
    "auth_client_sdk",
    "graph_rendering_engine",
];

pub fn generate_page(path_hint: Option<&str>) -> String {
    generate_page_with_content(path_hint, None)
}

pub fn generate_page_with_content(path_hint: Option<&str>, content: Option<String>) -> String {
    let mut rng = thread_rng();
    let title = random_name(&mut rng, 10);
    let links = generate_fake_links(9, 3);
    let paragraphs = content.unwrap_or_else(|| {
        (0..8)
            .map(|_| format!("<p>{}</p>", fake_paragraph(&mut rng)))
            .collect::<Vec<_>>()
            .join("\n")
    });
    let link_html = links
        .iter()
        .map(|link| {
            let text = link
                .rsplit('/')
                .next()
                .unwrap_or("resource")
                .split('.')
                .next()
                .unwrap_or("resource")
                .replace(['_', '-'], " ");
            format!(r#"<li><a href="{link}">{text}</a></li>"#)
        })
        .collect::<Vec<_>>()
        .join("\n");
    let path_meta = path_hint.unwrap_or("/");
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="robots" content="noindex, nofollow">
  <meta name="generator" content="AI Scraping Defense Rust Tarpit">
  <title>{title} - System Documentation</title>
  <style>
    body {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background:#f4f4f1; color:#2f3437; padding:2rem; line-height:1.6; }}
    h1 {{ border-bottom:1px solid #bbb; padding-bottom:.5rem; }}
    a {{ color:#255f85; }}
    .footer-link {{ visibility:hidden; }}
  </style>
</head>
<body data-path="{path_meta}">
  <h1>{title}</h1>
  {paragraphs}
  <h2>Further Reading:</h2>
  <ul>{link_html}</ul>
  <a class="footer-link" href="/internal-docs/admin">Admin Console</a>
</body>
</html>"#
    )
}

pub fn generate_fake_links(count: usize, depth: usize) -> Vec<String> {
    let mut rng = thread_rng();
    let mut links = Vec::with_capacity(count);
    for _ in 0..count {
        let kind = ["page", "js", "data", "styles"][rng.gen_range(0..4)];
        let dir_count = rng.gen_range(0..=depth);
        let dirs = (0..dir_count)
            .map(|_| {
                let len = rng.gen_range(5..=8);
                random_name(&mut rng, len)
            })
            .collect::<Vec<_>>();
        let extension = match kind {
            "page" => "html",
            "js" => "js",
            "data" => {
                if rng.gen_bool(0.5) {
                    "json"
                } else {
                    "xml"
                }
            }
            _ => "css",
        };
        let mut path = format!("/tarpit/{kind}/");
        if !dirs.is_empty() {
            path.push_str(&dirs.join("/"));
            path.push('/');
        }
        path.push_str(&random_name(&mut rng, 10));
        path.push('.');
        path.push_str(extension);
        links.push(path);
    }
    links
}

pub fn realistic_js_filename() -> String {
    let mut rng = thread_rng();
    let prefix = PREFIXES[rng.gen_range(0..PREFIXES.len())];
    format!("{prefix}_{}.js", random_name(&mut rng, 8))
}

pub fn fake_js_module(target_size: usize) -> String {
    let mut rng = thread_rng();
    let name = realistic_js_filename();
    let mut content = format!(
        "// Fake module: {name}\n// Generated: {}\n(function() {{\n",
        Utc::now().to_rfc3339()
    );
    for _ in 0..rng.gen_range(5..=18) {
        let name_len = rng.gen_range(4..=10);
        let var_name = random_alpha(&mut rng, name_len);
        let value = rng.gen_range(0..1000);
        content.push_str(&format!("  var {var_name} = {value};\n"));
    }
    content.push_str("})();\n");
    while content.len() < target_size {
        content.push_str("// ");
        content.push_str(&random_alpha(&mut rng, 60));
        content.push('\n');
    }
    content
}

fn fake_paragraph(rng: &mut ThreadRng) -> String {
    let words = [
        "adaptive",
        "runtime",
        "policy",
        "crawler",
        "routing",
        "matrix",
        "cache",
        "tenant",
        "validation",
        "heuristic",
        "sequence",
        "signal",
        "archive",
        "manifest",
        "operator",
        "threshold",
    ];
    let len = rng.gen_range(42..=76);
    let mut out = String::new();
    for idx in 0..len {
        if idx > 0 {
            out.push(' ');
        }
        out.push_str(words[rng.gen_range(0..words.len())]);
    }
    out.push('.');
    out
}

fn random_name(rng: &mut ThreadRng, len: usize) -> String {
    rng.sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn random_alpha(rng: &mut ThreadRng, len: usize) -> String {
    (0..len)
        .map(|_| (b'a' + rng.gen_range(0..26)) as char)
        .collect()
}
