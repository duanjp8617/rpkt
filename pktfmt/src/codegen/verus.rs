//! Opt-in Verus byte-range certificates extracted from the emitted Rust AST.
//! These prove bounds, not bitfield/endian semantics or handwritten extensions.
use std::collections::BTreeSet;
use std::io::Write;
use syn::visit::Visit;

#[derive(Default)]
struct Accesses {
    ranges: BTreeSet<(u64, u64, bool)>,
    errors: Vec<String>,
}

fn literal(expr: &syn::Expr) -> Option<u64> {
    match expr {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Int(i),
            ..
        }) => i.base10_parse().ok(),
        _ => None,
    }
}

fn path_is(expr: &syn::Expr, name: &str) -> bool {
    matches!(expr, syn::Expr::Path(p) if p.path.is_ident(name))
}

/// Fail closed if the generated packet parsers stop checking the original
/// chunk before constructing a packet. This is a syntactic linkage check, not
/// a semantic proof of arbitrary Rust. Dynamic-length checks are not covered.
pub fn check_packet_parse_gates(rust: &str, minimum: usize) -> Result<(), String> {
    let ast = syn::parse_file(rust).map_err(|e| e.to_string())?;
    let mut seen = BTreeSet::new();
    for item in &ast.items {
        let syn::Item::Impl(block) = item else {
            continue;
        };
        for item in &block.items {
            let syn::ImplItem::Fn(f) = item else { continue };
            let name = f.sig.ident.to_string();
            if !["parse", "parse_from_cursor", "parse_from_cursor_mut"].contains(&name.as_str()) {
                continue;
            }
            let checked = (|| -> Option<()> {
                let syn::Stmt::Local(binding) = f.block.stmts.first()? else {
                    return None;
                };
                let syn::Pat::Ident(variable) = &binding.pat else {
                    return None;
                };
                let syn::Expr::MethodCall(len) = &*binding.init.as_ref()?.expr else {
                    return None;
                };
                let syn::Expr::MethodCall(chunk) = &*len.receiver else {
                    return None;
                };
                if len.method != "len"
                    || chunk.method != "chunk"
                    || !len.args.is_empty()
                    || !chunk.args.is_empty()
                    || !path_is(&chunk.receiver, "buf")
                {
                    return None;
                }
                let syn::Stmt::Expr(syn::Expr::If(guard), _) = f.block.stmts.get(1)? else {
                    return None;
                };
                let syn::Expr::Binary(cond) = &*guard.cond else {
                    return None;
                };
                if !matches!(cond.op, syn::BinOp::Lt(_))
                    || !path_is(&cond.left, &variable.ident.to_string())
                    || literal(&cond.right)? != minimum as u64
                    || guard.else_branch.is_some()
                    || guard.then_branch.stmts.len() != 1
                {
                    return None;
                }
                let syn::Stmt::Expr(syn::Expr::Return(ret), _) = &guard.then_branch.stmts[0] else {
                    return None;
                };
                let syn::Expr::Call(err) = &**ret.expr.as_ref()? else {
                    return None;
                };
                if !path_is(&err.func, "Err")
                    || err.args.len() != 1
                    || !path_is(&err.args[0], "buf")
                {
                    return None;
                }
                Some(())
            })();
            if checked.is_none() {
                return Err(format!(
                    "unsupported or weakened fixed-header gate in {name}"
                ));
            }
            seen.insert(name);
        }
    }
    if seen.len() != 3 {
        return Err("missing checked packet constructor".into());
    }
    Ok(())
}

impl<'ast> Visit<'ast> for Accesses {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.to_string();
        if method == "get_unchecked" || method == "get_unchecked_mut" {
            let range = if call.args.len() != 1 {
                None
            } else {
                match &call.args[0] {
                    syn::Expr::Range(r) if matches!(r.limits, syn::RangeLimits::HalfOpen(_)) => r
                        .start
                        .as_deref()
                        .and_then(literal)
                        .zip(r.end.as_deref().and_then(literal)),
                    expr => literal(expr).and_then(|n| n.checked_add(1).map(|end| (n, end))),
                }
            };
            match range {
                Some((start, end)) => {
                    self.ranges.insert((start, end, method.ends_with("_mut")));
                }
                None => self.errors.push(format!(
                    "unsupported index in {method}; no certificate emitted"
                )),
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

/// Consume precisely the generated packet/group Rust, including widened flag
/// loads, pair accesses, and structural-length reads/writes. Do not infer ranges
/// solely from schema fields: optimized accesses can cover more than one field.
pub fn generate(name: &str, minimum: usize, rust: &str, out: &mut dyn Write) -> Result<(), String> {
    let ast = syn::parse_file(rust).map_err(|e| format!("Verus access extraction: {e}"))?;
    let mut accesses = Accesses::default();
    accesses.visit_file(&ast);
    if !accesses.errors.is_empty() {
        return Err(accesses.errors.join("; "));
    }
    writeln!(
        out,
        "// Bounds certificates for {name}; fixed contiguous minimum {minimum}."
    )
    .map_err(|e| e.to_string())?;
    writeln!(out, "pub mod {name} {{\nuse vstd::prelude::*;\nuse crate::buffers::PktBuf;\nuse crate::packet::{{Parsed, field_range}};\nverus! {{")
        .map_err(|e| e.to_string())?;
    writeln!(
        out,
        "pub fn parse<B: PktBuf>(buf: B) -> (out: Option<Parsed<B>>)\n\
        requires buf.valid(),\n\
        ensures out.is_some() <==> {minimum} <= buf.chunk_end() - buf.position(),\n\
            out.is_some() ==> out.unwrap().valid() && out.unwrap().fixed_len() == {minimum},\n\
        {{ Parsed::parse(buf, {minimum}) }}"
    )
    .map_err(|e| e.to_string())?;
    for (id, (start, end, mutable)) in accesses.ranges.into_iter().enumerate() {
        let kind = if mutable { "write" } else { "read" };
        // Intentionally no host-side assertion end <= minimum. Verus must prove
        // this proposition; an erroneous generator offset must fail verification.
        writeln!(
            out,
            "// runtime-access {name} {kind} {start} {end}\n\
            pub proof fn range_{id}<B: PktBuf>(p: &Parsed<B>)\n\
            requires p.valid(), p.fixed_len() == {minimum},\n\
            ensures {start} <= {end} <= p.fixed_len(),\n\
                0 <= p.position() + {start} <= p.position() + {end} <= p.bytes().len(),\n\
            {{ field_range(p, {start}, {end}); }}"
        )
        .map_err(|e| e.to_string())?;
        if mutable {
            writeln!(out, "pub fn write_{id}<B: PktBuf>(p: &mut Parsed<B>, i: usize, byte: u8)\n\
                requires old(p).valid(), old(p).fixed_len() == {minimum}, i < {end} - {start},\n\
                ensures final(p).valid(), final(p).fixed_len() == {minimum},\n\
                    final(p).bytes() == old(p).bytes().update(old(p).position() + {start} + i, byte),\n\
                {{ proof {{ range_{id}(p); }} p.write({start} + i, byte); }}")
                .map_err(|e| e.to_string())?;
        } else {
            writeln!(
                out,
                "pub fn read_{id}<B: PktBuf>(p: &Parsed<B>, i: usize) -> (byte: u8)\n\
                requires p.valid(), p.fixed_len() == {minimum}, i < {end} - {start},\n\
                ensures byte == p.bytes()[p.position() + {start} + i],\n\
                {{ proof {{ range_{id}(p); }} p.read({start} + i) }}"
            )
            .map_err(|e| e.to_string())?;
        }
    }
    writeln!(out, "}} // verus!\n}}").map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn extracts_actual_scalar_pair_and_mutable_ranges() {
        let code = "fn f(b: &[u8], m: &mut [u8]) { unsafe { b.get_unchecked(1); b.get_unchecked(4..12); m.get_unchecked_mut(7..9); } }";
        let mut out = Vec::new();
        generate("P", 12, code, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        for expected in ["P read 1 2", "P read 4 12", "P write 7 9"] {
            assert!(out.contains(expected));
        }
    }
    #[test]
    fn unknown_indices_fail_closed() {
        for index in ["n", "..2", "1..=2", "1..", "1 + 2"] {
            let code =
                format!("fn f(b: &[u8], n: usize) {{ unsafe {{ b.get_unchecked({index}); }} }}");
            assert!(generate("P", 8, &code, &mut Vec::new()).is_err());
        }
    }
    #[test]
    fn out_of_bounds_is_a_solver_obligation_not_silently_dropped() {
        let mut out = Vec::new();
        generate(
            "P",
            8,
            "fn f(b: &[u8]) { unsafe { b.get_unchecked(7..9); } }",
            &mut out,
        )
        .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("P read 7 9"));
        assert!(out.contains("p.fixed_len() == 8"));
    }

    #[test]
    fn parse_gate_linkage_rejects_weakened_or_missing_guards() {
        use crate::{parser::PacketParser, token::Tokenizer};
        let p = parse_with_error!(
            PacketParser,
            Tokenizer::new("packet P { header=[a=Field{bit=64}] }")
        )
        .unwrap();
        let header = super::super::HeaderGen::new(&p);
        let mut rust = Vec::new();
        super::super::PktGen::new(&header).code_gen(&mut rust);
        let rust = String::from_utf8(rust).unwrap();
        check_packet_parse_gates(&rust, 8).unwrap();
        assert!(
            check_packet_parse_gates(&rust.replace("chunk_len < 8", "chunk_len < 7"), 8).is_err()
        );
        assert!(check_packet_parse_gates(
            &rust.replace("return Err(buf);", "return Ok(Self { buf });"),
            8
        )
        .is_err());
    }
}
