use regex::Regex;
use serde::Deserialize;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const FILES: [&'static str; 5] = [
    "oui-sources/oui.csv",
    "oui-sources/cid.csv",
    "oui-sources/iab.csv",
    "oui-sources/mam.csv",
    "oui-sources/oui36.csv",
];

#[derive(Debug, Deserialize)]
struct Record {
    #[serde(rename = "Registry")]
    _registry: String,
    #[serde(rename = "Assignment")]
    assignment: String,
    #[serde(rename = "Organization Name")]
    org_name: String,
    #[serde(rename = "Organization Address")]
    _org_addr: String,
}

struct Assignment {
    addr: u64,
    prefix_len: usize,
    name: String,
}

fn read_records() -> Result<Vec<Assignment>> {
    let mut out = Vec::new();
    for file in FILES {
        println!("cargo:rerun-if-changed={file}");
        let mut f = csv::Reader::from_reader(BufReader::new(File::open(file)?));
        for rec in f.deserialize() {
            let Record {
                _registry,
                assignment,
                org_name,
                _org_addr,
            } = rec?;
            let mut addr = u64::from_str_radix(&assignment, 16)?;
            addr <<= assignment.len() * 4;
            out.push(Assignment {
                addr: addr,
                prefix_len: assignment.len() * 4,
                name: org_name,
            })
        }
    }

    out.sort_by(|l, r| l.addr.cmp(&r.addr));

    Ok(out)
}

struct Abbreviator {
    ws: Regex,
    punct: Regex,
    and: Regex,
    quals: Regex,
}

impl Abbreviator {
    fn new() -> Result<Self> {
        Ok(Self {
            ws: Regex::new(r"\s+")?,
            punct: Regex::new(r#"[\"',./:()]"#)?,
            and: Regex::new(r" [&] ")?,
            quals: Regex::new(
                r"(?i)\W(a +s|ab|ag|b ?v|closed joint stock company|co|company|corp|corporation|de c ?v|gmbh|holding|inc|incorporated|jsc|kg|k k|limited|llc|ltd|n ?v|oao|of|open joint stock company|ooo|oü|oy|oyj|plc|pty|pvt|s ?a ?r ?l|s ?a|s ?p ?a|sp ?k|s ?r ?l|systems|the|zao|z ?o ?o) ",
            )?,
        })
    }

    fn abbrv(&self, name: &str) -> Result<String> {
        let orig: Vec<_> = self
            .ws
            .replace_all(name, " ")
            .split(' ')
            .map(|word| -> String {
                let mut word: String = word.into();
                let mut copy = word.clone();
                copy.make_ascii_uppercase();
                if copy == word {
                    if let Some(tmp) = word.get_mut(1..) {
                        tmp.make_ascii_lowercase();
                    }
                }
                word.into()
            })
            .collect();
        let orig = orig.join(" ");
        let name = format!(" {} ", orig);
        let name = self.punct.replace_all(&name, " ");
        let name = self.and.replace_all(&name, " ");
        let name = self.quals.replace_all(&name, " ");
        let mut name = self.ws.replace_all(&name, "");
        if name.is_empty() {
            name = orig.into();
        }
        if let Some(name) = name.get(0..8) {
            Ok(name.into())
        } else {
            Ok(name.into())
        }
    }
}

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=build.rs");

    let records = read_records()?;

    let abbrv = Abbreviator::new()?;

    let mut out = BufWriter::new(File::create(
        std::path::Path::new(&std::env::var("OUT_DIR")?).join("oui_assignments.rs"),
    )?);
    write!(out, "const ASSIGNMENTS: &'static [Assignment] = &[\n")?;

    let quote = Regex::new(r#"["]"#)?;
    for rec in records {
        let addr = rec.addr.to_be_bytes();
        write!(out, "    Assignment {{\n")?;
        write!(out, "        range: Subnet::new(MacAddress::new([0x{:02X}, 0x{:02X}, 0x{:02X}, 0x{:02X}, 0x{:02X}, 0x{:02X}]), {}),\n", addr[2], addr[3], addr[4], addr[5], addr[6], addr[7], rec.prefix_len)?;
        write!(out, "        abbrv: \"{}\",\n", abbrv.abbrv(&rec.name)?)?;
        write!(
            out,
            "        name: \"{}\",\n",
            quote.replace_all(&rec.name, "\\\"")
        )?;
        write!(out, "    }},\n")?;
    }

    write!(out, "];\n")?;

    Ok(())
}
