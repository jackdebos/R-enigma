//! Human reports and exclusive, collision-safe report delivery (§2.4).
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

pub(crate) struct Context<'a> {
    pub cwd: &'a Path,
    pub request: &'a str,
    pub stdin: bool,
    pub explicit: Option<&'a str>,
    pub disabled: bool,
    pub argv: Vec<String>,
}

pub(crate) fn resume(argv: &[String]) -> String {
    let mut args = argv[..argv.len().min(1)].to_vec();
    let mut available = false;
    // Walk option/value pairs so a value named -c is never rewritten.
    let mut i = 1;
    while i < argv.len() {
        let pair = argv[i..].iter().take(2).cloned();
        match argv[i].as_str() {
            "--checkpoint" | "-c" => {
                args.push("--resume".into());
                args.extend(argv.get(i + 1).cloned());
                available = true;
                i += 2;
            }
            "--resume" | "-r" => {
                args.extend(pair);
                available = true;
                i += 2;
            }
            // Files this run created would make the continuation fail as
            // already existing; drop them (`--events -` stays).
            "--events" | "-e" if argv.get(i + 1).is_some_and(|v| v != "-") => i += 2,
            "--report" | "-o" => i += 2,
            "--request" | "-i" | "--events" | "-e" | "--threads" | "-t" | "--cancel-file"
            | "-x" => {
                args.extend(pair);
                i += 2;
            }
            _ => {
                args.push(argv[i].clone());
                i += 1;
            }
        }
    }
    if !available {
        return "not available (run with --checkpoint to make a search resumable)".into();
    }
    args.iter()
        .map(|s| {
            if !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_./=:".contains(&b))
            {
                s.clone()
            } else {
                format!("'{}'", s.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn text(v: &Value) -> &str {
    v.as_str().expect("validated wire string")
}
fn grouped(label: &str, value: &str) -> String {
    let mut out = label.to_owned();
    for (i, c) in value.chars().enumerate() {
        if i > 0 && i % 50 == 0 {
            out.push('\n');
            out.push_str(&" ".repeat(label.len()));
        } else if i > 0 && i % 5 == 0 {
            out.push(' ');
        }
        out.push(c);
    }
    out.push('\n');
    out
}
fn key(configuration: &Value, indent: &str) -> String {
    let slots = configuration["slots"]
        .as_array()
        .expect("validated configuration");
    let wheels = slots
        .iter()
        .map(|s| {
            let wheel = text(&s["wheel"]);
            match s.get("pairs") {
                Some(pairs) => {
                    let pairs = pairs
                        .as_array()
                        .expect("validated wiring")
                        .iter()
                        .map(|pair| format!("{}{}", text(&pair[0]), text(&pair[1])))
                        .collect::<Vec<_>>()
                        .join(" ");
                    format!("{wheel} (pairs: {pairs})")
                }
                None => wheel.to_owned(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    let rings = slots.iter().map(|s| text(&s["ring"])).collect::<String>();
    let positions = slots
        .iter()
        .map(|s| text(&s["position"]))
        .collect::<String>();
    let pairs = configuration["plugboard"]
        .as_array()
        .expect("validated plugboard");
    let pairs = if pairs.is_empty() {
        "none".into()
    } else {
        pairs
            .iter()
            .map(|p| format!("{}{}", text(&p[0]), text(&p[1])))
            .collect::<Vec<_>>()
            .join(" ")
    };
    format!("{indent}Wheels:     {wheels}\n{indent}Rings:      {rings}\n{indent}Positions:  {positions}\n{indent}Plugboard:  {pairs}\n")
}
fn gap(a: &Value, b: &Value) -> String {
    let a: i128 = text(a).parse().expect("Q32");
    let b: i128 = text(b).parse().expect("Q32");
    let magnitude = a.abs_diff(b);
    let fraction = ((magnitude & 0xffff_ffff) * 1_000_000 + (1 << 31)) >> 32;
    format!(
        "{}.{:06}",
        (magnitude >> 32) + fraction / 1_000_000,
        fraction % 1_000_000
    )
}
pub(crate) fn attack(
    result: &Value,
    reason: &str,
    selected: &str,
    request: &str,
    resume: &str,
    measure: &str,
) -> String {
    let status = match reason {
        "cancelled" => "CANCELLED",
        "outer_slice_end" => "empty slice",
        _ => "completed",
    };
    let seconds = text(&result["elapsed_ms"])
        .parse::<u128>()
        .expect("elapsed")
        / 1000;
    let mut out = format!("Enigma attack report\nStatus:       {status}\nRequest:      {request}\nStarted:      {}\nFinished:     {}\nDuration:     {:02}:{:02}:{:02}\nOuter keys:   {} of {selected}\nEvaluations:  {}\nThreads:      {}\nMeasure:      {measure}\n\n", text(&result["started_at"]), text(&result["finished_at"]), seconds/3600, seconds/60%60, seconds%60, text(&result["counters"]["outers_completed"]), text(&result["counters"]["evaluations_completed"]), text(&result["threads"]));
    if let Some(crib) = result.get("crib") {
        let positions = crib["positions"].as_array().expect("crib positions");
        out.push_str(&format!(
            "Crib:         {}\nPositions:    {}",
            text(&crib["text"]),
            positions.len()
        ));
        if !positions.is_empty() && positions.len() <= 10 {
            out.push_str(&format!(
                " ({})",
                positions.iter().map(text).collect::<Vec<_>>().join(", ")
            ));
        }
        out.push_str(&format!(
            "\nSettings:     {}\nStops:        {}\n\n",
            text(&crib["settings"]),
            text(&crib["stops"])
        ));
    }
    let hold = result["hold"].as_array().expect("hold");
    if hold.is_empty() {
        out.push_str("No candidates.\n");
    }
    for (i, candidate) in hold.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&format!(
            "#{}  score {}",
            i + 1,
            text(&candidate["score"]["measured"])
        ));
        if let Some(next) = hold.get(i + 1) {
            out.push_str(&format!(
                "  (gap to #{}: {})",
                i + 2,
                gap(
                    &candidate["score"]["ranking_q32"],
                    &next["score"]["ranking_q32"]
                )
            ));
        }
        out.push('\n');
        out.push_str(&key(&candidate["configuration"], "    "));
        if let Some(position) = candidate.get("crib_position") {
            out.push_str(&format!("    Crib position: {}\n", text(position)));
        }
        out.push_str(&grouped("    Plaintext:  ", text(&candidate["plaintext"])));
    }
    if reason == "cancelled" {
        out.push_str(&format!("\nResume:       {resume}\n"));
    }
    out
}
pub(crate) fn transform(
    job: &Value,
    output: &str,
    request: &str,
    started: &str,
    finished: &str,
) -> String {
    format!("Enigma transform report\nRequest:      {request}\nStarted:      {started}\nFinished:     {finished}\nDirection:    {}\n{}{}{}", text(&job["direction"]), key(&job["configuration"], ""), grouped("Input:      ", text(&job["text"])), grouped("Output:     ", output))
}

impl Context<'_> {
    pub fn deliver(&self, report: &str, human: bool, print: bool) -> std::process::ExitCode {
        if print && human {
            if let Err(error) = io::stdout().lock().write_all(report.as_bytes()) {
                eprintln!("error: failed to write stdout: {error}");
                return std::process::ExitCode::FAILURE;
            }
        }
        if self.disabled || (!human && self.explicit.is_none()) {
            return std::process::ExitCode::SUCCESS;
        }
        match self.save(report, &crate::now_ts()) {
            Ok((name, directory)) => {
                eprintln!(
                    "Report {name:?} saved successfully in {}",
                    directory.display()
                );
                std::process::ExitCode::SUCCESS
            }
            Err((path, error)) => {
                eprintln!("error: failed to save report {path:?}: {error}");
                std::process::ExitCode::FAILURE
            }
        }
    }
    fn save(
        &self,
        report: &str,
        timestamp: &str,
    ) -> Result<(String, std::path::PathBuf), (String, io::Error)> {
        let timestamp = timestamp.replace(['-', ':'], "");
        let stem = if self.stdin {
            format!("enigma-{timestamp}")
        } else {
            Path::new(self.request)
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned()
        };
        let mut index = 0u64;
        loop {
            let name = self
                .explicit
                .map(str::to_owned)
                .unwrap_or_else(|| match index {
                    0 => format!("{stem}.report.txt"),
                    // The stdin stem already holds the timestamp: only number it.
                    n if self.stdin => format!("{stem}-{}.report.txt", n + 1),
                    1 => format!("{stem}.{timestamp}.report.txt"),
                    n => format!("{stem}.{timestamp}-{n}.report.txt"),
                });
            let path = self.cwd.join(&name);
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    file.write_all(report.as_bytes())
                        .and_then(|()| file.flush())
                        .map_err(|e| (name.clone(), e))?;
                    // Name the saved file and its own directory, not the given path.
                    let file_name = path
                        .file_name()
                        .map_or_else(|| name.clone(), |f| f.to_string_lossy().into_owned());
                    let directory = path
                        .parent()
                        .unwrap_or(self.cwd)
                        .canonicalize()
                        .map_err(|e| (name.clone(), e))?;
                    return Ok((file_name, directory));
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && self.explicit.is_none() => {
                    index += 1
                }
                Err(e) => return Err((name, e)),
            }
        }
    }
}

/// Retain only report facts; never accumulate progress or alter event bytes.
pub(crate) struct Capture<'a, W> {
    pub writer: &'a mut W,
    pub started: Option<Value>,
    pub result: Option<Value>,
    pub done: Option<Value>,
}
impl<'a, W> Capture<'a, W> {
    pub fn new(writer: &'a mut W) -> Self {
        Self {
            writer,
            started: None,
            result: None,
            done: None,
        }
    }
}
impl<W: Write> Write for Capture<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writer.write_all(bytes)?;
        let value: Value = serde_json::from_slice(bytes).map_err(io::Error::other)?;
        match value["event"].as_str() {
            Some("started") => self.started = Some(value),
            Some("result") => self.result = Some(value),
            Some("done") => self.done = Some(value),
            _ => {}
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn transform_layout_direction_complete_pairs_and_grouping() {
        let job = json!({"direction":"decrypt", "text":"ABCDEF", "configuration":{"slots":[{"wheel":"B", "ring":"A", "position":"V"},{"wheel":"I", "ring":"B", "position":"J"}],"plugboard":[["A","B"],["C","D"]]}});
        assert_eq!(transform(&job, "FEDCBA", "data/request.json", "start", "end"), "Enigma transform report\nRequest:      data/request.json\nStarted:      start\nFinished:     end\nDirection:    decrypt\nWheels:     B I\nRings:      AB\nPositions:  VJ\nPlugboard:  AB CD\nInput:      ABCDE F\nOutput:     FEDCB A\n");
        assert_eq!(gap(&json!("0"), &json!("515396076")), "0.120000");
        assert_eq!(
            gap(&json!("-8589934592"), &json!("-4294967296")),
            "1.000000"
        );
        assert_eq!(grouped("Input:      ", ""), "Input:      \n");
        assert_eq!(
            resume(&[
                "./enigma".into(),
                "-c".into(),
                "a-_.=/path:42".into(),
                "".into()
            ]),
            "./enigma --resume a-_.=/path:42 ''"
        );
    }
    #[test]
    fn grouping_symbols_partial_and_continuation() {
        assert_eq!(grouped("Input:      ", "αβγδεζη"), "Input:      αβγδε ζη\n");
        assert_eq!(
            grouped("    Plaintext:  ", &"é".repeat(51)),
            format!(
                "    Plaintext:  {}\n                é\n",
                vec!["é".repeat(5); 10].join(" ")
            )
        );
    }
    #[test]
    fn resume_drops_file_outputs_that_would_already_exist() {
        let args = [
            "enigma",
            "r.json",
            "--events",
            "run.jsonl",
            "-o",
            "mine.txt",
            "-c",
            "ck",
            "-e",
            "x.jsonl",
            "--report",
            "y.txt",
            "-t",
            "2",
        ]
        .map(str::to_owned);
        assert_eq!(resume(&args), "enigma r.json --resume ck -t 2");
        let piped = ["enigma", "-e", "-", "-i", "-", "-r", "ck"].map(str::to_owned);
        assert_eq!(resume(&piped), "enigma -e - -i - -r ck");
    }
    #[test]
    fn resume_rewrites_and_quotes_posix() {
        for flag in ["--checkpoint", "-c", "--resume", "-r"] {
            let args = [
                "my program",
                flag,
                "a'b",
                "--request",
                "a;$é",
                "--no-report",
            ]
            .map(str::to_owned);
            let flag = if flag == "-r" { "-r" } else { "--resume" };
            assert_eq!(
                resume(&args),
                format!("'my program' {flag} 'a'\\''b' --request 'a;$é' --no-report")
            );
        }
        assert_eq!(
            resume(&["enigma".into()]),
            "not available (run with --checkpoint to make a search resumable)"
        );
    }
    #[test]
    fn exact_layout_gaps_key_and_status() {
        let candidate = json!({"configuration":{"slots":[{"wheel":"B","ring":"A","position":"V"},{"wheel":"I","ring":"B","position":"J"}],"plugboard":[]},"plaintext":"ABCDEFG","score":{"measured":"-8.333021","ranking_q32":"-4294967296"}});
        let mut second = candidate.clone();
        second["score"]["ranking_q32"] = json!("-8589934592");
        let mut result = json!({"started_at":"start","finished_at":"end","elapsed_ms":"70000","threads":"6","counters":{"outers_completed":"2","evaluations_completed":"42"},"hold":[candidate,second]});
        let out = attack(&result, "completed", "3", "file.json", "cmd", "ic");
        assert_eq!(out, "Enigma attack report\nStatus:       completed\nRequest:      file.json\nStarted:      start\nFinished:     end\nDuration:     00:01:10\nOuter keys:   2 of 3\nEvaluations:  42\nThreads:      6\nMeasure:      ic\n\n#1  score -8.333021  (gap to #2: 1.000000)\n    Wheels:     B I\n    Rings:      AB\n    Positions:  VJ\n    Plugboard:  none\n    Plaintext:  ABCDE FG\n\n#2  score -8.333021\n    Wheels:     B I\n    Rings:      AB\n    Positions:  VJ\n    Plugboard:  none\n    Plaintext:  ABCDE FG\n");
        result["hold"] = json!([]);
        assert!(
            attack(&result, "outer_slice_end", "3", "stdin", "cmd", "ic")
                .ends_with("\nNo candidates.\n")
        );
        assert!(
            attack(&result, "outer_slice_end", "3", "stdin", "cmd", "ic")
                .contains("Status:       empty slice\n")
        );
        let cancelled = attack(&result, "cancelled", "3", "stdin", "cmd", "ic");
        assert!(cancelled.contains("Status:       CANCELLED\n"));
        assert!(cancelled.ends_with("No candidates.\n\nResume:       cmd\n"));
    }
}
