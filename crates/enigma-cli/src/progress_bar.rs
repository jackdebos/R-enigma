//! Terminal-only progress presentation; no Core clocks or event changes.
use std::io::{self, Write};
use std::time::Duration;

#[derive(Clone, Copy)]
pub(crate) enum Phase {
    Outer,
    Stages,
}

#[derive(Clone, Copy)]
pub(crate) struct Snapshot {
    pub completed: u128,
    pub selected: u128,
    pub evaluations: u64,
    pub total_evaluations: u64,
    pub running: Duration,
    pub elapsed_ms: u128,
    pub own_outers: u128,
    pub phase: Phase,
}

fn duration(seconds: u128) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

pub(crate) fn line(s: Snapshot) -> String {
    let rate = if s.running.is_zero() {
        0.0
    } else {
        s.evaluations as f64 / s.running.as_secs_f64()
    };
    let (divisor, suffix) = if rate >= 1e9 {
        (1e9, "G")
    } else if rate >= 1e6 {
        (1e6, "M")
    } else if rate >= 1e3 {
        (1e3, "K")
    } else {
        (1.0, "")
    };
    let rate = format!("{:.2}{suffix} eval/s", rate / divisor);
    let elapsed = duration(s.elapsed_ms / 1000);
    if matches!(s.phase, Phase::Stages) {
        return format!(
            "chained stages | {} evaluations | {rate} | {elapsed} elapsed",
            s.total_evaluations
        );
    }
    let completed = s.completed.min(s.selected);
    let share = if s.selected == 0 {
        0.0
    } else {
        completed as f64 / s.selected as f64
    };
    // Integer arithmetic keeps floor exact without overflowing u128 totals.
    let cells = (0..24)
        .filter(|i| {
            completed >= s.selected / 24 * (i + 1) + (s.selected % 24 * (i + 1)).div_ceil(24)
        })
        .count();
    let cells = if s.selected == 0 { 0 } else { cells };
    let eta = if s.own_outers == 0 {
        "--:--:--".into()
    } else {
        duration(
            (s.running.as_secs_f64() * (s.selected - completed) as f64 / s.own_outers as f64)
                as u128,
        )
    };
    format!(
        "[{}{}] {:5.1}% | {}/{} outer keys | {rate} | {elapsed} elapsed | ETA {eta}",
        "#".repeat(cells),
        ".".repeat(24 - cells),
        share * 100.0,
        s.completed,
        s.selected
    )
}

pub(crate) struct Drawer<W> {
    writer: W,
    last: Option<Duration>,
    visible: bool,
}
impl<W: Write> Drawer<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            last: None,
            visible: false,
        }
    }
    pub fn draw(&mut self, line: &str, now: Duration, terminal: bool) -> io::Result<bool> {
        if !terminal
            && self
                .last
                .is_some_and(|last| now.saturating_sub(last) < Duration::from_millis(100))
        {
            return Ok(false);
        }
        self.visible = true;
        write!(self.writer, "\r{line}\x1b[K")?;
        self.writer.flush()?;
        self.last = Some(now);
        Ok(true)
    }
    pub fn clear(&mut self) -> io::Result<()> {
        if self.visible {
            self.writer.write_all(b"\r\x1b[K")?;
            self.writer.flush()?;
            self.visible = false;
        }
        Ok(())
    }
}

/// Snapshot counters are cumulative across resumes; speed is process-local.
pub(crate) struct Bar<W> {
    drawer: Drawer<W>,
    selected: u128,
    baseline: Option<(u128, u64)>,
    stages: bool,
    last: Option<(String, Duration, bool)>,
}
impl<W: Write> Bar<W> {
    pub fn new(writer: W, selected: u128) -> Self {
        Self {
            drawer: Drawer::new(writer),
            selected,
            baseline: None,
            stages: false,
            last: None,
        }
    }
    pub fn observe(&mut self, p: enigma_core::AttackProgress, running: Duration, elapsed_ms: u128) {
        let (outers, evaluations) = *self
            .baseline
            .get_or_insert((p.outers_completed(), p.evaluations_completed()));
        let text = line(Snapshot {
            completed: p.outers_completed(),
            selected: self.selected,
            evaluations: p.evaluations_completed().saturating_sub(evaluations),
            total_evaluations: p.evaluations_completed(),
            running,
            elapsed_ms,
            own_outers: p.outers_completed().saturating_sub(outers),
            phase: if self.stages {
                Phase::Stages
            } else {
                Phase::Outer
            },
        });
        // Presentation failure must not alter event delivery or cancel computation.
        let drawn = self.drawer.draw(&text, running, false).unwrap_or(false);
        self.last = Some((text, running, drawn));
    }
    pub fn stages(&mut self) {
        self.stages = true;
    }
    pub fn clear(&mut self) {
        let _ = self.drawer.clear();
    }
    pub fn finish(&mut self) {
        // A terminal snapshot already drawn at normal cadence needs no duplicate.
        if let Some((text, now, false)) = &self.last {
            let _ = self.drawer.draw(text, *now, true);
        }
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Snapshot {
        Snapshot {
            completed: 0,
            selected: 8,
            evaluations: 850,
            total_evaluations: 850,
            running: Duration::from_secs(1),
            elapsed_ms: 65_000,
            own_outers: 0,
            phase: Phase::Outer,
        }
    }
    #[test]
    fn outer_fields_and_eta() {
        let mut s = sample();
        assert_eq!(line(s), "[........................]   0.0% | 0/8 outer keys | 850.00 eval/s | 00:01:05 elapsed | ETA --:--:--");
        s.completed = 3;
        s.own_outers = 3;
        s.running = Duration::from_secs(6);
        s.evaluations = 7_380;
        assert_eq!(line(s), "[#########...............]  37.5% | 3/8 outer keys | 1.23K eval/s | 00:01:05 elapsed | ETA 00:00:10");
        s.completed = 8;
        assert_eq!(line(s), "[########################] 100.0% | 8/8 outer keys | 1.23K eval/s | 00:01:05 elapsed | ETA 00:00:00");
        s.completed = 7;
        s.own_outers = 1;
        s.running = Duration::from_secs(360_061);
        assert!(line(s).ends_with("ETA 100:01:01"));
    }
    #[test]
    fn cells_round_down_and_resume_uses_own_work() {
        let mut s = sample();
        s.selected = 100;
        s.completed = 49;
        assert_eq!(line(s), "[###########.............]  49.0% | 49/100 outer keys | 850.00 eval/s | 00:01:05 elapsed | ETA --:--:--");
        s.completed = 50;
        s.own_outers = 1;
        s.running = Duration::from_secs(2);
        s.evaluations = 20;
        assert_eq!(line(s), "[############............]  50.0% | 50/100 outer keys | 10.00 eval/s | 00:01:05 elapsed | ETA 00:01:40");
    }
    #[test]
    fn rates_durations_and_stages() {
        for (evaluations, rate) in [
            (850, "850.00"),
            (1230, "1.23K"),
            (1_230_000, "1.23M"),
            (1_230_000_000, "1.23G"),
        ] {
            let mut s = sample();
            s.phase = Phase::Stages;
            s.evaluations = evaluations;
            s.total_evaluations = evaluations;
            s.elapsed_ms = 360_061_000;
            assert_eq!(line(s), format!("chained stages | {evaluations} evaluations | {rate} eval/s | 100:01:01 elapsed"));
        }
        let mut s = sample();
        s.running = Duration::ZERO;
        assert!(line(s).contains("0.00 eval/s"));
    }
    #[test]
    fn injected_clock_throttles_except_initial_and_terminal_and_clears() {
        let mut bytes = Vec::new();
        let mut drawer = Drawer::new(&mut bytes);
        for (ms, terminal) in [
            (0, false),
            (0, false),
            (99, false),
            (100, false),
            (101, true),
        ] {
            drawer
                .draw("test", Duration::from_millis(ms), terminal)
                .unwrap();
        }
        drawer.clear().unwrap();
        assert_eq!(bytes, b"\rtest\x1b[K\rtest\x1b[K\rtest\x1b[K\r\x1b[K");
    }
}
