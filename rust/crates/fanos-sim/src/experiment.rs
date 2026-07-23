//! The **experiment runner** — a parameter-grid × seeds harness that turns a research question into a
//! reproducible artifact (`docs/design-testing.md`; audit S-P2).
//!
//! A one-off research file bakes its sweep into Rust and recompiles to ask a new question. This module lifts
//! that into data: define a [`Grid`] of named parameter axes, pick a seed count, hand the runner a
//! [`Scenario`] (a deterministic function of `(params, seed) → metrics`), and get back a table of [`Row`]s you
//! can emit as CSV or JSON. "What `f` deanonymizes at Full?" becomes running the same scenario over a wider
//! grid — a command, not a recompile — which is the foundation the `fanos evolve` genetic search wants
//! (`coherent-cybernetics.md §6`).
//!
//! The runner is deterministic: the Cartesian product of the grid is enumerated in a fixed order, and each
//! point runs seeds `0..seeds`, so the same grid + scenario yields the byte-identical artifact every time.

use std::collections::{BTreeMap, BTreeSet};

/// A parameter point: each axis name bound to one of its values (all values are strings; a scenario parses
/// what it needs). Ordered, so the artifact's columns are stable.
pub type Params = BTreeMap<String, String>;

/// A parameter grid: named axes, each with a list of candidate values. The set of runs is the **Cartesian
/// product** of the axes (an empty grid is a single empty point, so a scenario with no parameters still runs).
#[derive(Clone, Debug, Default)]
pub struct Grid {
    axes: Vec<(String, Vec<String>)>,
}

impl Grid {
    /// An empty grid (one empty parameter point).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an axis `name` sweeping `values` (builder). A later axis varies fastest in the enumeration order.
    #[must_use]
    pub fn axis(mut self, name: &str, values: &[&str]) -> Self {
        self.axes.push((name.to_owned(), values.iter().map(|v| (*v).to_owned()).collect()));
        self
    }

    /// The Cartesian product of the axes, in a fixed order (the first axis varies slowest). An axis with no
    /// values collapses the product to empty; an empty grid yields exactly one empty point.
    #[must_use]
    pub fn points(&self) -> Vec<Params> {
        let mut points = vec![Params::new()];
        for (name, values) in &self.axes {
            let mut next = Vec::with_capacity(points.len() * values.len());
            for base in &points {
                for v in values {
                    let mut p = base.clone();
                    p.insert(name.clone(), v.clone());
                    next.push(p);
                }
            }
            points = next;
        }
        points
    }
}

/// One measured run: the parameter point, the seed, and the named metric values the scenario produced.
#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    /// The parameter point this run used.
    pub params: Params,
    /// The seed this run used (`0..seeds`).
    pub seed: u64,
    /// The metrics the scenario measured, by name.
    pub metrics: BTreeMap<String, f64>,
}

/// A deterministic experiment: a function of `(params, seed)` to named metrics. Implementations MUST be pure
/// (same inputs ⇒ same metrics) so the artifact is reproducible — drive the simulator seeded, never a wall
/// clock or OS entropy.
pub trait Scenario {
    /// Run one `(params, seed)` and return its metrics.
    fn run(&self, params: &Params, seed: u64) -> BTreeMap<String, f64>;
}

/// A blanket impl so a plain closure is a [`Scenario`] — the common case.
impl<F: Fn(&Params, u64) -> BTreeMap<String, f64>> Scenario for F {
    fn run(&self, params: &Params, seed: u64) -> BTreeMap<String, f64> {
        self(params, seed)
    }
}

/// The runner: a [`Grid`] crossed with `seeds` repetitions of a [`Scenario`].
#[derive(Clone, Debug)]
pub struct Experiment {
    grid: Grid,
    seeds: u64,
}

impl Experiment {
    /// An experiment over `grid`, repeating each parameter point for seeds `0..seeds` (at least 1).
    #[must_use]
    pub fn new(grid: Grid, seeds: u64) -> Self {
        Self { grid, seeds: seeds.max(1) }
    }

    /// Run the scenario over the whole grid × seeds and collect the rows (grid order, then seed order).
    #[must_use]
    pub fn run<S: Scenario>(&self, scenario: &S) -> Vec<Row> {
        let mut rows = Vec::new();
        for params in self.grid.points() {
            for seed in 0..self.seeds {
                rows.push(Row { params: params.clone(), seed, metrics: scenario.run(&params, seed) });
            }
        }
        rows
    }

    /// The union of all metric names across `rows`, sorted — the metric columns of the artifact.
    fn metric_columns(rows: &[Row]) -> Vec<String> {
        let mut names = BTreeSet::new();
        for r in rows {
            names.extend(r.metrics.keys().cloned());
        }
        names.into_iter().collect()
    }

    /// The parameter axis names across `rows`, sorted — the parameter columns of the artifact.
    fn param_columns(rows: &[Row]) -> Vec<String> {
        let mut names = BTreeSet::new();
        for r in rows {
            names.extend(r.params.keys().cloned());
        }
        names.into_iter().collect()
    }

    /// Render the rows as CSV: `param columns…, seed, metric columns…`. A missing metric on a row is blank.
    #[must_use]
    pub fn to_csv(rows: &[Row]) -> String {
        let params = Self::param_columns(rows);
        let metrics = Self::metric_columns(rows);
        let mut out = String::new();
        let header: Vec<String> = params
            .iter()
            .cloned()
            .chain(std::iter::once("seed".to_owned()))
            .chain(metrics.iter().cloned())
            .collect();
        out.push_str(&header.join(","));
        out.push('\n');
        for r in rows {
            let mut cells: Vec<String> = params.iter().map(|p| r.params.get(p).cloned().unwrap_or_default()).collect();
            cells.push(r.seed.to_string());
            for m in &metrics {
                cells.push(r.metrics.get(m).map(f64::to_string).unwrap_or_default());
            }
            out.push_str(&cells.join(","));
            out.push('\n');
        }
        out
    }

    /// Render the rows as a JSON array of `{params, seed, metrics}` objects (compact, dependency-free).
    #[must_use]
    pub fn to_json(rows: &[Row]) -> String {
        let obj = |m: &BTreeMap<String, String>| -> String {
            let fields: Vec<String> = m.iter().map(|(k, v)| format!("{k:?}:{v:?}")).collect();
            format!("{{{}}}", fields.join(","))
        };
        let items: Vec<String> = rows
            .iter()
            .map(|r| {
                let metrics: Vec<String> = r.metrics.iter().map(|(k, v)| format!("{k:?}:{v}")).collect();
                format!(
                    "{{\"params\":{},\"seed\":{},\"metrics\":{{{}}}}}",
                    obj(&r.params),
                    r.seed,
                    metrics.join(",")
                )
            })
            .collect();
        format!("[{}]", items.join(","))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn the_grid_is_the_cartesian_product_in_a_fixed_order() {
        let grid = Grid::new().axis("t", &["3", "4"]).axis("n", &["7", "9"]);
        let points = grid.points();
        assert_eq!(points.len(), 4, "2 × 2 = 4 points");
        // The first axis varies slowest: (3,7),(3,9),(4,7),(4,9).
        assert_eq!(points[0].get("t").unwrap(), "3");
        assert_eq!(points[0].get("n").unwrap(), "7");
        assert_eq!(points[1].get("n").unwrap(), "9");
        assert_eq!(points[2].get("t").unwrap(), "4");
        // An empty grid is one empty point (a no-parameter scenario still runs).
        assert_eq!(Grid::new().points().len(), 1);
    }

    #[test]
    fn the_runner_crosses_the_grid_with_seeds_and_is_reproducible() {
        // A trivial scenario: metric = t · 10 + seed. Deterministic, so two runs match byte-for-byte.
        let scenario = |p: &Params, seed: u64| {
            let t: f64 = p.get("t").unwrap().parse().unwrap();
            BTreeMap::from([("score".to_owned(), t * 10.0 + seed as f64)])
        };
        let exp = Experiment::new(Grid::new().axis("t", &["3", "4"]), 3);
        let rows = exp.run(&scenario);
        assert_eq!(rows.len(), 2 * 3, "2 points × 3 seeds");
        // Point t=3, seed 2 → 32.
        let r = rows.iter().find(|r| r.params.get("t").unwrap() == "3" && r.seed == 2).unwrap();
        assert_eq!(r.metrics.get("score"), Some(&32.0));
        // Reproducible: an identical experiment yields identical rows.
        assert_eq!(rows, exp.run(&scenario));

        // The CSV header carries the parameter, the seed, and the metric columns.
        let csv = Experiment::to_csv(&rows);
        assert_eq!(csv.lines().next().unwrap(), "t,seed,score");
        assert_eq!(csv.lines().count(), 1 + 6, "header + 6 rows");
        // The JSON is a well-formed array of one object per row.
        let json = Experiment::to_json(&rows);
        assert!(json.starts_with('[') && json.ends_with(']'));
        assert_eq!(json.matches("\"seed\":").count(), 6);
    }
}
