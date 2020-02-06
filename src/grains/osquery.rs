use serde_json::Value;
use std::io::{self, BufRead, BufReader};
use std::process::Command;
use std::time::Duration;

use actix::{Actor, AsyncContext, Context, Recipient};

use crate::grains::SendToManyRecipients;
use crate::backends::Message;
use crate::metrics::{kind, Measurement, Tags, Unit};

fn default_osqueryi() -> String {
    String::from("osqueryi")
}

fn default_interval_ms() -> u64 {
    10000
}

fn default_run_at_start() -> bool {
    false
}

fn default_osqueryi_args() -> Vec<String> {
    Vec::new()
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OsqueryConfig {
    #[serde(default = "default_osqueryi")]
    osqueryi: String,
    #[serde(default = "default_osqueryi_args")]
    osqueryi_args: Vec<String>,
    config_path: Option<String>,
    queries: Vec<QueryConfig>,
    #[serde(default = "default_interval_ms")]
    interval_ms: u64,
    #[serde(default = "default_run_at_start")]
    run_at_start: bool,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct QueryConfig {
    query: Option<String>,
    pack: Option<String>,
    name: String,
    measurement: String,
    measurement_type: String,
    aggregation_type: Option<String>,
    iterations: Option<u64>,
    interval_ms: Option<u64>,
    run_at_start: Option<bool>,
}

impl QueryConfig {
    fn propagate_defaults(&self, parent: &OsqueryConfig) -> Self {
        let mut conf = self.clone();
        conf.interval_ms.get_or_insert(parent.interval_ms);
        conf.run_at_start.get_or_insert(parent.run_at_start);
        conf
    }
}

#[derive(Debug)]
pub enum OsqueryError {
    ConfigError(String),
    IOError(io::Error),
    JSONError(serde_json::Error),
    Error(String),
}

pub struct Osquery {
    conf: OsqueryConfig,
    recipients: Vec<Recipient<Message>>,
}

impl Osquery {
    pub fn with_config(mut conf: OsqueryConfig, recipients: Vec<Recipient<Message>>) -> Self {
        // validate freeform input
        for q in conf.queries.iter_mut() {
            if let None = q.aggregation_type {
                q.aggregation_type = Some("counter".to_string());
            }

            let aty = q.aggregation_type.as_ref().unwrap();
            kind::try_from_str(aty)
                .map_err(|_| OsqueryError::Error(format!("invalid aggregation type: {}", aty)))
                .unwrap();

            let ty = &q.measurement_type;
            Unit::try_from_str(&q.measurement_type, 0)
                .map_err(|_| OsqueryError::Error(format!("invalid measurement type: {}", ty)))
                .unwrap();
        }

        Osquery { conf, recipients }
    }

    fn schedule_queries(&mut self, ctx: &mut <Self as Actor>::Context) -> Result<(), OsqueryError> {
        for conf in &self.conf.queries {
            let query = Query::with_config(conf.propagate_defaults(&self.conf))?;
            self.schedule_query(query, true, ctx);
        }

        Ok(())
    }

    fn schedule_query(
        &self,
        mut query: Query,
        is_startup: bool,
        ctx: &mut <Self as Actor>::Context,
    ) {
        if let Some(i) = query.iterations_left.as_mut() {
            if *i == 0 {
                return;
            }
            *i -= 1;
        }
        let interval_ms = if is_startup && query.conf.run_at_start.unwrap_or(false) {
            0
        } else {
            query.conf.interval_ms.unwrap()
        };
        let interval = Duration::from_millis(interval_ms);
        ctx.run_later(interval, move |sself, ctx| {
            let qs = query.conf.query.clone();
            if let Err(e) = sself.run_query(&query, ctx) {
                error!("error running query: {:?} {:?}", qs, e);
            }

            sself.schedule_query(query, false, ctx);
        });
    }

    fn run_query(
        &mut self,
        query: &Query,
        _ctx: &mut <Self as Actor>::Context,
    ) -> Result<(), OsqueryError> {
        let output = Osqueryi::new()
            .command(&self.conf.osqueryi)
            .args(&self.conf.osqueryi_args)
            .config_path(self.conf.config_path.clone())
            .pack(&query.conf.pack)
            .query(&query.conf.query)
            .run()
            .map_err(|e| OsqueryError::IOError(e))?;
        let measurements = self.process_query_result(query, &output)?;
        let message = Message::List(measurements);
        self.recipients.do_send(message);

        Ok(())
    }

    fn process_query_result(
        &self,
        query: &Query,
        data: &[u8],
    ) -> Result<Vec<Measurement>, OsqueryError> {
        // Validate if freeform types are reasonable
        let mut reader = BufReader::new(data);
        let mut accum = String::new();
        let mut ret: Vec<Measurement> = Vec::new();
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    accum.push_str(&line);
                    if line.trim() == "]" {
                        let rows = serde_json::from_slice(accum.as_bytes())
                            .map_err(|e| OsqueryError::JSONError(e))?;
                        ret.extend(measurements_from_rows(&rows, &query.conf)?);
                        accum.clear();
                    }
                }
                Err(e) => return Err(OsqueryError::IOError(e)),
            }
        }

        Ok(ret)
    }
}

fn measurements_from_rows(
    rows: &Value,
    config: &QueryConfig,
) -> Result<Vec<Measurement>, OsqueryError> {
    let rows = rows
        .as_array()
        .ok_or_else(|| OsqueryError::Error("result is not an array".to_string()))?;

    let ret: Result<Vec<Measurement>, _> = rows
        .iter()
        .map(|row| measurement_from_row(row, config))
        .collect();
    ret
}

fn measurement_from_row(row: &Value, config: &QueryConfig) -> Result<Measurement, OsqueryError> {
    let obj = row
        .as_object()
        .ok_or_else(|| OsqueryError::Error("result row is not an object".to_string()))?;
    let mut tags = Tags::new();
    let mut measurement: u64 = 0;

    for (k, v) in obj {
        if k == &config.measurement {
            if let Value::String(v) = v {
                measurement = v.parse().unwrap_or_default();
                continue;
            }
        }

        let v = match v {
            Value::Bool(v) => v.to_string(),
            Value::Number(v) => v.to_string(),
            Value::String(v) => v.clone(),
            x => x.to_string(),
        };
        tags.insert(k, v);
    }

    // Unwraps are safe here, because it's guaranteed at
    // initialization that these are meaningful values
    Ok(Measurement::new(
        kind::try_from_str(&config.aggregation_type.as_ref().unwrap()).unwrap(),
        format!("osquery.{}", config.name),
        Unit::try_from_str(&config.measurement_type, measurement).unwrap(),
        tags,
    ))
}

impl Actor for Osquery {
    type Context = Context<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        info!("osquery grain started");
        self.schedule_queries(ctx).expect("Invalid osquery config");
    }

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        info!("osquery daemon stopped");
    }
}

#[derive(Debug)]
struct Query {
    conf: QueryConfig,
    iterations_left: Option<u64>,
}

impl Query {
    fn with_config(conf: QueryConfig) -> Result<Self, OsqueryError> {
        use OsqueryError::ConfigError;

        let iterations_left = conf.iterations.clone();
        if conf.interval_ms.unwrap() == 0 {
            return Err(ConfigError("interval_ms can't be 0".into()));
        }

        Ok(Query {
            conf,
            iterations_left,
        })
    }
}

struct Osqueryi {
    command: String,
    args: Vec<String>,
    config_path: Option<String>,
    query: Option<String>,
    pack: Option<String>,
}

impl Osqueryi {
    fn new() -> Self {
        Osqueryi {
            command: String::from("osqueryi"),
            args: Vec::new(),
            config_path: None,
            query: None,
            pack: None,
        }
    }

    fn command(&mut self, cmd: &str) -> &mut Self {
        self.command = cmd.to_string();
        self
    }

    fn args(&mut self, args: &[String]) -> &mut Self {
        self.args = args.to_vec();
        self
    }

    fn config_path(&mut self, path: Option<String>) -> &mut Self {
        self.config_path = path;
        self
    }
    fn pack(&mut self, pack: &Option<String>) -> &mut Self {
        self.pack = pack.clone();
        self
    }

    fn query(&mut self, query: &Option<String>) -> &mut Self {
        self.query = query.clone();
        self
    }

    fn run(&mut self) -> io::Result<Vec<u8>> {
        let mut command = Command::new(self.command.clone());
        command.args(self.to_args()?);
        debug!("running {:?}", command);
        let output = command.output()?;
        if !output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("osqueryi returned code: {}", output.status.code().unwrap()),
            ));
        }
        Ok(output.stdout)
    }

    fn to_args(&self) -> io::Result<Vec<String>> {
        let mut args = self.args.clone();
        args.push("--json".to_string());
        if let Some(config) = &self.config_path {
            args.push("--config_path".to_string());
            args.push(config.clone());
        }
        match (&self.query, &self.pack) {
            (Some(q), None) => args.push(q.clone()),
            (None, Some(p)) => {
                args.push("--pack".into());
                args.push(p.clone());
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "you must specify exactly one of query or pack",
                ))
            }
        }
        Ok(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(aggregation_type: Option<&str>) -> QueryConfig {
        QueryConfig {
            name: "foo".to_string(),
            measurement: "system_time".to_string(),
            measurement_type: "count".to_string(),
            aggregation_type: aggregation_type.or(Some("counter")).map(String::from),
            ..QueryConfig::default()
        }
    }

    #[test]
    fn test_measurement_from_row() {
        let mut config = config(None);

        let json = r#"{"name":"systemd","system_time":"23470","user_time":"17220"}"#;
        let row = serde_json::from_slice(json.as_bytes()).unwrap();
        let m = measurement_from_row(&row, &config).unwrap();

        assert_eq!(m.name, "osquery.foo");
        assert_eq!(m.value, Unit::Count(23470));
        assert_eq!(m.kind, kind::COUNTER);
        assert_eq!(m.tags.len(), 2);
        assert_eq!(m.tags.get("name").unwrap(), "systemd");
        assert_eq!(m.tags.get("user_time").unwrap(), "17220");
    }

    #[test]
    fn test_measurements_from_rows() {
        let mut config = config(Some("gauge"));

        let json = r#"[{"name":"systemd","system_time":"23470","user_time":"17220"}]"#;
        let rows = serde_json::from_slice(json.as_bytes()).unwrap();
        let ret = measurements_from_rows(&rows, &config).unwrap();

        assert_eq!(ret.len(), 1);
        let m = &ret[0];
        assert_eq!(m.name, "osquery.foo");
        assert_eq!(m.kind, kind::GAUGE);
        assert_eq!(m.tags.len(), 2);
    }
    #[test]
    fn test_measurements_from_rows_empty() {
        let mut config = config(Some("gauge"));

        let json = "[]";
        let rows = serde_json::from_slice(json.as_bytes()).unwrap();
        let ret = measurements_from_rows(&rows, &config).unwrap();

        assert!(ret.is_empty());
    }

    #[test]
    fn test_measurements_from_rows_error_no_outer_array() {
        let mut config = config(Some("gauge"));

        let json = r#"{"foo": "bar"}"#;
        let rows = serde_json::from_slice(json.as_bytes()).unwrap();
        let ret = measurements_from_rows(&rows, &config);

        match ret {
            Err(OsqueryError::Error(_)) => (),
            _ => panic!("should not get here"),
        };
    }

    #[test]
    fn test_measurements_from_rows_error_no_inner_object() {
        let mut config = config(Some("gauge"));

        let json = r#"[1, 2]"#;
        let rows = serde_json::from_slice(json.as_bytes()).unwrap();
        let ret = measurements_from_rows(&rows, &config);

        match ret {
            Err(OsqueryError::Error(_)) => (),
            _ => panic!("should not get here"),
        };
    }
}
