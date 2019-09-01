use serde_json::Value;
use std::io;
use std::process::Command;
use std::time::Duration;

use actix::{Actor, AsyncContext, Context, Recipient};

use crate::backends::Message;
use crate::metrics::{kind, Measurement, Tags, Unit};

fn default_interval_ms() -> u64 {
    10000
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OsqueryConfig {
    config_path: Option<String>,
    queries: Vec<QueryConfig>,
    #[serde(default = "default_interval_ms")]
    interval_ms: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct QueryConfig {
    iterations: Option<u64>,
    interval_ms: Option<u64>,
    query: String,
    measurement: String,
    measurement_type: String,
}

impl QueryConfig {
    fn propagate_defaults(&self, parent: &OsqueryConfig) -> Self {
        let mut conf = self.clone();
        conf.interval_ms.get_or_insert(parent.interval_ms);
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
    pub fn with_config(conf: OsqueryConfig, recipients: Vec<Recipient<Message>>) -> Self {
        Osquery { conf, recipients }
    }

    fn schedule_queries(&mut self, ctx: &mut <Self as Actor>::Context) -> Result<(), OsqueryError> {
        for conf in &self.conf.queries {
            let query = Query::with_config(conf.propagate_defaults(&self.conf))?;
            self.schedule_query(query, ctx);
        }

        Ok(())
    }

    fn schedule_query(&self, mut query: Query, ctx: &mut <Self as Actor>::Context) {
        let interval = Duration::from_millis(query.conf.interval_ms.unwrap());
        ctx.run_later(interval, move |sself, ctx| {
            let qs = query.conf.query.clone();
            if let Err(e) = sself.run_query(&query, ctx) {
                error!("error running query: {:?} {:?}", qs, e);
            }

            if let Some(i) = query.iterations_left.as_mut() {
                *i -= 1;
                if *i > 0 {
                    sself.schedule_query(query, ctx);
                }
            }
        });
    }

    fn run_query(
        &mut self,
        query: &Query,
        _ctx: &mut <Self as Actor>::Context,
    ) -> Result<(), OsqueryError> {
        let output = Osqueryi::new()
            .config_path(self.conf.config_path.clone())
            .query(&query.conf.query)
            .run()
            .map_err(|e| OsqueryError::IOError(e))?;
        let measurements = self.process_query_result(query, &output)?;
        let message = Message::List(measurements);
        for recipient in &self.recipients {
            recipient.do_send(message.clone()).unwrap();
        }

        Ok(())
    }

    fn process_query_result(
        &self,
        query: &Query,
        data: &[u8],
    ) -> Result<Vec<Measurement>, OsqueryError> {
        let name = &query.conf.measurement;
        let ty = &query.conf.measurement_type;
        let k = kind::try_from_str(ty)
            .map_err(|_| OsqueryError::Error(format!("invalid measurement type: {}", ty)))?;
        let rows = serde_json::from_slice(data).map_err(|e| OsqueryError::JSONError(e))?;
        measurements_from_rows(&rows, name, k)
    }
}

fn measurements_from_rows(
    rows: &Value,
    name: &str,
    k: kind::Kind,
) -> Result<Vec<Measurement>, OsqueryError> {
    let rows = rows
        .as_array()
        .ok_or_else(|| OsqueryError::Error("result is not an array".to_string()))?;

    let ret: Result<Vec<Measurement>, _> = rows
        .iter()
        .map(|row| measurement_from_row(row, name, k))
        .collect();
    ret
}

fn measurement_from_row(
    row: &Value,
    name: &str,
    k: kind::Kind,
) -> Result<Measurement, OsqueryError> {
    let obj = row
        .as_object()
        .ok_or_else(|| OsqueryError::Error("result row is not an object".to_string()))?;
    let mut tags = Tags::new();
    for (k, v) in obj {
        let v = match v {
            Value::Bool(v) => v.to_string(),
            Value::Number(v) => v.to_string(),
            Value::String(v) => v.clone(),
            x => x.to_string(),
        };
        tags.insert(k, v);
    }
    Ok(Measurement::new(k, name.to_string(), Unit::Count(0), tags))
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
        if let Some(i) = &iterations_left {
            if *i == 0 {
                return Err(ConfigError("iterations can't be set to 0".into()));
            }
        }
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
    config_path: Option<String>,
    query: Option<String>,
}

impl Osqueryi {
    fn new() -> Self {
        Osqueryi {
            config_path: None,
            query: None,
        }
    }

    fn config_path(&mut self, path: Option<String>) -> &mut Self {
        self.config_path = path;
        self
    }

    fn query(&mut self, query: &str) -> &mut Self {
        self.query = Some(query.to_string());
        self
    }

    fn run(&mut self) -> io::Result<Vec<u8>> {
        let args = self.to_args()?;
        let output = Command::new("osqueryi").args(args).output()?;
        Ok(output.stdout)
    }

    fn to_args(&self) -> io::Result<Vec<String>> {
        let mut args = vec!["--json".to_string()];
        if let Some(config) = &self.config_path {
            args.push("--config_path".to_string());
            args.push(config.clone());
        }
        let query = self
            .query
            .clone()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "query string not provided"))?;
        args.push(query);
        Ok(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_measurement_from_row() {
        let json = r#"{"name":"systemd","system_time":"23470","user_time":"17220"}"#;
        let row = serde_json::from_slice(json.as_bytes()).unwrap();
        let m = measurement_from_row(&row, "foo", kind::COUNTER).unwrap();
        assert_eq!(m.name, "foo");
        assert_eq!(m.kind, kind::COUNTER);
        assert_eq!(m.tags.len(), 3);
        assert_eq!(m.tags.get("name").unwrap(), "systemd");
        assert_eq!(m.tags.get("system_time").unwrap(), "23470");
        assert_eq!(m.tags.get("user_time").unwrap(), "17220");
    }

    #[test]
    fn test_measurements_from_rows() {
        let json = r#"[{"name":"systemd","system_time":"23470","user_time":"17220"}]"#;
        let rows = serde_json::from_slice(json.as_bytes()).unwrap();
        let ret = measurements_from_rows(&rows, "foo", kind::GAUGE).unwrap();
        assert_eq!(ret.len(), 1);
        let m = &ret[0];
        assert_eq!(m.name, "foo");
        assert_eq!(m.kind, kind::GAUGE);
        assert_eq!(m.tags.len(), 3);
    }
    #[test]
    fn test_measurements_from_rows_empty() {
        let json = "[]";
        let rows = serde_json::from_slice(json.as_bytes()).unwrap();
        let ret = measurements_from_rows(&rows, "foo", kind::GAUGE).unwrap();
        assert!(ret.is_empty());
    }

    #[test]
    fn test_measurements_from_rows_error_no_outer_array() {
        let json = r#"{"foo": "bar"}"#;
        let rows = serde_json::from_slice(json.as_bytes()).unwrap();
        let ret = measurements_from_rows(&rows, "foo", kind::GAUGE);
        match ret {
            Err(OsqueryError::Error(_)) => (),
            _ => panic!("should not get here"),
        };
    }

    #[test]
    fn test_measurements_from_rows_error_no_inner_object() {
        let json = r#"[1, 2]"#;
        let rows = serde_json::from_slice(json.as_bytes()).unwrap();
        let ret = measurements_from_rows(&rows, "foo", kind::GAUGE);
        match ret {
            Err(OsqueryError::Error(_)) => (),
            _ => panic!("should not get here"),
        };
    }
}
