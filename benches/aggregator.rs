use criterion::{criterion_group, criterion_main, Criterion, BatchSize};
use ingraind::aggregations::buffer::Aggregator;
use ingraind::metrics::{kind, Measurement, Tags, Unit};

pub fn record(c: &mut Criterion) {
    let mut metrics = Vec::new();
    for i in 0..1000 {
        let mut tags = Tags::new();
        tags.insert("foo", "bar");
        tags.insert("bar", "baz");
        metrics.push(Measurement::new(
            kind::COUNTER,
            format!("foo_{}", i),
            Unit::Count(1),
            tags,
        ));
    }
    c.bench_function("record", |b| {
        b.iter_batched(
            || metrics.clone(),
            |metrics| {
                let mut aggregator = Aggregator::new(true);
                for m in metrics.iter().cloned() {
                    aggregator.record(m);
                }
            },
            BatchSize::SmallInput,
        )
    });
}

pub fn flush(c: &mut Criterion) {
    let mut aggregator = Aggregator::new(true);
    for i in 0..5000 {
        let mut tags = Tags::new();
        tags.insert("foo", "bar");
        tags.insert("bar", "baz");
        aggregator.record(Measurement::new(
            kind::COUNTER,
            format!("foo_{}", i),
            Unit::Count(1),
            tags,
        ));
    }
    c.bench_function("flush", |b| {
        b.iter_batched(
            || aggregator.clone(),
            |mut aggregator| aggregator.flush(),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, record, flush);
criterion_main!(benches);
