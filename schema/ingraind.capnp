@0xba471a64c010bd65;

struct IngrainPayload {
    data @0 :List(SerializedMeasurement);
}

struct SerializedMeasurement {
    timestamp @0 :UInt64;
    kind @1 :UInt16;
    name @2 :Text;
    measurement @3 :Float64;
    tags @4 :List(Tag);
}

struct Tag {
  key @0 :Text;
  value @1 :Text;
}