#!/bin/bash

cargo test --profile release
cargo run --bin simple_election --profile release

