// Copyright (C) Jeeyong Um <conr2d@proton.me>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{env, path::PathBuf};

fn main() {
    let target = std::env::var("TARGET").unwrap();

    if target.contains("windows") {
        println!("cargo:rustc-link-lib=dylib=msvcrt");
    } else if target.contains("apple") {
        println!("cargo:rustc-link-lib=dylib=c++");
    } else if target.contains("linux") || target.contains("bsd") {
        println!("cargo:rustc-link-lib=dylib=stdc++");
    } else {
        println!("cargo:warning=Unknown target platform: {}", target);
    }

    let dst = cmake::Config::new("RandomX").build();

    println!("cargo:rustc-link-search=native={}/build", dst.display());
    println!("cargo:rustc-link-lib=static=randomx");

    let bindings = bindgen::Builder::default()
        .header("RandomX/src/randomx.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
