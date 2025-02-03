// Copyright (C) Jeeyong Um <conr2d@proton.me>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use rxvm_sys as sys;
use std::sync::Arc;

const RANDOMX_HASH_SIZE: usize = sys::RANDOMX_HASH_SIZE as usize;

bitflags::bitflags! {
    #[derive(Clone, Copy)]
    pub struct RandomXFlags: u32 {
        // const Default = sys::randomx_flags_RANDOMX_FLAG_DEFAULT;
        const LargePages = sys::randomx_flags_RANDOMX_FLAG_LARGE_PAGES;
        const HardAes = sys::randomx_flags_RANDOMX_FLAG_HARD_AES;
        const FullMem = sys::randomx_flags_RANDOMX_FLAG_FULL_MEM;
        const Jit = sys::randomx_flags_RANDOMX_FLAG_JIT;
        const Secure = sys::randomx_flags_RANDOMX_FLAG_SECURE;
        const Argon2Ssse3 = sys::randomx_flags_RANDOMX_FLAG_ARGON2_SSSE3;
        const Argon2Avx2 = sys::randomx_flags_RANDOMX_FLAG_ARGON2_AVX2;
        const Argon2 = sys::randomx_flags_RANDOMX_FLAG_ARGON2;
    }
}

impl Default for RandomXFlags {
    /// Returns the recommended flags to be used on the current machine.
    fn default() -> Self {
        let bits = unsafe { sys::randomx_get_flags() };

        Self::from_bits_truncate(bits)
    }
}

#[derive(Debug)]
pub enum Error {
    CacheNotAllocated,
    DatasetNotAllocated,
    VmNotCreated,
}

pub struct RandomXCache {
    pointer: *mut sys::randomx_cache,
}

impl RandomXCache {
    /// Allocates a RandomX cache.
    pub fn new(flags: RandomXFlags) -> Result<Self, Error> {
        let pointer = unsafe { sys::randomx_alloc_cache(flags.bits()) };

        match pointer {
            _ if pointer.is_null() => Err(Error::CacheNotAllocated),
            _ => Ok(Self { pointer }),
        }
    }

    /// Initializes the cache memory and SuperscalarHash using the provided key value.
    pub fn init(&mut self, key: &[u8]) {
        unsafe {
            sys::randomx_init_cache(self.pointer, key.as_ptr() as *const _, key.len());
        }
    }
}

unsafe impl Send for RandomXCache {}
unsafe impl Sync for RandomXCache {}

impl Drop for RandomXCache {
    fn drop(&mut self) {
        unsafe {
            sys::randomx_release_cache(self.pointer);
        }
    }
}

// Wrapper for sending raw pointer.
#[derive(Clone)]
struct Sendable<T>(*mut T);
unsafe impl<T> Send for Sendable<T> {}

pub struct RandomXDataset {
    pointer: *mut sys::randomx_dataset,
}

impl RandomXDataset {
    /// Allocates a RandomX dataset.
    pub fn new(flags: RandomXFlags) -> Result<Self, Error> {
        let pointer = unsafe { sys::randomx_alloc_dataset(flags.bits()) };

        match pointer {
            _ if pointer.is_null() => Err(Error::DatasetNotAllocated),
            _ => Ok(Self { pointer }),
        }
    }

    /// Initializes RandomX dataset items.
    pub fn init(&mut self, cache: &RandomXCache) {
        unsafe {
            let item_count = sys::randomx_dataset_item_count();
            let num_threads = std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(1) as u64;

            if num_threads > 1 {
                let delta = item_count / num_threads;

                let mut threads = Vec::new();
                for i in 0..num_threads {
                    let sendable_dataset = Sendable(self.pointer);
                    let sendable_cache = Sendable(cache.pointer);

                    let start = i * delta;
                    let count = if i < num_threads - 1 {
                        delta
                    } else {
                        item_count - (delta * (num_threads - 1))
                    };

                    threads.push(std::thread::spawn(move || {
                        let dataset = sendable_dataset.clone();
                        let cache = sendable_cache.clone();

                        sys::randomx_init_dataset(dataset.0, cache.0, start, count);
                    }));
                }

                for t in threads {
                    t.join().expect("Failed to initialize RandomX dataset");
                }
            } else {
                sys::randomx_init_dataset(self.pointer, cache.pointer, 0, item_count);
            }
        }
    }
}

unsafe impl Send for RandomXDataset {}
unsafe impl Sync for RandomXDataset {}

impl Drop for RandomXDataset {
    fn drop(&mut self) {
        unsafe {
            sys::randomx_release_dataset(self.pointer);
        }
    }
}

pub struct RandomXVm {
    pointer: *mut sys::randomx_vm,
    _cache: Option<Arc<RandomXCache>>,
    _dataset: Option<Arc<RandomXDataset>>,
}

impl RandomXVm {
    /// Creates and initializes a RandomX virtual machine.
    pub fn new(
        flags: RandomXFlags,
        cache: Option<Arc<RandomXCache>>,
        dataset: Option<Arc<RandomXDataset>>,
    ) -> Result<Self, Error> {
        let pointer = unsafe {
            sys::randomx_create_vm(
                flags.bits(),
                cache.as_ref().map_or(std::ptr::null_mut(), |c| c.pointer),
                dataset.as_ref().map_or(std::ptr::null_mut(), |d| d.pointer),
            )
        };

        match pointer {
            _ if pointer.is_null() => Err(Error::VmNotCreated),
            _ => Ok(Self {
                pointer,
                _cache: cache,
                _dataset: dataset,
            }),
        }
    }

    /// Reinitializes the virtual machine with a new Cache.
    pub fn set_cache(&mut self, cache: Arc<RandomXCache>) {
        unsafe {
            sys::randomx_vm_set_cache(self.pointer, cache.pointer);
        }
        self._cache = Some(cache);
    }

    /// Reinitializes the virtual machine with a new Dataset.
    pub fn set_dataset(&mut self, dataset: Arc<RandomXDataset>) {
        unsafe {
            sys::randomx_vm_set_dataset(self.pointer, dataset.pointer);
        }
        self._dataset = Some(dataset);
    }

    /// Calculates a RandomX hash value.
    pub fn calculate_hash(&mut self, input: &[u8]) -> [u8; RANDOMX_HASH_SIZE] {
        let mut output = [0u8; RANDOMX_HASH_SIZE];

        unsafe {
            sys::randomx_calculate_hash(
                self.pointer,
                input.as_ptr() as *const _,
                input.len(),
                output.as_mut_ptr() as *mut _,
            );
        }

        output
    }

    /// Begins the calculation of multiple RandomX hashes.
    pub fn calculate_hash_first(&mut self, input: &[u8]) {
        unsafe {
            sys::randomx_calculate_hash_first(
                self.pointer,
                input.as_ptr() as *const _,
                input.len(),
            );
        }
    }

    /// Returns the RandomX hash value of the previous input and begins calculating the next hash.
    pub fn calculate_hash_next(&mut self, input: &[u8]) -> [u8; RANDOMX_HASH_SIZE] {
        let mut output = [0u8; RANDOMX_HASH_SIZE];

        unsafe {
            sys::randomx_calculate_hash_next(
                self.pointer,
                input.as_ptr() as *const _,
                input.len(),
                output.as_mut_ptr() as *mut _,
            );
        }

        output
    }

    /// Returns the RandomX hash value of the previous input.
    pub fn calculate_hash_last(&mut self) -> [u8; RANDOMX_HASH_SIZE] {
        let mut output = [0u8; RANDOMX_HASH_SIZE];

        unsafe {
            sys::randomx_calculate_hash_last(self.pointer, output.as_mut_ptr() as *mut _);
        }

        output
    }
}

impl Drop for RandomXVm {
    fn drop(&mut self) {
        unsafe {
            sys::randomx_destroy_vm(self.pointer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn equals_hex(hash: &[u8], hex: &str) -> bool {
        hash == &const_hex::decode(hex).unwrap()[..]
    }

    #[test]
    fn light_vm() {
        let flags = RandomXFlags::default();
        let mut cache = RandomXCache::new(flags).expect("Failed to allocate cache");
        cache.init(b"test key 000");
        let mut vm =
            RandomXVm::new(flags, Some(Arc::new(cache)), None).expect("Failed to create VM");
        let hash = vm.calculate_hash(b"This is a test");
        assert!(equals_hex(
            &hash,
            "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f"
        ));
    }

    #[test]
    fn fast_vm() {
        let flags = RandomXFlags::default() | RandomXFlags::FullMem;
        let mut cache = RandomXCache::new(flags).expect("Failed to allocate cache");
        cache.init(b"test key 000");
        let mut dataset = RandomXDataset::new(flags).expect("Failed to allocate dataset");
        dataset.init(&cache);
        let mut vm =
            RandomXVm::new(flags, None, Some(Arc::new(dataset))).expect("Failed to create VM");
        let hash = vm.calculate_hash(b"This is a test");
        assert!(equals_hex(
            &hash,
            "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f"
        ));
    }

    #[test]
    fn reinit_cache() {
        let flags = RandomXFlags::default();
        let mut cache = RandomXCache::new(flags).expect("Failed to allocate cache");
        cache.init(b"test key 000");
        let mut vm =
            RandomXVm::new(flags, Some(Arc::new(cache)), None).expect("Failed to create VM");
        let hash =
            vm.calculate_hash(b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua");
        assert!(equals_hex(
            &hash,
            "c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8"
        ));

        let mut cache = RandomXCache::new(flags).expect("Failed to allocate cache");
        cache.init(b"test key 000");
        cache.init(b"test key 001");
        vm.set_cache(Arc::new(cache));
        let hash =
            vm.calculate_hash(b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua");
        assert!(equals_hex(
            &hash,
            "e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc"
        ));
    }

    #[test]
    fn calculate_multiple_hashes() {
        let flags = RandomXFlags::default();
        let mut cache = RandomXCache::new(flags).expect("Failed to allocate cache");
        cache.init(b"test key 000");
        let mut vm =
            RandomXVm::new(flags, Some(Arc::new(cache)), None).expect("Failed to create VM");
        vm.calculate_hash_first(b"This is a test");
        let hash = vm.calculate_hash_next(b"Lorem ipsum dolor sit amet");
        assert!(equals_hex(
            &hash,
            "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f"
        ));
        let hash = vm.calculate_hash_next(
            b"sed do eiusmod tempor incididunt ut labore et dolore magna aliqua",
        );
        assert!(equals_hex(
            &hash,
            "300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969"
        ));
        let hash = vm.calculate_hash_last();
        assert!(equals_hex(
            &hash,
            "c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8"
        ));
    }
}
