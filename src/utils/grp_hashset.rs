use rand::{self, Rng};
use std::collections::HashSet;

//Growable randomly popped Hashmap
pub struct GrpHashset {
    pub vec: Vec<Vec<u8>>,
    pub hashset: HashSet<Vec<u8>>,
    pub count: usize,
    pub max_size: usize,
    pub rng: rand::rngs::ThreadRng,
}

pub trait GrpHashsetCacheMethods {
    fn new(max_size: usize) -> GrpHashset;
    fn contains(&self, key: &[u8]) -> bool;
    //fn get(&self, key: &[u8]) -> Option<&Vec<u8>>;
    fn insert(&mut self, key: &[u8]) -> bool;
}

impl GrpHashsetCacheMethods for GrpHashset {
    fn new(max_size: usize) -> Self {
        GrpHashset {
            vec: vec![],
            hashset: HashSet::new(),
            count: 0,
            max_size,
            rng: rand::rng(),
        }
    }

    //fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
    //self.hashset.get(key)
    //}

    fn contains(&self, value: &[u8]) -> bool {
        HashSet::contains(&self.hashset, value)
    }

    fn insert(&mut self, value: &[u8]) -> bool {
        self.count += 1;
        let result = HashSet::insert(&mut self.hashset, value.to_vec());
        self.vec.push(value.to_vec());
        if self.count >= self.max_size {
            let index_to_delete: usize = self.rng.random_range(0..self.max_size);

            let item_to_delete = self
                .vec
                .get(index_to_delete)
                .expect("Random generator caused overflow at GrpHashmap::insert")
                .clone();

            self.vec.remove(index_to_delete);
            HashSet::remove(&mut self.hashset, &item_to_delete);
        }
        result
    }
}
