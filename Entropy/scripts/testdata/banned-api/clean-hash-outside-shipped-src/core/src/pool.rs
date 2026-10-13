// Ordered collections hash nothing.
let mut seen = BTreeSet::new();
let map: BTreeMap<u8, u8> = BTreeMap::new();
let digest = hash_one_record(&record);
let rehash_one = false;
