use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AddressEpochs {
    next_by_address: BTreeMap<usize, u64>,
}

impl AddressEpochs {
    pub fn next_epoch(&mut self, address: usize) -> u64 {
        let next = self.next_by_address.entry(address).or_insert(1);
        let epoch = *next;
        *next += 1;
        epoch
    }
}
