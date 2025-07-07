use std::collections::HashMap;
use std::fmt;
use std::ops::{Bound, RangeBounds};

use super::{max_value, BuiltinTypes, Error, Header};

#[derive(Copy, Clone, Debug)]
pub struct CondBounds {
    pub start: Bound<u64>,
    pub end: Bound<u64>,
}

impl CondBounds {
    pub fn from_range<B: RangeBounds<u64>>(b: B) -> Self {
        Self {
            start: b.start_bound().map(|v| *v),
            end: b.end_bound().map(|v| *v),
        }
    }

    // The `intersect` and `is_empty` are currently unstable,
    // we just copy the code from the stdlib here.
    fn is_empty(&self) -> bool {
        use std::ops::Bound::*;
        !match (self.start, self.end) {
            (Unbounded, _) | (_, Unbounded) => true,
            (Included(start), Excluded(end))
            | (Excluded(start), Included(end))
            | (Excluded(start), Excluded(end)) => start < end,
            (Included(start), Included(end)) => start <= end,
        }
    }

    // Since the contained bound is non-empty, we can
    // always derive a valid max_value
    fn max_value(&self) -> u64 {
        debug_assert!(!self.is_empty());
        match self.end {
            Bound::Unbounded => u64::MAX,
            Bound::Included(n) => n,
            Bound::Excluded(n) => n - 1,
        }
    }

    // The `intersect` and `is_empty` are currently unstable,
    // we just copy the code from the stdlib here.
    fn intersect(&self, other: &Self) -> bool {
        use std::ops::Bound::*;

        let (self_start, self_end) = (self.start, self.end);
        let (other_start, other_end) = (other.start, other.end);

        let start = match (self_start, other_start) {
            (Included(a), Included(b)) => Included(Ord::max(a, b)),
            (Excluded(a), Excluded(b)) => Excluded(Ord::max(a, b)),
            (Unbounded, Unbounded) => Unbounded,

            (x, Unbounded) | (Unbounded, x) => x,

            (Included(i), Excluded(e)) | (Excluded(e), Included(i)) => {
                if i > e {
                    Included(i)
                } else {
                    Excluded(e)
                }
            }
        };
        let end = match (self_end, other_end) {
            (Included(a), Included(b)) => Included(Ord::min(a, b)),
            (Excluded(a), Excluded(b)) => Excluded(Ord::min(a, b)),
            (Unbounded, Unbounded) => Unbounded,

            (x, Unbounded) | (Unbounded, x) => x,

            (Included(i), Excluded(e)) | (Excluded(e), Included(i)) => {
                if i < e {
                    Included(i)
                } else {
                    Excluded(e)
                }
            }
        };

        !Self { start, end }.is_empty()
    }
}

impl fmt::Display for CondBounds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.start, self.end) {
            (Bound::Included(n), Bound::Included(m)) if n == m => write!(f, "{n}"),
            (Bound::Included(n), Bound::Excluded(m)) if n + 1 == m => write!(f, "{n}"),
            _ => {
                match self.start {
                    Bound::Unbounded => write!(f, "..")?,
                    Bound::Included(n) => write!(f, "{n}..")?,
                    Bound::Excluded(_) => {
                        // Make sure that the start bound is not excluded.
                        panic!()
                    }
                }
                match self.end {
                    Bound::Unbounded => Ok(()),
                    Bound::Included(n) => write!(f, "={n}"),
                    Bound::Excluded(n) => write!(f, "{n}"),
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct Cond {
    cond_map: HashMap<String, Vec<CondBounds>>,
}

impl Cond {
    pub fn field_names(&self) -> impl Iterator<Item = &str> {
        self.cond_map.keys().map(|s| &s[..])
    }

    pub fn ranges(&self, field_name: &str) -> Option<&Vec<CondBounds>> {
        self.cond_map.get(field_name)
    }

    pub fn from_cond_list(
        conds: Vec<(String, CondBounds)>,
        header: &Header,
    ) -> Result<Self, Error> {
        // Make sure the following hold:
        // 1. cond contains a valid field name
        // 2. `repr` is u8/u16/u32/u64
        // 3. the range specified by the cond does not exceeds the bit limit of the
        //    field.
        // 4. the defined range is not empty
        // 5. the field's `gen` is true, meaning that it is not a length-related field.
        let cond_checker = |field_name: &String, bounds: &CondBounds| -> Result<(), Error> {
            let (field, _) = header.field(field_name).ok_or(Error::cond(
                1,
                format!("invalid field name in cond expression: {field_name}"),
            ))?;

            if field.repr == BuiltinTypes::ByteSlice {
                return_err!(Error::cond(
                    2,
                    "field repr can not be a byte slice".to_string()
                ));
            }

            if bounds.max_value() > max_value(field.bit).unwrap() {
                return_err!(Error::cond(
                    3,
                    format!(
                        "the max value of range {} exceeds the allowed value of field {}",
                        bounds, field_name
                    )
                ));
            }

            if bounds.is_empty() {
                return_err!(Error::cond(4, format!("invalid range {}", bounds)));
            }

            if !field.gen {
                return_err!(Error::cond(5, "field gen must be true".to_string()));
            }

            Ok(())
        };

        let mut cond_map: HashMap<String, Vec<CondBounds>> = HashMap::new();
        for (field_name, bounds) in conds.into_iter() {
            // make sure the the defined condition branch is valid.
            cond_checker(&field_name, &bounds)?;
            match cond_map.get_mut(&field_name) {
                Some(existing) => {
                    // the compared field has appeared, make sure that
                    // the current range does not overlap with previously
                    // defined ranges
                    for existing_bounds in existing.iter() {
                        if bounds.intersect(existing_bounds) {
                            return_err!(Error::cond(
                                6,
                                format!(
                                    "bounds {} and {} have intersections",
                                    existing_bounds, bounds
                                )
                            ));
                        }
                    }
                    existing.push(bounds);
                }
                None => {
                    // create a new enty in the map
                    cond_map.insert(field_name, vec![bounds]);
                }
            }
        }

        Ok(Self { cond_map })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_fuck() {
        let n1 = 5;
        let n2 = 16;

        match (n1, n2) {
            (2..=4 | 2..8, 15..19) => println!("bingo"),
            (2..8, _) => println!("fuck"),
            _ => println!("fuckfuck"),
        }
    }
}
