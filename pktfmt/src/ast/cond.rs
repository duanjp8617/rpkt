use std::collections::HashMap;
use std::fmt;
use std::ops::{Bound, RangeBounds};

use super::{max_value, BitPos, BuiltinTypes, Error, Field, Header};

#[derive(Copy, Clone, Debug)]
pub struct CondBounds {
    pub start: Bound<u64>,
    pub end: Bound<u64>,
}

impl CondBounds {
    fn update_end(&mut self, max_end: u64) {
        match self.end {
            Bound::Unbounded => self.end = Bound::Included(max_end),
            Bound::Included(original_max_end) => {
                if original_max_end > max_end {
                    self.end = Bound::Included(max_end)
                }
            }
            Bound::Excluded(original_max_end) => {
                if max_end < u64::MAX && original_max_end > max_end + 1 {
                    self.end = Bound::Included(max_end)
                }
            }
        }
    }

    pub fn from_range<B: RangeBounds<u64>>(b: B) -> Self {
        Self {
            start: b.start_bound().map(|v| *v),
            end: b.end_bound().map(|v| *v),
        }
    }

    // The `intersect` and `is_empty` are currently unstable,
    // we just copy the code from the stdlib here.
    pub fn is_empty(&self) -> bool {
        use std::ops::Bound::*;
        !match (self.start, self.end) {
            (Unbounded, Excluded(n)) => n > 0,
            (Included(n), Unbounded) => n < u64::MAX,
            (Unbounded, _) | (_, Unbounded) => true,
            (Included(start), Excluded(end))
            | (Excluded(start), Included(end))
            | (Excluded(start), Excluded(end)) => start < end,
            (Included(start), Included(end)) => start <= end,
        }
    }

    // The `intersect` and `is_empty` are currently unstable,
    // we just copy the code from the stdlib here.
    pub fn intersect(&self, other: &Self) -> Self {
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

        Self { start, end }
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
    cond_map: HashMap<BitPos, (String, Vec<CondBounds>)>,
}

impl Cond {
    /// Retrive a map that maps the starting bit position of the cond field, to
    /// the field name and the cond field ranges.
    ///
    /// This reverse map helps analysis and generation of group parser code.
    pub fn cond_map(&self) -> &HashMap<BitPos, (String, Vec<CondBounds>)> {
        &self.cond_map
    }

    pub fn from_cond_list(
        conds: Vec<(String, Vec<CondBounds>)>,
        header: &Header,
    ) -> Result<Self, Error> {
        // Make sure the following hold:
        let cond_checker = |field_name: &String,
                            bounds: &mut Vec<CondBounds>|
         -> Result<(&Field, BitPos), Error> {
            // 1. cond contains a valid field name
            let (field, bitpos) = header.field(field_name).ok_or(Error::cond(
                1,
                format!("invalid field name in cond expression: {field_name}"),
            ))?;

            // 2. `repr` is u8/u16/u32/u64
            if field.repr == BuiltinTypes::ByteSlice {
                return_err!(Error::cond(
                    2,
                    format!("repr of field {field_name} is a byte slice")
                ));
            }

            for i in 0..bounds.len() {
                let original_bound = bounds[i];
                bounds[i].update_end(max_value(field.bit).unwrap());

                // 4. the defined range should be non-empty after the update
                if bounds[i].is_empty() {
                    return_err!(Error::cond(
                        4,
                        format!("range {} is invalid for field {field_name}", original_bound)
                    ));
                }

                // 6. the defined ranges overlap.
                for prev_bound in (&bounds[..i]).iter() {
                    if !prev_bound.intersect(&bounds[i]).is_empty() {
                        return_err!(Error::cond(
                            6,
                            format!("field {field_name} has intersected ranges")
                        ));
                    }
                }
            }

            Ok((field, bitpos))
        };

        let mut cond_map: HashMap<BitPos, (String, Vec<CondBounds>)> = HashMap::new();
        for (field_name, mut bounds) in conds.into_iter() {
            // Make sure the the defined condition branch is valid.
            let (_, bitpos) = cond_checker(&field_name, &mut bounds)?;

            match cond_map.insert(bitpos, (field_name.clone(), bounds)) {
                None => {}
                Some(_) => return_err!(Error::cond(
                    7,
                    format!("duplicated cond field {field_name}")
                )),
            }
        }

        if cond_map.len() > 8 {
            return_err!(Error::cond(8, format!("too many distinctive cond fields")));
        }

        Ok(Self { cond_map })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn bounds_empty() {
        assert_eq!(CondBounds::from_range(0..=0).is_empty(), false);
        assert_eq!(CondBounds::from_range(..0).is_empty(), true);
        assert_eq!(CondBounds::from_range(u64::MAX..).is_empty(), true);
        assert_eq!(CondBounds::from_range(3..3).is_empty(), true);
        assert_eq!(CondBounds::from_range(3..=3).is_empty(), false);
        assert_eq!(CondBounds::from_range(5..=3).is_empty(), true);
    }

    #[test]
    fn intersect_test() {
        let b = CondBounds::from_range(3..=3).intersect(&CondBounds::from_range(4..=4));
        println!("{:?}, {:?}", b.start, b.end);
        println!("{}", b.is_empty());
    }

    #[test]
    fn print_bounds() {
        let mut buf: Vec<u8> = vec![];
        write!(&mut buf, "{}", CondBounds::from_range(3..=3)).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "3");
    }
}
