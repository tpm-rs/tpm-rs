//! Internal compile-time helper macros.
//!
//! Ideally we would use [`Iterator::find`] and [`Iterator::max`] instead of
//! these macros. But these are currently not callable in const contexts on
//! Stable.

/// Returns the maximum unsigned integer value produced when applying
/// a `fn(T) -> uN` function to each element of a `[T]` slice.
macro_rules! max_by {
    ($vals:expr, $f:expr) => {{
        let vals: &[_] = $vals;
        let mut max_val = 0;
        let mut i = 0;
        while i < vals.len() {
            let v = $f(vals[i]);
            if v > max_val {
                max_val = v;
            }
            i += 1;
        }
        max_val
    }};
}

/// Returns the maximum of one or more integer values.
///
/// Values after the first may be preceded by `#[cfg(...)]` attributes, in
/// which case they only contribute to the maximum if the configuration
/// predicate holds. Use `0` as the first value if all other values are
/// conditional.
macro_rules! max {
    // Internal rules: update `$max` with each remaining value, collecting any
    // attributes in `[...]` so they can be applied to that value's block.
    (@rest $max:ident; []) => {};
    (@rest $max:ident; [$($attrs:tt)*] #[$m:meta] $($rest:tt)*) => {
        max!(@rest $max; [$($attrs)* #[$m]] $($rest)*)
    };
    (@rest $max:ident; [$($attrs:tt)*] $val:expr $(, $($rest:tt)*)?) => {
        $($attrs)*
        {
            let v = $val;
            if v > $max {
                $max = v;
            }
        }
        max!(@rest $max; [] $($($rest)*)?)
    };
    ($first:expr $(, $($rest:tt)*)?) => {{
        #[allow(unused_mut)]
        let mut max_val = $first;
        max!(@rest max_val; [] $($($rest)*)?);
        max_val
    }};
}

/// Returns `Some(x)` for the first element `x` in `$vals` satisfying the
/// given closure-like predicate, or `None` if no element matches.
macro_rules! find_by {
    ($vals:expr, |$x:ident| $cond:expr) => {{
        let vals: &[_] = $vals;
        let mut res = None;
        let mut i = 0;
        while i < vals.len() {
            let $x = vals[i];
            if $cond {
                res = Some($x);
                break;
            }
            i += 1;
        }
        res
    }};
}

#[cfg(test)]
mod tests {
    const fn double(x: usize) -> usize {
        x * 2
    }

    #[test]
    fn test_max() {
        const M1: usize = max!(5);
        const M2: usize = max!(1, 5, 3, 9, 2);
        const M3: usize = max!(10, 20, 30,);
        assert_eq!(M1, 5);
        assert_eq!(M2, 9);
        assert_eq!(M3, 30);
    }

    #[test]
    fn test_max_cfg() {
        const M1: usize = max!(
            1,
            #[cfg(any())]
            50,
            #[cfg(all())]
            7,
            3
        );
        const M2: u16 = max!(
            0,
            #[cfg(any())]
            8,
            #[cfg(all())]
            #[cfg(any())]
            9
        );
        assert_eq!(M1, 7);
        assert_eq!(M2, 0);
    }

    #[test]
    fn test_max_by() {
        const EMPTY: &[usize] = &[];
        const M_EMPTY: usize = max_by!(EMPTY, double);
        const M_FN: usize = max_by!(&[1, 5, 3], double);
        assert_eq!(M_EMPTY, 0);
        assert_eq!(M_FN, 10);
    }

    #[test]
    fn test_find_by() {
        const EMPTY: &[i32] = &[];
        const F_EMPTY: Option<i32> = find_by!(EMPTY, |x| x % 2 == 0);
        const F_FN: Option<i32> = find_by!(&[1, 3, 4, 6], |x| x % 2 == 0);
        const F_NONE: Option<i32> = find_by!(&[1, 3, 5], |x| x > 10);
        assert_eq!(F_EMPTY, None);
        assert_eq!(F_FN, Some(4));
        assert_eq!(F_NONE, None);
    }
}
