pub trait Join {
    fn join<A, B, RA, RB>(oper_a: A, oper_b: B) -> (RA, RB)
    where
        A: FnOnce() -> RA + Send,
        B: FnOnce() -> RB + Send,
        RA: Send,
        RB: Send;
}

pub enum SerialJoin {}

impl Join for SerialJoin {
    #[inline]
    fn join<A, B, RA, RB>(oper_a: A, oper_b: B) -> (RA, RB)
    where
        A: FnOnce() -> RA + Send,
        B: FnOnce() -> RB + Send,
        RA: Send,
        RB: Send,
    {
        (oper_a(), oper_b())
    }
}

#[cfg(feature = "rayon")]
pub enum RayonJoin {}

#[cfg(feature = "rayon")]
impl Join for RayonJoin {
    #[inline]
    fn join<A, B, RA, RB>(oper_a: A, oper_b: B) -> (RA, RB)
    where
        A: FnOnce() -> RA + Send,
        B: FnOnce() -> RB + Send,
        RA: Send,
        RB: Send,
    {
        rayon::join(oper_a, oper_b)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_serial_join() {
        let oper_a = || 1 + 1;
        let oper_b = || 2 + 2;
        assert_eq!((2, 4), SerialJoin::join(oper_a, oper_b));
    }

    #[test]
    #[cfg(feature = "rayon")]
    fn test_rayon_join() {
        let oper_a = || 1 + 1;
        let oper_b = || 2 + 2;
        assert_eq!((2, 4), RayonJoin::join(oper_a, oper_b));
    }
}
