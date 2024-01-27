use lambdaworks_math::{
    cyclic_group::IsGroup, elliptic_curve::traits::IsEllipticCurve, unsigned_integer::element::U256,
};

use crate::{
    secp256k1::curve::{Point, Secp256k1},
    PrivateKey,
};

#[derive(Debug)]
pub struct PublicKey {
    pub(crate) point: Point,
}

impl PublicKey {
    pub(crate) fn new(point: Point) -> Self {
        Self { point }
    }

    pub(crate) fn from_u256(integer: U256) -> Self {
        let point = Secp256k1::generator().operate_with_self(integer);
        Self::new(point)
    }

    pub fn from_private_key(s: PrivateKey) -> Self {
        Self::from_u256(s.into())
    }

    pub(crate) fn point(&self) -> &Point {
        &self.point
    }
}
