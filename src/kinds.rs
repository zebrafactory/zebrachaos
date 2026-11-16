#[derive(Debug, PartialEq)]
pub enum Kind {
    Control,
    Data,
    BigData,
    Dir,
}

#[derive(Debug, PartialEq)]
pub struct KindError(pub u8);

impl TryFrom<u8> for Kind {
    type Error = KindError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Control),
            1 => Ok(Self::Data),
            2 => Ok(Self::BigData),
            _ => Err(KindError(value)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kind() {
        assert_eq!(Kind::try_from(0).unwrap(), Kind::Control);
    }
}
