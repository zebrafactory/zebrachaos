#[derive(Debug, PartialEq)]
pub enum Kind {
    Control,
    Data,
    BigData,
    Directory,
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
            3 => Ok(Self::Directory),
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
        assert_eq!(Kind::Control as u8, 0);

        assert_eq!(Kind::try_from(1).unwrap(), Kind::Data);
        assert_eq!(Kind::Data as u8, 1);

        assert_eq!(Kind::try_from(2).unwrap(), Kind::BigData);
        assert_eq!(Kind::BigData as u8, 2);

        assert_eq!(Kind::try_from(3).unwrap(), Kind::Directory);
        assert_eq!(Kind::Directory as u8, 3);
    }
}
