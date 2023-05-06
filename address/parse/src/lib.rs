use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum AddressParseError {
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),
    #[error("Invalid address length")]
    InvalidLength,
}

#[derive(Clone, Debug, Error)]
pub enum SubnetParseError {
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),
    #[error("Invalid address length")]
    InvalidLength,
    #[error("Invalid subnet prefix length")]
    InvalidPrefixLen,
}

impl From<AddressParseError> for SubnetParseError {
    fn from(e: AddressParseError) -> Self {
        match e {
            AddressParseError::ParseInt(e) => Self::from(e),
            AddressParseError::InvalidLength => Self::InvalidLength,
        }
    }
}

pub fn parse_subnet<R, F>(
    s: &str,
    parse_addr: F,
    max_prefix_len: u32,
) -> Result<(R, u32), SubnetParseError>
where
    F: for<'a> FnOnce(&'a str) -> Result<R, AddressParseError>,
{
    match s.rfind('/') {
        Some(pos) => {
            let addr = parse_addr(&s[..pos])?;
            let prefix_len: u32 = s[(pos + 1)..].parse()?;
            if prefix_len > max_prefix_len {
                Err(SubnetParseError::InvalidPrefixLen)
            } else {
                Ok((addr, prefix_len))
            }
        }
        None => Ok((parse_addr(s)?, max_prefix_len)),
    }
}

pub fn parse_ipv4_subnet(s: &str) -> Result<([u8; 4], u32), SubnetParseError> {
    parse_subnet(s, parse_ipv4, 32)
}

pub fn parse_ipv6_subnet(s: &str) -> Result<([u8; 16], u32), SubnetParseError> {
    parse_subnet(s, parse_ipv6, 128)
}

pub fn parse_hw(s: &str, addr: &mut [u8]) -> Result<(), AddressParseError> {
    let mut iter = s.split(|c: char| c == ':' || c == '-');
    for byte in addr.iter_mut() {
        *byte = u8::from_str_radix(iter.next().ok_or(AddressParseError::InvalidLength)?, 16)?;
    }
    iter.next()
        .ok_or(())
        .err()
        .ok_or(AddressParseError::InvalidLength)?;
    Ok(())
}

pub fn parse_ipv4(s: &str) -> Result<[u8; 4], AddressParseError> {
    let mut addr = [0u8; 4];
    let mut iter = s.split('.');
    addr[0] = iter
        .next()
        .ok_or(AddressParseError::InvalidLength)?
        .parse()?;
    addr[1] = iter
        .next()
        .ok_or(AddressParseError::InvalidLength)?
        .parse()?;
    addr[2] = iter
        .next()
        .ok_or(AddressParseError::InvalidLength)?
        .parse()?;
    addr[3] = iter
        .next()
        .ok_or(AddressParseError::InvalidLength)?
        .parse()?;
    iter.next()
        .ok_or(())
        .err()
        .ok_or(AddressParseError::InvalidLength)?;
    Ok(addr)
}

pub fn parse_ipv6(s: &str) -> Result<[u8; 16], AddressParseError> {
    let mut addr = [0u8; 16];
    let mut idx = 0usize;

    let mut iter = s.split("::");
    let Some(first) = iter.next() else {
        return Err(AddressParseError::InvalidLength);
    };

    if !first.is_empty() {
        for word in first.split(':') {
            if idx >= 16 {
                return Err(AddressParseError::InvalidLength);
            }

            match u16::from_str_radix(word, 16) {
                Ok(word) => {
                    let w = word.to_be_bytes();
                    addr[idx] = w[0];
                    idx += 1;
                    addr[idx] = w[1];
                    idx += 1;
                }
                Err(e) => {
                    if idx == 12 {
                        if let Some(_) = iter.next() {
                            return Err(AddressParseError::InvalidLength);
                        }
                        let ipv4 = parse_ipv4(word)?;
                        addr[12] = ipv4[0];
                        addr[13] = ipv4[1];
                        addr[14] = ipv4[2];
                        addr[15] = ipv4[3];
                        return Ok(addr);
                    } else {
                        return Err(AddressParseError::from(e));
                    }
                }
            }
        }
    }

    if let Some(second) = iter.next() {
        if let Some(_) = iter.next() {
            return Err(AddressParseError::InvalidLength);
        }

        let end = idx;
        idx = 15;

        if !second.is_empty() {
            for word in second.split(':').rev() {
                if idx < end {
                    return Err(AddressParseError::InvalidLength);
                }

                match u16::from_str_radix(word, 16) {
                    Ok(word) => {
                        let w = word.to_be_bytes();
                        addr[idx] = w[1];
                        idx -= 1;
                        addr[idx] = w[0];
                        idx -= 1;
                    }
                    Err(e) => {
                        if idx == 15 {
                            if let Some(_) = iter.next() {
                                return Err(AddressParseError::InvalidLength);
                            }
                            let ipv4 = parse_ipv4(word)?;
                            addr[12] = ipv4[0];
                            addr[13] = ipv4[1];
                            addr[14] = ipv4[2];
                            addr[15] = ipv4[3];
                            return Ok(addr);
                        } else {
                            return Err(AddressParseError::from(e));
                        }
                    }
                }
            }
        }
    } else if idx < 16 {
        return Err(AddressParseError::InvalidLength);
    }

    Ok(addr)
}
