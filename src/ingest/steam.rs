//! `UserID` parsing: SteamID64 or legacy `STEAM_X:Y:Z`.

/// SteamID64 of account 0 in the public universe (individual accounts).
const BASE: u64 = 76_561_197_960_265_728;
const ACCOUNT_MASK: u64 = 0xFFFF_FFFF;

#[derive(Debug, PartialEq, Eq)]
pub struct InvalidOwner;

/// `Ok(None)` means anonymous (absent or `0`); `Err` means the value was
/// present but not a Steam ID, which callers treat as anonymous after logging.
pub fn parse_owner(raw: &str) -> Result<Option<i64>, InvalidOwner> {
    let raw = raw.trim();
    if raw.is_empty() || raw == "0" {
        return Ok(None);
    }

    let id = if raw.len() >= 6 && raw[..6].eq_ignore_ascii_case("STEAM_") {
        let mut parts = raw[6..].split(':');
        let (universe, y, z) = (parts.next(), parts.next(), parts.next());
        if parts.next().is_some() {
            return Err(InvalidOwner);
        }
        let (Some(universe), Some(y), Some(z)) = (universe, y, z) else {
            return Err(InvalidOwner);
        };
        if universe.is_empty() || !universe.bytes().all(|b| b.is_ascii_digit()) {
            return Err(InvalidOwner);
        }
        let y: u64 = match y {
            "0" => 0,
            "1" => 1,
            _ => return Err(InvalidOwner),
        };
        let z: u64 = z.parse().map_err(|_| InvalidOwner)?;
        BASE.checked_add(z.checked_shl(1).ok_or(InvalidOwner)? | y)
            .ok_or(InvalidOwner)?
    } else {
        if !raw.bytes().all(|b| b.is_ascii_digit()) {
            return Err(InvalidOwner);
        }
        raw.parse::<u64>().map_err(|_| InvalidOwner)?
    };

    // Same check as the PHP version: the high 32 bits must be the universe/type.
    if id & !ACCOUNT_MASK != BASE {
        return Err(InvalidOwner);
    }
    i64::try_from(id).map(Some).map_err(|_| InvalidOwner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymous() {
        assert_eq!(parse_owner(""), Ok(None));
        assert_eq!(parse_owner("0"), Ok(None));
        assert_eq!(parse_owner(" 0 "), Ok(None));
    }

    #[test]
    fn steam64() {
        assert_eq!(
            parse_owner("76561197960268197"),
            Ok(Some((BASE + 2469) as i64))
        );
    }

    #[test]
    fn legacy_format() {
        assert_eq!(
            parse_owner("STEAM_0:1:1234"),
            Ok(Some((BASE + 2469) as i64))
        );
        assert_eq!(
            parse_owner("steam_1:0:1234"),
            Ok(Some((BASE + 2468) as i64))
        );
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "abc",
            "12345",
            "-1",
            "STEAM_0:2:5",
            "STEAM_0:1",
            "STEAM_0:1:2:3",
            "STEAM_:1:2",
            "STEAM_0:1:99999999999999",
            "76561197960265727",
            "99999999999999999999",
        ] {
            assert_eq!(parse_owner(bad), Err(InvalidOwner), "{bad}");
        }
    }
}
