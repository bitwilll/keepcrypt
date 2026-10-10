//! Registry dates and their freshness (docs/seal-watchonly-braille.md "Checking the seal",
//! "Go-ahead QR"; tasks/todo.md, M1 Q5 and group 7; tasks/lessons.md: the Pi has no clock).
//!
//! - A snapshot header carries its UTC date as the decimal number YYYYMMDD (a u32). Only a real
//!   Gregorian date in years 1-9999 is accepted; anything else is `BadDate`.
//! - Freshness against the shell's `today`: Future when the date is after today, Current up to 30
//!   days old, Stale from day 31. It is the shell's warning, never a refusal: core has no clock.
//!   Phones warn on Stale and Future; the Pi shows the date and asks the user to confirm it.

use crate::error::{CoreError, SnapshotError};

/// Days a snapshot or proof stays Current.
pub(crate) const FRESH_DAYS: i64 = 30;

/// A calendar date, as a registry header writes it (YYYYMMDD) or a shell's clock gives it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RegistryDate {
    year: u16,
    month: u8,
    day: u8,
}

/// How old a snapshot or proof is, against the shell's `today`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Freshness {
    /// At most 30 days old.
    Current,
    /// 31 days old or more: phones warn.
    Stale,
    /// Dated after today: phones warn, since a clock or a snapshot is wrong.
    Future,
}

impl RegistryDate {
    /// A date from its parts: a real Gregorian date, years 1-9999, else `Snapshot(BadDate)`.
    pub fn new(year: u16, month: u8, day: u8) -> Result<Self, CoreError> {
        if (1..=9999).contains(&year)
            && (1..=12).contains(&month)
            && day >= 1
            && day <= days_in_month(year, month)
        {
            Ok(Self { year, month, day })
        } else {
            Err(CoreError::Snapshot(SnapshotError::BadDate))
        }
    }

    /// A date from the decimal number YYYYMMDD, as a header holds it.
    pub fn from_yyyymmdd(value: u32) -> Result<Self, CoreError> {
        let bad = CoreError::Snapshot(SnapshotError::BadDate);
        let year = u16::try_from(value / 10_000).map_err(|_| bad)?;
        let month = u8::try_from(value / 100 % 100).map_err(|_| bad)?;
        let day = u8::try_from(value % 100).map_err(|_| bad)?;
        Self::new(year, month, day)
    }

    /// The decimal number YYYYMMDD.
    pub fn yyyymmdd(&self) -> u32 {
        u32::from(self.year) * 10_000 + u32::from(self.month) * 100 + u32::from(self.day)
    }

    /// The year, 1-9999.
    pub fn year(&self) -> u16 {
        self.year
    }

    /// The month, 1-12.
    pub fn month(&self) -> u8 {
        self.month
    }

    /// The day of the month, from 1.
    pub fn day(&self) -> u8 {
        self.day
    }

    /// Days since 1 March of year 0 in the proleptic Gregorian calendar (H. Hinnant's
    /// days_from_civil), so two dates' difference is their distance in days.
    fn day_number(&self) -> i64 {
        let month = i64::from(self.month);
        let year = i64::from(self.year) - i64::from(month <= 2);
        let era = year.div_euclid(400);
        let year_of_era = year - era * 400;
        let day_of_year =
            (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(self.day) - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        era * 146_097 + day_of_era
    }

    /// Current up to 30 days before `today`, Stale from day 31, Future after `today`.
    pub(crate) fn freshness(&self, today: RegistryDate) -> Freshness {
        let age = today.day_number() - self.day_number();
        if age < 0 {
            Freshness::Future
        } else if age <= FRESH_DAYS {
            Freshness::Current
        } else {
            Freshness::Stale
        }
    }
}

fn is_leap(year: u16) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn date(value: u32) -> RegistryDate {
        RegistryDate::from_yyyymmdd(value).expect("a valid date")
    }

    #[test]
    fn real_dates_only() {
        for good in [
            20260301, 20280229, 20000229, 20261231, 20260131, 20260430, 10101, 99991231, 21000228,
        ] {
            assert_eq!(date(good).yyyymmdd(), good, "{good}");
        }
        for bad in [
            20260229,
            21000229,
            19000229,
            20261310,
            20260001,
            20260300,
            20260431,
            20260132,
            101,
            0,
            100_000_101,
            u32::MAX,
            20261300,
        ] {
            assert_eq!(
                RegistryDate::from_yyyymmdd(bad),
                Err(CoreError::Snapshot(SnapshotError::BadDate)),
                "{bad}"
            );
        }
        assert_eq!(RegistryDate::new(2026, 3, 1), Ok(date(20260301)));
        assert_eq!(
            RegistryDate::new(0, 1, 1),
            Err(CoreError::Snapshot(SnapshotError::BadDate))
        );
        let d = date(20260301);
        assert_eq!((d.year(), d.month(), d.day()), (2026, 3, 1));
    }

    // The boundaries: day 30 is Current, day 31 Stale, one day ahead Future, across February,
    // a leap day and a year end.
    #[test]
    fn freshness_boundaries() {
        let cases = [
            (20260130, 20260301, Freshness::Current),
            (20260129, 20260301, Freshness::Stale),
            (20260302, 20260301, Freshness::Future),
            (20260301, 20260301, Freshness::Current),
            (20280131, 20280301, Freshness::Current),
            (20280130, 20280301, Freshness::Stale),
            (20261202, 20270101, Freshness::Current),
            (20261201, 20270101, Freshness::Stale),
            (20270101, 20261231, Freshness::Future),
            (10101, 99991231, Freshness::Stale),
            (99991231, 10101, Freshness::Future),
        ];
        for (dated, today, want) in cases {
            assert_eq!(
                date(dated).freshness(date(today)),
                want,
                "{dated} on {today}"
            );
        }
        assert_eq!(date(20000301).day_number() - date(20000228).day_number(), 2);
        assert_eq!(date(19000301).day_number() - date(19000228).day_number(), 1);
    }
}
