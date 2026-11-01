//! End-to-end checks of the public API with small inline packs.
//!
//! These tests deliberately use only the crate's exported items, so a missing
//! re-export or a private type in a public signature fails the build.

use fador_i18n::{
    format_date_php, format_placeholders, format_strftime, format_strftime_in_zone, is_known,
    is_valid_zone_name, local_parts, normalize_language_code, offset_for, plural_form,
    select_plural, zone_names, DateTimeNames, EmbeddedPacks, Json, LanguagePack, LanguageSet,
    LocalTime, PackError, PosixTz, TimeStrings, TzError, Tzdb, Zone, MAX_PADDING, MAX_ZONES,
    PLURAL_RULES,
};
use fador_testutil::{iterations, Rng};

const EN: &str = r#"{
    "code": "en",
    "english_name": "English",
    "messages": {
        "PLURAL_RULE": 1,
        "WELCOME": "Welcome, %1$s!",
        "POSTS": ["no posts", "1 post", "%d posts"],
        "PROFILE": {"contact": {"email": "Email"}, "age": 42}
    },
    "files": {
        "common": {"lang": {"INDEX": "Index page"}},
        "viewtopic": {"lang": {"NO_UNREAD_POSTS": "No unread posts in this topic"}}
    },
    "tz": {"UTC_OFFSET": "UTC%s", "Europe/Helsinki": "Helsinki"},
    "datetime": {"Thursday": "Thursday", "Thu": "Thu", "July": "July", "Jul": "Jul"}
}"#;

const FI: &str = r#"{
    "code": "fi",
    "english_name": "Finnish",
    "messages": {
        "PLURAL_RULE": 1,
        "WELCOME": "Tervetuloa, %1$s!",
        "POSTS": {"0": "ei viestejä", "1": "1 viesti", "2": "%d viestiä"}
    },
    "files": {"common": {"lang": {"INDEX": "Etusivu"}}},
    "datetime": {"Wednesday": "Keskiviikko", "Wed": "Ke", "Thursday": "Torstai", "Thu": "To", "July": "Heinäkuu", "Jul": "Heinä"}
}"#;

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

#[test]
fn packs_resolve_messages_per_pack_file_and_page() {
    let en = LanguagePack::from_json(EN, "en").expect("English pack");
    let fi = LanguagePack::from_json(FI, "fi").expect("Finnish pack");
    let set = LanguageSet::new(fi, en);

    assert_eq!(set.primary().code(), "fi");
    assert_eq!(set.fallback().code(), "en");
    assert_eq!(set.lang("WELCOME", &args(&["Ada"])), "Tervetuloa, Ada!");
    assert_eq!(set.lang("POSTS", &args(&["0"])), "ei viestejä");
    assert_eq!(set.lang("POSTS", &args(&["3"])), "3 viestiä");
    assert_eq!(set.lang_file("common", "INDEX", &[]), "Etusivu");
    assert_eq!(
        set.lang_page(&["common", "viewtopic"], "NO_UNREAD_POSTS", &[]),
        "No unread posts in this topic"
    );
    assert_eq!(
        set.nested("PROFILE", &["contact", "email"]).as_deref(),
        Some("Email")
    );
    assert_eq!(set.nested("PROFILE", &["age"]).as_deref(), Some("42"));
    assert_eq!(set.timezone_label("Europe/Helsinki"), "Helsinki");
    assert_eq!(set.timezone_label("UTC"), "UTC");
    assert_eq!(set.lang("MISSING", &[]), "MISSING");
    assert!(matches!(
        set.primary().message("POSTS"),
        Some(Json::Object(_))
    ));

    // Selecting the fallback swaps the two packs and keeps both reachable.
    let english = set.select("en_US");
    assert_eq!(english.primary().code(), "en");
    assert_eq!(english.fallback().code(), "fi");
    assert_eq!(english.lang_file("common", "INDEX", &[]), "Index page");
    assert_eq!(normalize_language_code(" FI "), "fi");
}

#[test]
fn embedded_registry_and_disk_loading_agree() {
    let embedded = EmbeddedPacks::new().add("en", EN).add("fi", FI);
    assert_eq!(embedded.len(), 2);
    let set =
        LanguageSet::load_with_embedded("fi", std::path::Path::new("does-not-exist"), &embedded)
            .expect("both packs come from the registry");
    assert_eq!(set.primary().code(), "fi");
    assert_eq!(set.fallback().code(), "en");
    assert_eq!(set.lang("WELCOME", &args(&["Ada"])), "Tervetuloa, Ada!");
    assert!(matches!(
        LanguagePack::from_embedded(&embedded, "de"),
        Err(PackError::UnknownLanguage(_))
    ));
    assert!(matches!(
        LanguagePack::from_json("[1, 2]", "en"),
        Err(PackError::NotAnObject)
    ));
    assert!(matches!(
        LanguagePack::from_json("{", "en"),
        Err(PackError::Json(_))
    ));
}

#[test]
fn plural_rules_and_placeholders_are_public() {
    assert_eq!(PLURAL_RULES, 16);
    assert_eq!(plural_form(1, 1), 1);
    assert_eq!(plural_form(0, 1), 2);
    assert_eq!(plural_form(21, 7), 1);
    assert_eq!(plural_form(22, 7), 2);
    let forms = ["no posts", "1 post", "%d posts"];
    assert_eq!(select_plural(&forms, Some(0), 1), Some(&"no posts"));
    assert_eq!(select_plural(&forms, Some(2), 1), Some(&"%d posts"));

    assert_eq!(format_placeholders("%s", &args(&["a"])), "a");
    assert_eq!(
        format_placeholders("%1$s has %2$d posts", &args(&["Ada", "3"])),
        "Ada has 3 posts"
    );
    assert_eq!(format_placeholders("%.2f", &args(&["3.14159"])), "3.14");
    assert_eq!(format_placeholders("%05d", &args(&["42"])), "00042");
    assert_eq!(
        format_placeholders("%x/%X", &args(&["255", "255"])),
        "ff/FF"
    );
    assert_eq!(format_placeholders("100%%", &[]), "100%");
    assert_eq!(MAX_PADDING, 65_535);
}

#[test]
fn dates_use_localized_names_and_zone_rules() {
    let en = LanguagePack::from_json(EN, "en").unwrap();
    let fi = LanguagePack::from_json(FI, "fi").unwrap();

    assert_eq!(
        en.format_date(1_782_907_200, "Europe/Helsinki", "D d.m.Y H:i T"),
        "Wed 01.07.2026 15:00 EEST"
    );
    assert_eq!(
        fi.format_date(1_782_907_200, "Europe/Helsinki", "D d.m.Y H:i"),
        "Ke 01.07.2026 15:00"
    );

    let names = DateTimeNames::english();
    assert_eq!(
        format_date_php(Tzdb::embedded(), &names, true, 0, "UTC", "l jS F Y H:i"),
        "Thursday 1st January 1970 00:00"
    );
    assert_eq!(
        format_date_php(Tzdb::embedded(), &names, true, 0, "UTC", r"\Y-\m-\d"),
        "Y-m-d"
    );

    let strings = TimeStrings::english();
    assert_eq!(
        format_strftime("%B %d, %Y, %I:%M:%S %p", 0, &strings),
        "January 01, 1970, 12:00:00 am"
    );
    assert_eq!(
        format_strftime_in_zone("%H:%M %d.%m.%Y", 0, "Etc/GMT-2", &strings),
        "02:00 01.01.1970"
    );
}

#[test]
fn timezone_database_is_public_and_covers_2040() {
    let tz = Tzdb::embedded();
    assert!(tz.len() > 400);
    assert!(tz.len() <= MAX_ZONES);
    assert!(tz.is_known("Europe/Helsinki"));
    assert!(tz.is_known("Z"));
    assert!(!tz.is_known("Not/AZone"));
    assert!(zone_names().iter().any(|zone| zone == "America/New_York"));
    assert!(is_known("America/New_York"));

    assert_eq!(offset_for("Europe/Helsinki", 1_782_907_200), 10_800);
    assert_eq!(
        tz.offset_for("Europe/Helsinki", 2_225_966_400),
        Some(10_800)
    );
    assert_eq!(
        tz.offset_for("America/New_York", 2_210_241_600),
        Some(-18_000)
    );
    assert_eq!(
        tz.offset_for("America/New_York", 2_225_966_400),
        Some(-14_400)
    );
    assert_eq!(
        tz.abbreviation("Europe/Helsinki", 2_225_966_400).as_deref(),
        Some("EEST")
    );
    assert_eq!(tz.is_dst("Europe/Helsinki", 2_210_241_600), Some(false));

    let local = tz.local_parts("Europe/Helsinki", 1_784_151_000).unwrap();
    assert_eq!(
        local,
        LocalTime {
            year: 2026,
            month: 7,
            day: 16,
            hour: 0,
            minute: 30,
            second: 0,
        }
    );
    assert_eq!(local.parts(), (2026, 7, 16, 0, 30, 0));
    assert_eq!(local.weekday(), 4);
    assert_eq!(local.day_of_year(), 197);
    assert_eq!(local_parts("Europe/Helsinki", 1_784_151_000), Some(local));
    assert_eq!(tz.local_parts("Not/AZone", 0), None);
}

#[test]
fn posix_rules_and_zone_names_are_public() {
    let rule = PosixTz::parse("EET-2EEST,M3.5.0/3,M10.5.0/4").expect("EU rule");
    assert_eq!(rule.std_name(), "EET");
    assert_eq!(rule.dst_name(), Some("EEST"));
    assert_eq!(rule.std_offset(), 7_200);
    assert_eq!(rule.dst_offset(), Some(10_800));
    assert_eq!(rule.offset_at(2_216_250_000), 10_800);
    assert_eq!(rule.offset_at(2_234_998_800), 7_200);
    assert_eq!(rule.name_at(2_225_966_400), "EEST");
    assert!(PosixTz::parse("").is_none());

    assert!(is_valid_zone_name("Europe/Helsinki"));
    assert!(!is_valid_zone_name("../UTC"));
    assert!(!is_valid_zone_name("Europe//UTC"));

    let tz = Tzdb::default();
    assert!(tz.is_empty());
    let error = Zone::parse_tzif(b"TZif").unwrap_err();
    assert_eq!(error, TzError::Truncated);
}

#[test]
fn fuzz_public_parsers_do_not_panic() {
    let mut rng = Rng::new(0x4a11_0001);
    let cases = iterations(200);
    let zones = [
        "UTC",
        "Europe/Helsinki",
        "America/New_York",
        "Not/AZone",
        "",
    ];
    let formats = [
        "Y-m-d H:i:s",
        "%B %e, %Y",
        "%s %d %x",
        "D d.m.Y",
        "\\Y %% %j",
    ];
    for _ in 0..cases {
        let spec_length = rng.below(64);
        let spec = rng.text(spec_length);
        let _ = PosixTz::parse(&spec);
        let _ = is_valid_zone_name(&spec);
        let _ = LanguagePack::from_json(&spec, "xx");
        let _ = Tzdb::from_archive(spec.as_bytes());

        let format = formats[rng.below(formats.len())];
        let stamp = (rng.next_u64() % 4_000_000_000) as i64 - 1_000_000_000;
        let zone = zones[rng.below(zones.len())];
        let _ = offset_for(zone, stamp);
        let _ = local_parts(zone, stamp);
        let _ = format_date_php(
            Tzdb::embedded(),
            &DateTimeNames::english(),
            true,
            stamp,
            zone,
            format,
        );
        let _ = format_strftime(format, stamp, &TimeStrings::english());
        let _ = format_placeholders(format, &args(&[spec.as_str(), "1", "-1"]));
    }
    for hostile in fador_testutil::MALICIOUS_STRINGS {
        let _ = PosixTz::parse(hostile);
        let _ = is_valid_zone_name(hostile);
        let _ = LanguagePack::from_json(hostile, "xx");
        let _ = format_placeholders(hostile, &args(&["%s", "%%"]));
    }
}
