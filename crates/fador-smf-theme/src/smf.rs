//! The functions SMF itself defines for its theme templates.
//!
//! The language core only knows PHP's standard functions. Everything SMF adds
//! — `create_button()`, `allowedTo()`, `theme_copyright()`, `timeformat()`,
//! `comma_format()`, `cleanXml()`, `JavaScriptEscape()` and the
//! `theme_inline_permissions()` helper — lives here, behind the
//! [`HostFunctions`] interface, so an embedder that does not render SMF themes
//! never links it into a template.
//!
//! All of it is pure string work over the globals the embedder seeded
//! (`$txt`, `$settings`, `$user_info`, `$modSettings`, `$context`,
//! `$scripturl`, `$forum_version`, `$forum_copyright`). Nothing here reads the
//! database, the filesystem or the network.

use crate::builtins::{number_format, php_sprintf};
use crate::host::{HostContext, HostFunctions};
use crate::time::{format_time, OffsetType, TimeSettings, TimeStrings, TodayKind};
use crate::value::{Key, PhpArray, Value};
use std::time::{SystemTime, UNIX_EPOCH};

/// The SMF theme host functions.
///
/// Stateless: every input is read from the template globals, so one instance
/// can serve any number of renders. Install it with
/// [`Evaluator::set_host`](crate::Evaluator::set_host).
#[derive(Debug, Clone, Copy, Default)]
pub struct SmfFunctions;

impl HostFunctions for SmfFunctions {
    fn has(&self, name: &str) -> bool {
        matches!(
            name,
            "allowedto"
                | "allowed_to"
                | "call_integration_hook"
                | "cleanxml"
                | "comma_format"
                | "create_button"
                | "javascriptescape"
                | "theme_copyright"
                | "theme_inline_permissions"
                | "timeformat"
                | "un_htmlspecialchars"
                | "unhtmlspecialchars"
        )
    }

    fn constant(&self, name: &str) -> Option<Value> {
        match name {
            // The template dialect's compile-time constants. SMF defines them
            // in its entry point; the port keeps the values the templates
            // branch on.
            "SMF" => Some(Value::Int(1)),
            "WIRELESS" => Some(Value::Bool(false)),
            "WYSIWYG" => Some(Value::Bool(false)),
            _ => None,
        }
    }

    fn call(
        &mut self,
        name: &str,
        args: Vec<Value>,
        context: &mut dyn HostContext,
    ) -> Option<Result<Value, String>> {
        let result = match name {
            "un_htmlspecialchars" | "unhtmlspecialchars" => {
                let text = args.first().map(Value::to_php_string).unwrap_or_default();
                Ok(Value::Str(fador_core::util::html_unescape_compat(&text)))
            }
            "javascriptescape" => {
                let text = args.first().map(Value::to_php_string).unwrap_or_default();
                let scripturl = context
                    .global("scripturl")
                    .map(|value| value.to_php_string())
                    .unwrap_or_default();
                Ok(Value::Str(javascript_escape(&text, &scripturl)))
            }
            "allowedto" | "allowed_to" => {
                let is_admin = context
                    .global_field("user_info", "is_admin")
                    .map(|value| value.to_bool())
                    .unwrap_or(false);
                if is_admin {
                    return Some(Ok(Value::Bool(true)));
                }
                let requested = args.first().cloned().unwrap_or(Value::Null);
                let names = if let Some(array) = requested.as_array() {
                    array
                        .borrow()
                        .values()
                        .iter()
                        .map(Value::to_php_string)
                        .collect::<Vec<_>>()
                } else {
                    vec![requested.to_php_string()]
                };
                let allowed = context
                    .global_field("user_info", "permissions")
                    .as_ref()
                    .and_then(Value::as_array)
                    .map(|array| {
                        array.borrow().values().iter().any(|value| {
                            let value = value.to_php_string();
                            names.iter().any(|name| value.eq_ignore_ascii_case(name))
                        })
                    })
                    .unwrap_or(false);
                Ok(Value::Bool(allowed))
            }
            "create_button" => {
                let name = args.first().map(Value::to_php_string).unwrap_or_default();
                let alt = args.get(1).map(Value::to_php_string).unwrap_or_default();
                let label = args.get(2).map(Value::to_php_string).unwrap_or_default();
                let custom = args.get(3).map(Value::to_php_string).unwrap_or_default();
                let text = |key: &str| {
                    context
                        .global_field("txt", key)
                        .map(|value| value.to_php_string())
                        .unwrap_or_else(|| key.to_string())
                };
                let use_image_buttons = context
                    .global_field("settings", "use_image_buttons")
                    .map(|value| value.to_bool())
                    .unwrap_or(true);
                if !use_image_buttons {
                    return Some(Ok(Value::Str(text(&alt))));
                }
                let use_buttons = context
                    .global_field("settings", "use_buttons")
                    .map(|value| value.to_bool())
                    .unwrap_or(false);
                let images = context
                    .global_field("settings", "lang_images_url")
                    .map(|value| value.to_php_string())
                    .filter(|value| !value.is_empty())
                    .or_else(|| {
                        context
                            .global_field("settings", "images_url")
                            .map(|value| value.to_php_string())
                    })
                    .unwrap_or_default();
                let source = if use_buttons {
                    format!("{images}/buttons/{name}")
                } else {
                    format!("{images}/{name}")
                };
                let label_html = if label.is_empty() {
                    String::new()
                } else {
                    format!("<strong>{}</strong>", text(&label))
                };
                let source_escaped = fador_core::util::html_escape_compat(&source);
                Ok(Value::Str(format!(
                    "<img src=\"{source_escaped}\" alt=\"{}\" {custom} />{label_html}",
                    fador_core::util::html_escape_compat(&text(&alt))
                )))
            }
            "theme_inline_permissions" => {
                let permission = args.first().map(Value::to_php_string).unwrap_or_default();
                let groups = context
                    .global_field("context", &permission)
                    .unwrap_or(Value::Null);
                context.set_global_field("context", "current_permission", Value::Str(permission));
                context.set_global_field("context", "member_groups", groups);
                if let Err(message) =
                    context.call_template("template_inline_permissions", Vec::new())
                {
                    return Some(Err(message));
                }
                Ok(Value::Null)
            }
            "theme_copyright" => {
                let version = context
                    .global("forum_version")
                    .map(|value| value.to_php_string())
                    .unwrap_or_else(|| "SMF 2.0.19".into());
                let copyright = context
                    .global("forum_copyright")
                    .map(|value| value.to_php_string())
                    .unwrap_or_default();
                if copyright.is_empty() {
                    return Some(Ok(Value::Str(String::new())));
                }
                let mut formatted = php_sprintf(&copyright, &[Value::Str(version)]);
                if context
                    .global_field("modSettings", "force_gdpr")
                    .is_some_and(|value| value.to_bool())
                {
                    let scripturl = context
                        .global("scripturl")
                        .map(|value| value.to_php_string())
                        .unwrap_or_default();
                    let terms = context
                        .global_field("txt", "terms_and_policies")
                        .map(|value| value.to_php_string())
                        .unwrap_or_default();
                    formatted.push_str(&format!(
                        " | <a id=\"button_agreement\" href=\"{scripturl}?action=agreement\"><span>{terms}</span></a>"
                    ));
                }
                Ok(Value::Str(format!(
                    "\n\t\t\t<span class=\"smalltext\" style=\"display: inline; visibility: visible; font-family: Verdana, Arial, sans-serif;\">{formatted}\n\t\t\t</span>"
                )))
            }
            "cleanxml" => {
                let text = args.first().map(Value::to_php_string).unwrap_or_default();
                Ok(Value::Str(clean_xml(&text)))
            }
            // The server has no integration hooks; SMF's call is a no-op that
            // returns an empty array.
            "call_integration_hook" => Ok(Value::from_array(PhpArray::new())),
            "comma_format" => {
                let value = args.first().cloned().unwrap_or(Value::Null);
                let format = context
                    .global_field("txt", "number_format")
                    .map(|value| value.to_php_string())
                    .unwrap_or_default();
                Ok(Value::Str(comma_format(&value, &format)))
            }
            "timeformat" => {
                let timestamp = args.first().map(Value::to_int).unwrap_or(0);
                let kind_value = args.get(1).cloned().unwrap_or(Value::Bool(true));
                let offset_value = args.get(2).cloned().unwrap_or(Value::Bool(false));
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|duration| duration.as_secs() as i64)
                    .unwrap_or(0);
                let settings = time_settings(context);
                let strings = time_strings(context);
                let kind = match &kind_value {
                    Value::Bool(true) => TodayKind::Today,
                    Value::Str(format) if !format.is_empty() => TodayKind::Custom(format),
                    _ => TodayKind::User,
                };
                let offset = match &offset_value {
                    Value::Bool(false) | Value::Null => OffsetType::UserAndForum,
                    Value::Str(value) if value == "forum" => OffsetType::ForumOnly,
                    _ => OffsetType::None,
                };
                Ok(Value::Str(format_time(
                    timestamp, now, kind, offset, &settings, &strings,
                )))
            }
            _ => return None,
        };
        Some(result)
    }
}

/// Read SMF's date settings from `$user_info` and `$modSettings`.
fn time_settings(context: &dyn HostContext) -> TimeSettings {
    let format = context
        .global_field("user_info", "time_format")
        .map(|value| value.to_php_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            context
                .global_field("modSettings", "time_format")
                .map(|value| value.to_php_string())
        })
        .unwrap_or_else(|| "%B %d, %Y, %I:%M:%S %p".into());
    TimeSettings {
        format,
        today_mod: context
            .global_field("modSettings", "todayMod")
            .map(|value| value.to_int())
            .unwrap_or(0),
        user_offset: context
            .global_field("user_info", "time_offset")
            .map(|value| value.to_float())
            .unwrap_or(0.0),
        forum_offset: context
            .global_field("modSettings", "time_offset")
            .map(|value| value.to_float())
            .unwrap_or(0.0),
        zone: context
            .global_field("modSettings", "default_timezone")
            .map(|value| value.to_php_string())
            .unwrap_or_default(),
    }
}

/// Read the localized day, month and "today" names from `$txt`.
fn time_strings(context: &dyn HostContext) -> TimeStrings {
    let get = |key: &str| context.global_field("txt", key);
    TimeStrings {
        days: indexed_strings(get("days"), 0, 7),
        days_short: indexed_strings(get("days_short"), 0, 7),
        months: indexed_strings(get("months"), 1, 12),
        months_short: indexed_strings(get("months_short"), 1, 12),
        time_am: get("time_am")
            .map(|value| value.to_php_string())
            .unwrap_or_default(),
        time_pm: get("time_pm")
            .map(|value| value.to_php_string())
            .unwrap_or_default(),
        today: get("today")
            .map(|value| value.to_php_string())
            .unwrap_or_default(),
        yesterday: get("yesterday")
            .map(|value| value.to_php_string())
            .unwrap_or_default(),
        capitalize: get("lang_capitalize_dates").is_some_and(|value| value.to_bool()),
    }
}

/// Read `count` consecutive integer keys starting at `start` from an array.
fn indexed_strings(value: Option<Value>, start: i64, count: usize) -> Vec<String> {
    let Some(array) = value.as_ref().and_then(Value::as_array) else {
        return Vec::new();
    };
    let array = array.borrow();
    (0..count)
        .map(|offset| {
            array
                .get(&Key::Int(start + offset as i64))
                .map(|cell| cell.borrow().to_php_string())
                .unwrap_or_default()
        })
        .collect()
}

/// SMF's `JavaScriptEscape()`: wrap text in single quotes and break every
/// sequence that could end a script or start a tag.
fn javascript_escape(text: &str, scripturl: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    let mut rest = text;
    while !rest.is_empty() {
        let mut replaced = false;
        for (from, to) in [
            ("</", "<' + '/"),
            ("script", "scri'+'pt"),
            ("<a href", "<a hr'+'ef"),
        ] {
            if rest.starts_with(from) {
                out.push_str(to);
                rest = &rest[from.len()..];
                replaced = true;
                break;
            }
        }
        if replaced {
            continue;
        }
        if !scripturl.is_empty() && rest.starts_with(scripturl) {
            out.push_str(scripturl);
            out.push_str("'+'");
            rest = &rest[scripturl.len()..];
            continue;
        }
        let c = rest.chars().next().unwrap();
        match c {
            '\r' => {}
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            _ => out.push(c),
        }
        rest = &rest[c.len_utf8()..];
    }
    out.push('\'');
    out
}

/// SMF's `cleanXml()`: drop the control characters XML 1.0 forbids.
fn clean_xml(text: &str) -> String {
    text.chars()
        .filter(|c| {
            let value = *c as u32;
            !(value <= 0x08
                || value == 0x0B
                || value == 0x0C
                || (0x0E..=0x19).contains(&value)
                || value == 0xFFFE
                || value == 0xFFFF)
        })
        .collect()
}

/// `comma_format()`: apply `$txt['number_format']` to a value.
fn comma_format(value: &Value, format: &str) -> String {
    let Some((thousands, decimal, decimals)) = parse_number_format(format) else {
        return value.to_php_string();
    };
    match value {
        Value::Float(value) => number_format(*value, decimals, &decimal, &thousands),
        Value::Int(value) => number_format(*value as f64, 0, &decimal, &thousands),
        Value::Str(text) => {
            if let Ok(number) = text.parse::<f64>() {
                number_format(
                    number,
                    if text.contains('.') { decimals } else { 0 },
                    &decimal,
                    &thousands,
                )
            } else {
                text.clone()
            }
        }
        _ => value.to_php_string(),
    }
}

/// Parse SMF's `$txt['number_format']` shape, for example `1,234.00`.
fn parse_number_format(format: &str) -> Option<(String, String, usize)> {
    let bytes = format.as_bytes();
    if bytes.first() != Some(&b'1') {
        return None;
    }
    let mut index = 1;
    let thousands_start = index;
    while index < bytes.len() && !bytes[index].is_ascii_digit() {
        index += 1;
    }
    let thousands = format[thousands_start..index].to_string();
    if !format[index..].starts_with("234") {
        return None;
    }
    index += 3;
    let decimal_start = index;
    while index < bytes.len() && !bytes[index].is_ascii_digit() {
        index += 1;
    }
    let decimal = format[decimal_start..index].to_string();
    let decimals = &format[index..];
    if !decimals.chars().all(|c| c == '0') {
        return None;
    }
    Some((thousands, decimal, decimals.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse, EvalLimits, Evaluator};

    fn evaluator() -> Evaluator {
        let mut evaluator = Evaluator::new(EvalLimits::default());
        evaluator.set_host(Box::new(SmfFunctions));
        let mut txt = PhpArray::new();
        txt.insert(Key::Str("title".into()), Value::Str("Hello".into()));
        txt.insert(Key::Str("save".into()), Value::Str("Save".into()));
        txt.insert(
            Key::Str("number_format".into()),
            Value::Str("1,234.00".into()),
        );
        txt.insert(
            Key::Str("terms_and_policies".into()),
            Value::Str("Terms".into()),
        );
        txt.insert(
            Key::Str("days".into()),
            Value::from_array(indexed_array(&[
                "Sunday",
                "Monday",
                "Tuesday",
                "Wednesday",
                "Thursday",
                "Friday",
                "Saturday",
            ])),
        );
        txt.insert(
            Key::Str("days_short".into()),
            Value::from_array(indexed_array(&[
                "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat",
            ])),
        );
        txt.insert(
            Key::Str("months".into()),
            Value::from_array(indexed_array(&[
                "January",
                "February",
                "March",
                "April",
                "May",
                "June",
                "July",
                "August",
                "September",
                "October",
                "November",
                "December",
            ])),
        );
        txt.insert(
            Key::Str("months_short".into()),
            Value::from_array(indexed_array(&[
                "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
            ])),
        );
        txt.insert(Key::Str("time_am".into()), Value::Str("am".into()));
        txt.insert(Key::Str("time_pm".into()), Value::Str("pm".into()));
        evaluator.set_global("txt", Value::from_array(txt));
        let mut settings = PhpArray::new();
        settings.insert(
            Key::Str("images_url".into()),
            Value::Str("/Themes/default/images".into()),
        );
        settings.insert(Key::Str("use_image_buttons".into()), Value::Bool(true));
        settings.insert(Key::Str("use_buttons".into()), Value::Bool(true));
        evaluator.set_global("settings", Value::from_array(settings));
        evaluator.set_global(
            "scripturl",
            Value::Str("https://example.test/forums/index.php".into()),
        );
        evaluator
    }

    fn indexed_array(values: &[&str]) -> PhpArray {
        let mut array = PhpArray::new();
        for (index, value) in values.iter().enumerate() {
            array.insert(Key::Int(index as i64), Value::Str((*value).to_string()));
        }
        array
    }

    fn render(evaluator: &mut Evaluator, code: &str) -> String {
        let statements = parse(code).unwrap();
        evaluator.execute(&statements).unwrap();
        let _ = evaluator.take_output();
        evaluator.call("template_main", Vec::new()).unwrap();
        evaluator.take_output()
    }

    #[test]
    fn timeformat_reads_user_globals() {
        let mut eval = evaluator();
        let mut user = PhpArray::new();
        user.insert(
            Key::Str("time_format".into()),
            Value::Str("%Y-%m-%d %H:%M".into()),
        );
        user.insert(Key::Str("time_offset".into()), Value::Float(0.0));
        eval.set_global("user_info", Value::from_array(user));
        let mut mods = PhpArray::new();
        mods.insert(Key::Str("todayMod".into()), Value::Int(0));
        mods.insert(Key::Str("time_offset".into()), Value::Int(0));
        eval.set_global("modSettings", Value::from_array(mods));

        let output = render(
            &mut eval,
            "<?php function template_main() { echo timeformat(0, false), '|', timeformat(0, '%Y'); } ?>",
        );
        assert_eq!(output, "1970-01-01 00:00|1970");
    }

    #[test]
    fn timeformat_uses_the_board_zone_and_today_label() {
        let mut eval = evaluator();
        let mut user = PhpArray::new();
        user.insert(
            Key::Str("time_format".into()),
            Value::Str("%B %d, %Y, %H:%M".into()),
        );
        eval.set_global("user_info", Value::from_array(user));
        let mut mods = PhpArray::new();
        mods.insert(
            Key::Str("default_timezone".into()),
            Value::Str("Europe/Helsinki".into()),
        );
        mods.insert(Key::Str("todayMod".into()), Value::Int(2));
        eval.set_global("modSettings", Value::from_array(mods));
        let txt = eval.global("txt").unwrap();
        let array = txt.as_array().unwrap().clone();
        array
            .borrow_mut()
            .insert(Key::Str("today".into()), Value::Str("Today at ".into()));
        array.borrow_mut().insert(
            Key::Str("yesterday".into()),
            Value::Str("Yesterday at ".into()),
        );
        eval.set_global("txt", txt);

        // 2026-07-01T00:00:00Z is 03:00 EEST.
        let output = render(
            &mut eval,
            "<?php function template_main() { echo timeformat(1782864000, '%H:%M'); } ?>",
        );
        assert_eq!(output, "03:00");
    }

    #[test]
    fn theme_copyright_formats_the_language_global() {
        let mut eval = evaluator();
        eval.set_global("forum_version", Value::Str("SMF 2.0.19".into()));
        eval.set_global(
            "forum_copyright",
            Value::Str("<a href=\"credits\">%1$s</a>".into()),
        );
        let output = render(
            &mut eval,
            "<?php function template_main() { echo theme_copyright(); } ?>",
        );
        assert!(output.contains("<a href=\"credits\">SMF 2.0.19</a>"));
        assert!(output.starts_with("\n\t\t\t<span class=\"smalltext\""));
    }

    #[test]
    fn theme_copyright_can_add_the_agreement_link() {
        let mut eval = evaluator();
        eval.set_global("forum_copyright", Value::Str("© %1$s".into()));
        let mut mods = PhpArray::new();
        mods.insert(Key::Str("force_gdpr".into()), Value::Bool(true));
        eval.set_global("modSettings", Value::from_array(mods));
        let output = render(
            &mut eval,
            "<?php function template_main() { echo theme_copyright(); } ?>",
        );
        assert!(output.contains("button_agreement"));
        assert!(output.contains(">Terms<"));
    }

    #[test]
    fn comma_format_follows_the_language_format() {
        assert_eq!(comma_format(&Value::Int(2256), "1,234.00"), "2,256");
        assert_eq!(comma_format(&Value::Int(2256), "1 234,00"), "2 256");
        assert_eq!(
            comma_format(&Value::Int(2256), "Default number format"),
            "2256"
        );
        assert_eq!(
            comma_format(&Value::Str("12.5".into()), "1,234.00"),
            "12.50"
        );
        assert_eq!(
            parse_number_format("1,234.00"),
            Some((",".into(), ".".into(), 2))
        );
        assert!(parse_number_format("Default number format").is_none());
    }

    #[test]
    fn create_button_builds_an_image_or_a_label() {
        let mut eval = evaluator();
        let output = render(
            &mut eval,
            "<?php function template_main() { echo create_button('save.gif', 'save'); } ?>",
        );
        assert_eq!(
            output,
            "<img src=\"/Themes/default/images/buttons/save.gif\" alt=\"Save\"  />"
        );
        let output = render(
            &mut eval,
            "<?php function template_main() { echo create_button('save.gif', 'save', 'save'); } ?>",
        );
        assert_eq!(
            output,
            "<img src=\"/Themes/default/images/buttons/save.gif\" alt=\"Save\"  /><strong>Save</strong>"
        );

        let mut settings = PhpArray::new();
        settings.insert(Key::Str("use_image_buttons".into()), Value::Bool(false));
        eval.set_global("settings", Value::from_array(settings));
        let output = render(
            &mut eval,
            "<?php function template_main() { echo create_button('save.gif', 'save'); } ?>",
        );
        assert_eq!(output, "Save");
    }

    #[test]
    fn allowedto_checks_permissions_and_the_admin_flag() {
        let mut eval = evaluator();
        let mut user = PhpArray::new();
        let mut permissions = PhpArray::new();
        permissions.insert(Key::Int(0), Value::Str("post_new".into()));
        user.insert(
            Key::Str("permissions".into()),
            Value::from_array(permissions),
        );
        user.insert(Key::Str("is_admin".into()), Value::Bool(false));
        eval.set_global("user_info", Value::from_array(user));
        let output = render(
            &mut eval,
            "<?php function template_main() { echo allowedTo('post_new') ? 'yes' : 'no', allowedTo(array('post_new', 'x')) ? 'yes' : 'no', allowedTo('admin') ? 'yes' : 'no'; } ?>",
        );
        assert_eq!(output, "yesyesno");

        let mut user = PhpArray::new();
        user.insert(Key::Str("is_admin".into()), Value::Bool(true));
        eval.set_global("user_info", Value::from_array(user));
        let output = render(
            &mut eval,
            "<?php function template_main() { echo allowedTo('anything') ? 'yes' : 'no'; } ?>",
        );
        assert_eq!(output, "yes");
    }

    #[test]
    fn theme_inline_permissions_renders_the_template_function() {
        let mut eval = evaluator();
        let mut context = PhpArray::new();
        let mut groups = PhpArray::new();
        groups.insert(Key::Int(0), Value::Int(1));
        context.insert(Key::Str("view_own_posts".into()), Value::from_array(groups));
        eval.set_global("context", Value::from_array(context));
        let output = render(
            &mut eval,
            "<?php function template_inline_permissions() { global $context; echo $context['current_permission'], ':', count($context['member_groups']); } function template_main() { theme_inline_permissions('view_own_posts'); } ?>",
        );
        assert_eq!(output, "view_own_posts:1");
    }

    #[test]
    fn javascript_escape_breaks_tags_and_quotes() {
        assert_eq!(javascript_escape("a'b", ""), "'a\\'b'");
        assert_eq!(javascript_escape("</script>", ""), "'<' + '/scri'+'pt>'");
        assert_eq!(
            javascript_escape("https://x/y", "https://x/y"),
            "'https://x/y'+''"
        );
        let mut eval = evaluator();
        let output = render(
            &mut eval,
            "<?php function template_main() { echo JavaScriptEscape(\"a'b\"); } ?>",
        );
        assert_eq!(output, "'a\\'b'");
    }

    #[test]
    fn cleanxml_drops_control_characters() {
        assert_eq!(clean_xml("a\u{1}b\tc\nd"), "ab\tc\nd");
    }

    #[test]
    fn integration_hooks_and_constants_are_stubs() {
        let mut eval = evaluator();
        let output = render(
            &mut eval,
            "<?php function template_main() { echo count(call_integration_hook('x')), SMF, WIRELESS ? 'w' : '-', WYSIWYG ? 'y' : '-'; } ?>",
        );
        assert_eq!(output, "01--");
    }

    #[test]
    fn unknown_smf_function_is_outside_the_allow_list() {
        let mut eval = evaluator();
        let statements =
            parse("<?php function template_main() { echo get_database(); } ?>").unwrap();
        eval.execute(&statements).unwrap();
        let error = eval.call("template_main", Vec::new()).unwrap_err();
        assert!(error.message.contains("allow-list"), "{}", error.message);
    }
}
