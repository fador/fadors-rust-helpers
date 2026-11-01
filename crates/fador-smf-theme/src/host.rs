//! The interface between the language core and an application's functions.
//!
//! The evaluator implements the PHP standard functions by itself; everything
//! else a template may call comes from a [`HostFunctions`] implementation the
//! embedder installs. This keeps the language core usable without SMF: an
//! embedder that only needs `count()` and `sprintf()` installs nothing, while
//! [`crate::SmfFunctions`] adds the SMF theme functions.
//!
//! A host function sees its arguments as values and a [`HostContext`] that can
//! read and write the template globals and call a template function back.
//!
//! ```
//! use fador_smf_theme::{parse, EvalLimits, Evaluator, HostContext, HostFunctions, Value};
//!
//! struct Doubler;
//!
//! impl HostFunctions for Doubler {
//!     fn has(&self, name: &str) -> bool {
//!         name == "double"
//!     }
//!
//!     fn call(
//!         &mut self,
//!         name: &str,
//!         args: Vec<Value>,
//!         _context: &mut dyn HostContext,
//!     ) -> Option<Result<Value, String>> {
//!         (name == "double").then(|| {
//!             Ok(Value::Int(
//!                 args.first().map(Value::to_int).unwrap_or(0) * 2,
//!             ))
//!         })
//!     }
//! }
//!
//! let mut evaluator = Evaluator::new(EvalLimits::default());
//! evaluator.set_host(Box::new(Doubler));
//! let statements = parse("<?php function template_main() { echo double(21); } ?>").unwrap();
//! evaluator.execute(&statements).unwrap();
//! evaluator.call("template_main", Vec::new()).unwrap();
//! assert_eq!(evaluator.take_output(), "42");
//! ```

use crate::value::Value;

/// The functions an embedder adds to the template sandbox.
///
/// Implementations are looked up by lower-case name. [`HostFunctions::has`]
/// must agree with [`HostFunctions::call`]: `has` is what `function_exists()`
/// reports, and `call` returning `None` for a name it does not handle is what
/// keeps the allow-list closed.
///
/// A host function must not panic; it returns an error message instead, which
/// the evaluator turns into an [`EvalError`](crate::EvalError).
pub trait HostFunctions {
    /// Whether this host provides the function `name` (already lower case).
    fn has(&self, name: &str) -> bool;

    /// The value of a template constant, when this host defines one.
    ///
    /// SMF uses this for `SMF`, `WIRELESS` and `WYSIWYG`. A constant the
    /// embedder registered with
    /// [`Evaluator::set_constant`](crate::Evaluator::set_constant) wins.
    fn constant(&self, name: &str) -> Option<Value> {
        let _ = name;
        None
    }

    /// Call the function.
    ///
    /// Returns `None` when the host does not handle `name`, so the evaluator
    /// can report the name as outside the allow-list.
    fn call(
        &mut self,
        name: &str,
        args: Vec<Value>,
        context: &mut dyn HostContext,
    ) -> Option<Result<Value, String>>;
}

/// What a host function can see of the running template.
///
/// Every accessor is bounded by what the evaluator already holds; a host
/// cannot create a global, read a file or reach the database through this
/// interface.
pub trait HostContext {
    /// A deep copy of a global's value, or `None` when the global is unset.
    fn global(&self, name: &str) -> Option<Value>;

    /// One field of a global array, read without copying the whole array.
    ///
    /// Returns `None` when the global is unset, is not an array, or has no
    /// such key.
    fn global_field(&self, name: &str, key: &str) -> Option<Value>;

    /// Store `value` under `key` in a global array.
    ///
    /// Returns `false` when the global is unset or is not an array; a missing
    /// key is added.
    fn set_global_field(&mut self, name: &str, key: &str, value: Value) -> bool;

    /// Call a template function by name.
    ///
    /// Only functions the template itself declared can be reached, so the
    /// sandbox stays closed. The callee runs with the host still installed,
    /// and its rendered output is appended to the template's output as usual.
    ///
    /// # Errors
    ///
    /// Returns the evaluation error as a message when the function is not
    /// declared or fails.
    fn call_template(&mut self, name: &str, args: Vec<Value>) -> Result<Value, String>;
}
