//! Drawing (tasks/todo.md, M3 "One drawing path"): the only code that draws. Screens build
//! `screen::Screen` models; this module owns the one `Frame` they are drawn into, and only it can
//! make one. The renderer and its painters land in group 6.

mod frame;

pub use frame::{Frame, SIDE};
