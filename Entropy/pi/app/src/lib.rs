//! keepcrypt-pi: ceremony, screens and the `Hal` trait shared by the device and the simulator (M3).
//!
//! Everything that ships is here (tasks/todo.md, M3 "One app, two hardware layers"): the screen
//! model (`screen`), the hardware traits that the device drivers (M4) and the simulator implement
//! (`hal`), button input and the idle timer (`input`), the frame and its renderer (`ui`), and the
//! app (`App`): the ceremony over core's typestate (`app`), the screens' models (`screens`), the
//! entry grids (`grid`), the extras it forwards to the pool (`extras`) and the waiting-screen game
//! (`games`). The simulator (pi/sim) implements `hal`; this crate never depends on it. This file
//! holds the module list and one macro only.

#![forbid(unsafe_code)]

/// Declares a unit-only enum together with `ALL`, every variant in declaration order, generated
/// from the declaration itself, so no variant can be declared and left out of the list (as in
/// core's error.rs).
macro_rules! listed_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident, )+
        }
    ) => {
        $(#[$meta])*
        pub enum $name {
            $( $(#[$vmeta])* $variant, )+
        }

        impl $name {
            /// Every variant, in declaration order. Generated with the enum, so none can be
            /// missing.
            pub const ALL: [$name; [$(stringify!($variant)),+].len()] = [$($name::$variant),+];
        }
    };
}

mod app;
pub mod extras;
mod games;
mod grid;
pub mod hal;
pub mod input;
pub mod screen;
mod screens;
pub mod ui;

pub use app::App;
