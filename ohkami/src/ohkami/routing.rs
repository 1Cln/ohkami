#![allow(non_snake_case, unused_mut)]

use crate::Ohkami;
use crate::fang::handler::{Handler, IntoHandler};
use crate::fang::{BoxedFPC, Fang};
use crate::router::{base::Router, segments::RouteSegments};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct HandlerMeta {
    pub(crate) name: &'static str,
    pub(crate) n_pathparams: usize,
}
impl HandlerMeta {
    fn new<T, H: IntoHandler<T>>(h: &H) -> Self {
        Self {
            name: std::any::type_name::<H>(),
            n_pathparams: h.n_pathparams(),
        }
    }
}
impl std::fmt::Debug for HandlerMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("HandlerMeta")
            .field("name", &self.name)
            .field("n_pathparams", &self.n_pathparams)
            .finish()
    }
}

macro_rules! HandlerSet {
    ($( $method:ident ),*) => {
        pub struct HandlerSet {
            pub(crate) route: RouteSegments,
            $(
                pub(crate) $method: Option<(Handler, HandlerMeta)>,
            )*
        }

        impl HandlerSet {
            pub(crate) fn new(route_str: impl Into<std::borrow::Cow<'static, str>>) -> Self {
                Self {
                    route: RouteSegments::from_literal(route_str),
                    $(
                        $method: None,
                    )*
                }
            }
        }

        impl HandlerSet {
            $(
                pub fn $method<T, H: IntoHandler<T>>(mut self, handler: H) -> Self {
                    let meta = HandlerMeta::new::<T, H>(&handler);
                    self.$method = Some((handler.into_handler(), meta));
                    self
                }
            )*
        }
    };
}
HandlerSet! { GET, PUT, POST, PATCH, DELETE }

pub struct ByAnother {
    pub(crate) route: RouteSegments,
    pub(crate) ohkami: Ohkami,
}

macro_rules! Route {
    ($( $method:ident ),*) => {
        /// Core trait for Ohkami's routing definition.
        ///
        /// <br>
        ///
        /// *example.rs*
        /// ```no_run
        /// use ohkami::{Ohkami, Route};
        ///
        /// async fn index() -> &'static str {
        ///     "ohkami"
        /// }
        ///
        /// async fn greet() -> &'static str {
        ///     "I'm fine."
        /// }
        ///
        /// async fn hello() -> String {
        ///     format!("Hello!!!")
        /// }
        ///
        /// #[tokio::main]
        /// async fn main() {
        ///     Ohkami::new((
        ///         "/"  // <-- `Route` works here...
        ///             .GET(index),
        ///         "/hello"  // <-- `Route` works here...
        ///             .GET(greet)
        ///             .PUT(hello),
        ///     )).howl("localhost:3000").await
        /// }
        /// ```
        pub trait Route: Sized {
            $(
                fn $method<T>(self, handler: impl IntoHandler<T>) -> HandlerSet;
            )*

            /// Route to another Ohkami instance.
            fn By(self, another: Ohkami) -> ByAnother;
        }

        impl Route for &'static str {
            $(
                fn $method<T>(self, handler: impl IntoHandler<T>) -> HandlerSet {
                    HandlerSet::new(self).$method(handler)
                }
            )*

            fn By(self, another: Ohkami) -> ByAnother {
                ByAnother {
                    route:  RouteSegments::from_literal(self),
                    ohkami: another,
                }
            }
        }
    };
}
Route! { GET, PUT, POST, PATCH, DELETE }

trait RoutingItem {
    fn apply(self, router: &mut Router);
}
const _: () = {
    impl RoutingItem for HandlerSet {
        fn apply(self, router: &mut Router) {
            router.register_handlers(self)
        }
    }

    impl RoutingItem for ByAnother {
        fn apply(self, router: &mut Router) {
            router.merge_another(self)
        }
    }

    impl RoutingItem for Ohkami {
        fn apply(self, router: &mut Router) {
            router.merge_another(ByAnother {
                route: RouteSegments::from_literal("/"),
                ohkami: self,
            })
        }
    }

    impl RoutingItem for &'static str {
        fn apply(self, _router: &mut Router) {}
    }
};

pub trait Routing<Fangs = ()> {
    fn apply(self, target: &mut Ohkami);
}
const _: () = {
    impl Routing<()> for () {
        fn apply(self, _target: &mut Ohkami) {}
    }
    impl<R: RoutingItem> Routing<()> for R {
        fn apply(self, target: &mut Ohkami) {
            <R as RoutingItem>::apply(self, &mut target.router)
        }
    }

    /// for better developer experience
    impl<F: Fang<BoxedFPC> + 'static> Routing<std::marker::PhantomData<F>> for F {
        fn apply(self, target: &mut Ohkami) {
            target.fangs = Some(Arc::new(self));
        }
    }
    impl<F: Fang<BoxedFPC> + 'static> Routing<(std::marker::PhantomData<F>,)> for (F,) {
        fn apply(self, target: &mut Ohkami) {
            let (f,) = self;
            target.fangs = Some(Arc::new(f));
        }
    }

    macro_rules! routing {
        ( $( $item:ident ),+ ) => {
            impl<$( $item: RoutingItem ),+> Routing<()> for ( $($item,)+ ) {
                fn apply(self, target: &mut Ohkami) {
                    let ( $( $item, )+ ) = self;
                    $(
                        <$item as RoutingItem>::apply($item, &mut target.router);
                    )+
                }
            }
        };
    }
    routing!(R1);
    routing!(R1, R2);
    routing!(R1, R2, R3);
    routing!(R1, R2, R3, R4);
    routing!(R1, R2, R3, R4, R5);
    routing!(R1, R2, R3, R4, R5, R6);
    routing!(R1, R2, R3, R4, R5, R6, R7);
    routing!(R1, R2, R3, R4, R5, R6, R7, R8);
    routing!(R1, R2, R3, R4, R5, R6, R7, R8, R9);
    routing!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10);
    routing!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11);
    routing!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12);

    macro_rules! routing_with_1_fang {
        ( $( $item:ident ),+ ) => {
            impl<F1, $( $item: RoutingItem ),+> Routing<(F1,)> for ( F1, $($item,)+ )
            where
                F1: Fang<BoxedFPC> + 'static,
            {
                fn apply(self, target: &mut Ohkami) {
                    let ( f1, $( $item, )+ ) = self;
                    target.fangs = Some(Arc::new(f1));
                    $(
                        <$item as RoutingItem>::apply($item, &mut target.router);
                    )+
                }
            }
        };
    }
    routing_with_1_fang!(R1);
    routing_with_1_fang!(R1, R2);
    routing_with_1_fang!(R1, R2, R3);
    routing_with_1_fang!(R1, R2, R3, R4);
    routing_with_1_fang!(R1, R2, R3, R4, R5);
    routing_with_1_fang!(R1, R2, R3, R4, R5, R6);
    routing_with_1_fang!(R1, R2, R3, R4, R5, R6, R7);
    routing_with_1_fang!(R1, R2, R3, R4, R5, R6, R7, R8);
    routing_with_1_fang!(R1, R2, R3, R4, R5, R6, R7, R8, R9);
    routing_with_1_fang!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10);
    routing_with_1_fang!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11);
    routing_with_1_fang!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12);

    macro_rules! routing_with_2_fangs {
        ( $( $item:ident ),+ ) => {
            impl<F1, F2, $( $item: RoutingItem ),+> Routing<(F1, F2)> for ( F1, F2, $($item,)+ )
            where
                F1: Fang<F2::Proc> + 'static,
                F2: Fang<BoxedFPC> + 'static,
            {
                fn apply(self, target: &mut Ohkami) {
                    let ( f1, f2, $( $item, )+ ) = self;
                    target.fangs = Some(Arc::new((f1, f2)));
                    $(
                        <$item as RoutingItem>::apply($item, &mut target.router);
                    )+
                }
            }
        };
    }
    routing_with_2_fangs!(R1);
    routing_with_2_fangs!(R1, R2);
    routing_with_2_fangs!(R1, R2, R3);
    routing_with_2_fangs!(R1, R2, R3, R4);
    routing_with_2_fangs!(R1, R2, R3, R4, R5);
    routing_with_2_fangs!(R1, R2, R3, R4, R5, R6);
    routing_with_2_fangs!(R1, R2, R3, R4, R5, R6, R7);
    routing_with_2_fangs!(R1, R2, R3, R4, R5, R6, R7, R8);
    routing_with_2_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9);
    routing_with_2_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10);
    routing_with_2_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11);
    routing_with_2_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12);

    macro_rules! routing_with_3_fangs {
        ( $( $item:ident ),+ ) => {
            impl<F1, F2, F3, $( $item: RoutingItem ),+> Routing<(F1, F2, F3)> for ( F1, F2, F3, $($item,)+ )
            where
                F1: Fang<F2::Proc> + 'static,
                F2: Fang<F3::Proc> + 'static,
                F3: Fang<BoxedFPC> + 'static,
            {
                fn apply(self, target: &mut Ohkami) {
                    let ( f1, f2, f3, $( $item, )+ ) = self;
                    target.fangs = Some(Arc::new((f1, f2, f3)));
                    $(
                        <$item as RoutingItem>::apply($item, &mut target.router);
                    )+
                }
            }
        };
    }
    routing_with_3_fangs!(R1);
    routing_with_3_fangs!(R1, R2);
    routing_with_3_fangs!(R1, R2, R3);
    routing_with_3_fangs!(R1, R2, R3, R4);
    routing_with_3_fangs!(R1, R2, R3, R4, R5);
    routing_with_3_fangs!(R1, R2, R3, R4, R5, R6);
    routing_with_3_fangs!(R1, R2, R3, R4, R5, R6, R7);
    routing_with_3_fangs!(R1, R2, R3, R4, R5, R6, R7, R8);
    routing_with_3_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9);
    routing_with_3_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10);
    routing_with_3_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11);
    routing_with_3_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12);

    macro_rules! routing_with_4_fangs {
        ( $( $item:ident ),+ ) => {
            impl<F1, F2, F3, F4, $( $item: RoutingItem ),+> Routing<(F1, F2, F3, F4)> for ( F1, F2, F3, F4, $($item,)+ )
            where
                F1: Fang<F2::Proc> + 'static,
                F2: Fang<F3::Proc> + 'static,
                F3: Fang<F4::Proc> + 'static,
                F4: Fang<BoxedFPC> + 'static,
            {
                fn apply(self, target: &mut Ohkami) {
                    let ( f1, f2, f3, f4, $( $item, )+ ) = self;
                    target.fangs = Some(Arc::new((f1, f2, f3, f4)));
                    $(
                        <$item as RoutingItem>::apply($item, &mut target.router);
                    )+
                }
            }
        };
    }
    routing_with_4_fangs!(R1);
    routing_with_4_fangs!(R1, R2);
    routing_with_4_fangs!(R1, R2, R3);
    routing_with_4_fangs!(R1, R2, R3, R4);
    routing_with_4_fangs!(R1, R2, R3, R4, R5);
    routing_with_4_fangs!(R1, R2, R3, R4, R5, R6);
    routing_with_4_fangs!(R1, R2, R3, R4, R5, R6, R7);
    routing_with_4_fangs!(R1, R2, R3, R4, R5, R6, R7, R8);
    routing_with_4_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9);
    routing_with_4_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10);
    routing_with_4_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11);
    routing_with_4_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12);

    macro_rules! routing_with_5_fangs {
        ( $( $item:ident ),+ ) => {
            impl<F1, F2, F3, F4, F5, $( $item: RoutingItem ),+> Routing<(F1, F2, F3, F4, F5)> for ( F1, F2, F3, F4, F5, $($item,)+ )
            where
                F1: Fang<F2::Proc> + 'static,
                F2: Fang<F3::Proc> + 'static,
                F3: Fang<F4::Proc> + 'static,
                F4: Fang<F5::Proc> + 'static,
                F5: Fang<BoxedFPC> + 'static,
            {
                fn apply(self, target: &mut Ohkami) {
                    let ( f1, f2, f3, f4, f5, $( $item, )+ ) = self;
                    target.fangs = Some(Arc::new((f1, f2, f3, f4, f5)));
                    $(
                        <$item as RoutingItem>::apply($item, &mut target.router);
                    )+
                }
            }
        };
    }
    routing_with_5_fangs!(R1);
    routing_with_5_fangs!(R1, R2);
    routing_with_5_fangs!(R1, R2, R3);
    routing_with_5_fangs!(R1, R2, R3, R4);
    routing_with_5_fangs!(R1, R2, R3, R4, R5);
    routing_with_5_fangs!(R1, R2, R3, R4, R5, R6);
    routing_with_5_fangs!(R1, R2, R3, R4, R5, R6, R7);
    routing_with_5_fangs!(R1, R2, R3, R4, R5, R6, R7, R8);
    routing_with_5_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9);
    routing_with_5_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10);
    routing_with_5_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11);
    routing_with_5_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12);

    macro_rules! routing_with_6_fangs {
        ( $( $item:ident ),+ ) => {
            impl<F1, F2, F3, F4, F5, F6, $( $item: RoutingItem ),+> Routing<(F1, F2, F3, F4, F5, F6)> for ( F1, F2, F3, F4, F5, F6, $($item,)+ )
            where
                F1: Fang<F2::Proc> + 'static,
                F2: Fang<F3::Proc> + 'static,
                F3: Fang<F4::Proc> + 'static,
                F4: Fang<F5::Proc> + 'static,
                F5: Fang<F6::Proc> + 'static,
                F6: Fang<BoxedFPC> + 'static,
            {
                fn apply(self, target: &mut Ohkami) {
                    let ( f1, f2, f3, f4, f5, f6, $( $item, )+ ) = self;
                    target.fangs = Some(Arc::new((f1, f2, f3, f4, f5, f6)));
                    $(
                        <$item as RoutingItem>::apply($item, &mut target.router);
                    )+
                }
            }
        };
    }
    routing_with_6_fangs!(R1);
    routing_with_6_fangs!(R1, R2);
    routing_with_6_fangs!(R1, R2, R3);
    routing_with_6_fangs!(R1, R2, R3, R4);
    routing_with_6_fangs!(R1, R2, R3, R4, R5);
    routing_with_6_fangs!(R1, R2, R3, R4, R5, R6);
    routing_with_6_fangs!(R1, R2, R3, R4, R5, R6, R7);
    routing_with_6_fangs!(R1, R2, R3, R4, R5, R6, R7, R8);
    routing_with_6_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9);
    routing_with_6_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10);
    routing_with_6_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11);
    routing_with_6_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12);

    macro_rules! routing_with_7_fangs {
        ( $( $item:ident ),+ ) => {
            impl<F1, F2, F3, F4, F5, F6, F7, $( $item: RoutingItem ),+> Routing<(F1, F2, F3, F4, F5, F6, F7)> for ( F1, F2, F3, F4, F5, F6, F7, $($item,)+ )
            where
                F1: Fang<F2::Proc> + 'static,
                F2: Fang<F3::Proc> + 'static,
                F3: Fang<F4::Proc> + 'static,
                F4: Fang<F5::Proc> + 'static,
                F5: Fang<F6::Proc> + 'static,
                F6: Fang<F7::Proc> + 'static,
                F7: Fang<BoxedFPC> + 'static,
            {
                fn apply(self, target: &mut Ohkami) {
                    let ( f1, f2, f3, f4, f5, f6, f7, $( $item, )+ ) = self;
                    target.fangs = Some(Arc::new((f1, f2, f3, f4, f5, f6, f7)));
                    $(
                        <$item as RoutingItem>::apply($item, &mut target.router);
                    )+
                }
            }
        };
    }
    routing_with_7_fangs!(R1);
    routing_with_7_fangs!(R1, R2);
    routing_with_7_fangs!(R1, R2, R3);
    routing_with_7_fangs!(R1, R2, R3, R4);
    routing_with_7_fangs!(R1, R2, R3, R4, R5);
    routing_with_7_fangs!(R1, R2, R3, R4, R5, R6);
    routing_with_7_fangs!(R1, R2, R3, R4, R5, R6, R7);
    routing_with_7_fangs!(R1, R2, R3, R4, R5, R6, R7, R8);
    routing_with_7_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9);
    routing_with_7_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10);
    routing_with_7_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11);
    routing_with_7_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12);

    macro_rules! routing_with_8_fangs {
        ( $( $item:ident ),+ ) => {
            impl<F1, F2, F3, F4, F5, F6, F7, F8, $( $item: RoutingItem ),+> Routing<(F1, F2, F3, F4, F5, F6, F7, F8)> for ( F1, F2, F3, F4, F5, F6, F7, F8, $($item,)+ )
            where
                F1: Fang<F2::Proc> + 'static,
                F2: Fang<F3::Proc> + 'static,
                F3: Fang<F4::Proc> + 'static,
                F4: Fang<F5::Proc> + 'static,
                F5: Fang<F6::Proc> + 'static,
                F6: Fang<F7::Proc> + 'static,
                F7: Fang<F8::Proc> + 'static,
                F8: Fang<BoxedFPC> + 'static,
            {
                fn apply(self, target: &mut Ohkami) {
                    let ( f1, f2, f3, f4, f5, f6, f7, f8, $( $item, )+ ) = self;
                    target.fangs = Some(Arc::new((f1, f2, f3, f4, f5, f6, f7, f8)));
                    $(
                        <$item as RoutingItem>::apply($item, &mut target.router);
                    )+
                }
            }
        };
    }
    routing_with_8_fangs!(R1);
    routing_with_8_fangs!(R1, R2);
    routing_with_8_fangs!(R1, R2, R3);
    routing_with_8_fangs!(R1, R2, R3, R4);
    routing_with_8_fangs!(R1, R2, R3, R4, R5);
    routing_with_8_fangs!(R1, R2, R3, R4, R5, R6);
    routing_with_8_fangs!(R1, R2, R3, R4, R5, R6, R7);
    routing_with_8_fangs!(R1, R2, R3, R4, R5, R6, R7, R8);
    routing_with_8_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9);
    routing_with_8_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10);
    routing_with_8_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11);
    routing_with_8_fangs!(R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12);
};
