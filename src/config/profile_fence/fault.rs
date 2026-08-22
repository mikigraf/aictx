use std::cell::Cell;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Point {
    PostCreateValidation,
    RecoveryPreparationValidation,
    UpgradeValidation,
    DowngradeValidation,
    ClearValidation,
    ClearParentSync,
}

thread_local! {
    static NEXT: Cell<Option<Point>> = const { Cell::new(None) };
}

pub(super) fn inject(point: Point) {
    NEXT.with(|next| {
        assert!(next.get().is_none(), "only one fence fault may be pending");
        next.set(Some(point));
    });
}

pub(super) fn take(point: Point) -> bool {
    NEXT.with(|next| {
        if next.get() == Some(point) {
            next.set(None);
            true
        } else {
            false
        }
    })
}
