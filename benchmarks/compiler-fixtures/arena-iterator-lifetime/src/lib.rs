#![allow(dead_code)]

use std::{marker::PhantomData, mem};

pub struct Arena;

pub struct ArenaVec<'arena, T> {
    ptr: *const T,
    len: usize,
    _arena: &'arena Arena,
}

pub struct IntoIter<T> {
    ptr: *const T,
    end: *const T,
    _marker: PhantomData<T>,
}

impl<T> Iterator for IntoIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

impl<'arena, T: 'arena> IntoIterator for ArenaVec<'arena, T> {
    type Item = T;
    type IntoIter = IntoIter<T>;

    #[inline(never)]
    fn into_iter(self) -> IntoIter<T> {
        let begin = self.ptr;
        let end = unsafe { begin.add(self.len) };
        mem::forget(self);
        IntoIter {
            ptr: begin,
            end,
            _marker: PhantomData,
        }
    }
}

pub struct AnchoredArenaVec<'arena, T> {
    ptr: *const T,
    len: usize,
    _arena: &'arena Arena,
}

pub struct AnchoredIntoIter<'arena, T> {
    ptr: *const T,
    end: *const T,
    _marker: PhantomData<&'arena [T]>,
}

impl<'arena, T> Iterator for AnchoredIntoIter<'arena, T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

impl<'arena, T: 'arena> IntoIterator for AnchoredArenaVec<'arena, T> {
    type Item = T;
    type IntoIter = AnchoredIntoIter<'arena, T>;

    #[inline(never)]
    fn into_iter(self) -> AnchoredIntoIter<'arena, T> {
        let begin = self.ptr;
        let end = unsafe { begin.add(self.len) };
        mem::forget(self);
        AnchoredIntoIter {
            ptr: begin,
            end,
            _marker: PhantomData,
        }
    }
}
