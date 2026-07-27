use core::marker::PhantomData;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

pub struct Node<T> {
    pub value: T,
    pub next: *mut Node<T>,
}

pub struct RelaxedRawIter<T> {
    head: AtomicPtr<Node<T>>,
    _marker: PhantomData<T>,
}

impl<T> RelaxedRawIter<T> {
    pub fn empty() -> Self {
        Self {
            head: AtomicPtr::new(ptr::null_mut()),
            _marker: PhantomData,
        }
    }

    pub fn next(&self) -> Option<*mut Node<T>> {
        let current = self.head.load(Ordering::Relaxed);
        (!current.is_null()).then_some(current)
    }
}

pub struct AcquireRawIter<T> {
    head: AtomicPtr<Node<T>>,
    _marker: PhantomData<T>,
}

impl<T> AcquireRawIter<T> {
    pub fn empty() -> Self {
        Self {
            head: AtomicPtr::new(ptr::null_mut()),
            _marker: PhantomData,
        }
    }

    pub fn next(&self) -> Option<*mut Node<T>> {
        let ordering = Ordering::Acquire;
        let current = self.head.load(ordering);
        (!current.is_null()).then_some(current)
    }
}

pub struct Counter {
    value: AtomicUsize,
}

impl Counter {
    pub fn new(value: usize) -> Self {
        Self {
            value: AtomicUsize::new(value),
        }
    }

    pub fn get(&self) -> usize {
        self.value.load(Ordering::Relaxed)
    }
}
