//! Abstraction for managing memory of the system and the loader.

/// Size of the heap.
const FALLBACK_HEAP_SIZE: usize = 0x1000 /* 32 KiB */;
/// Maximal size of the heap when allocating free pages
const MAX_HEAP_SIZE: usize = 256 * 4096 + 512 * 4096; /* x * 32 KiB */
/// Backing memory for the heap.
static mut FALLBACK_HEAP: [u8; FALLBACK_HEAP_SIZE] = [0; FALLBACK_HEAP_SIZE];
/// Tracks the current heap size
static mut CURRENT_HEAP_SIZE: usize = 0;

#[global_allocator]
static ALLOC: good_memory_allocator::SpinLockedAllocator =
    good_memory_allocator::SpinLockedAllocator::empty();

pub fn init(l1_virt: u64, l1_phy: u64) {
    unsafe {
        use lib::mem::paging::alloc_heap_pages;
        let (start_addr, size) = alloc_heap_pages(l1_virt, l1_phy & (!0x1FFFFFu64), MAX_HEAP_SIZE);
        if size > FALLBACK_HEAP_SIZE {
            // for i in 0..size {
            //     let target_address = (start_addr as *mut u8).add(i);
            //     core::ptr::write_volatile(target_address,  0);
            // }
            // core::ptr::write_bytes(start_addr as *mut u8, 0, size);
            // core::ptr::write_bytes(start_addr as *mut u8, 0, size);
            ALLOC.init(start_addr as usize, size);
            CURRENT_HEAP_SIZE = size;
        } else {
            ALLOC.init(FALLBACK_HEAP.as_ptr() as usize, FALLBACK_HEAP_SIZE);
            CURRENT_HEAP_SIZE = FALLBACK_HEAP_SIZE;
        }
    }
}

/// Returns the current heap size
pub fn get_curr_heap_size() -> usize {
    unsafe { CURRENT_HEAP_SIZE }
}
