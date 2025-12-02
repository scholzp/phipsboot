use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use log::info;

use core::ptr;
use lib::mem::paging;
use lib::safe::Safe;

use crate::shared_mem_com::SharedMemCommunicator;
use crate::state_machine::task_id::TaskId;
use crate::state_machine::TeeCommand;

static mut TASK_MAP: Safe<BTreeMap<TaskId, Box<dyn Fn(&mut SharedMemCommunicator)>>> =
    Safe::new(BTreeMap::new());

pub fn init_task_map() {
    unsafe {
        TASK_MAP.insert(TaskId::Ping, Box::new(task_ping));
        TASK_MAP.insert(TaskId::AttackReadMem, Box::new(task_attack_read_mem));
        TASK_MAP.insert(TaskId::AttackWriteMem, Box::new(task_attack_write_mem));
        TASK_MAP.insert(TaskId::AttackNopMem, Box::new(task_attack_nop_mem));
        TASK_MAP.insert(TaskId::AttackIpi, Box::new(task_attack_ipi));
    }
}

fn task_ping(communicator: &mut SharedMemCommunicator) {
    let payload_mem = unsafe { communicator.get_slice() };
    payload_mem[0] += 1;

    communicator.set_task(TaskId::Ping);
    communicator.set_status(TeeCommand::TeeSend);
}

fn task_attack_write_mem(communicator: &mut SharedMemCommunicator) {
    task_mem_helper(communicator, true);
    communicator.set_task(TaskId::AttackWriteMem);
    communicator.set_status(TeeCommand::TeeSend);
}

fn task_attack_read_mem(communicator: &mut SharedMemCommunicator) {
    task_mem_helper(communicator, true);
    communicator.set_task(TaskId::AttackReadMem);
    communicator.set_status(TeeCommand::TeeSend);
}

fn task_attack_nop_mem(communicator: &mut SharedMemCommunicator) {
    task_mem_helper(communicator, false);
    communicator.set_task(TaskId::AttackNopMem);
    communicator.set_status(TeeCommand::TeeSend);
}

fn task_attack_ipi(communicator: &mut SharedMemCommunicator) {
    use alloc::alloc::{alloc, Layout};
    // We have one byte status field and 8 byte physical address that are
    // stored in the shared memory.

    // first get memory and the respective physical address
    let payload_mem = unsafe { communicator.get_slice() };
    let address_offset = 2;
    let secret: u32 = 0x1337_beef;

    // First byte denote if vector was initialized
    if 0 == payload_mem[0] {
        // Create a vector with capacity to make sure that all is done with one
        //allocation
        let secret_ptr = unsafe { alloc(Layout::from_size_align(4, 4).unwrap()) as *mut u32 };
        unsafe {
            ptr::write_volatile(secret_ptr, secret);
        }
        unsafe {
            ptr::write_volatile(
                payload_mem.as_mut_ptr().add(address_offset) as *mut u64,
                paging::get_physical_address(secret_ptr as u64),
            );
        }
        // info!("Initialized vector: {:#016x?} -> {:#016x?}", data_ptr as u64, unsafe{ paging::get_physical_address(data_ptr as u64) });
        payload_mem[0] = 1;
    }
    info!("Prepared secret");
    communicator.set_task(TaskId::AttackIpi);
    communicator.set_status(TeeCommand::TeeSend);
}

fn task_mem_helper(communicator: &mut SharedMemCommunicator, read: bool) {
    use alloc::alloc::{alloc, Layout};
    // We have one byte status field and 8 byte physical address that are
    // stored in the shared memory.

    // first get memory and the respective physical address
    let payload_mem = unsafe { communicator.get_slice() };
    let task = communicator.get_task();
    // We want to fill 4 KiB of memory
    let num_elements: usize = 0x1 << 12;
    let address_offset = 2;

    // First byte denote if vector was initialized
    if 0 == payload_mem[0] {
        // Create a vecotr with capacity to make sure that all is done with one
        //allocation
        let data_ptr =
            unsafe { alloc(Layout::from_size_align(num_elements, 4096).unwrap()) as *mut u32 };
        for x in 0..(num_elements / 4) {
            unsafe {
                ptr::write_volatile(data_ptr.add(x), 0x1_u32);
            }
        }
        unsafe {
            ptr::write_volatile(
                payload_mem.as_mut_ptr().add(address_offset) as *mut u64,
                paging::get_physical_address(data_ptr as u64),
            );
        }
        payload_mem[0] = 1;
    } else {
        unsafe {
            let mut current_value: u32;
            let data_ptr = paging::get_virtual_address(ptr::read_volatile(
                payload_mem.as_mut_ptr().add(address_offset) as *mut u64,
            )) as *mut u32;
            for x in 0..(num_elements / 4) {
                current_value = if true == read {
                    ptr::read_volatile(data_ptr.add(x))
                } else {
                    0
                };
                if TaskId::AttackWriteMem == task {
                    ptr::write_volatile(data_ptr.add(x), current_value + 1);
                }
            }
        }
    }
}

pub fn execute_task(task_id: TaskId, communicator: &mut SharedMemCommunicator) {
    unsafe {
        match TASK_MAP.get(&task_id) {
            Some(func) => func(communicator),
            None => {
                info!("No task");
            }
        };
    };
}
