//! Process management syscalls
use crate::mm::address::StepByOne;
use crate::{
    config::PAGE_SIZE,
    mm::translated_byte_buffer,
    mm::{MapPermission, PageTable, VirtAddr, VirtPageNum},
    task::{change_program_brk, exit_current_and_run_next, suspend_current_and_run_next},
    task::{current_task, current_task_mut},
    timer::get_time_us,
};

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// TODO: get time with second and microsecond
/// HINT: You might reimplement it with virtual memory management.
/// HINT: What if [`TimeVal`] is splitted by two pages ?
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    trace!("kernel: sys_get_time");
    let current_task = current_task().unwrap();
    let token = current_task.get_user_token();

    // 检查 ts 是否按 8 字节对齐
    let ts_addr = ts as usize;
    if ts_addr % 8 != 0 {
        return -1; // 指针未对齐
    }

    // 检查页面权限：确保 [ts, ts + sizeof(TimeVal)) 可写
    let page_table = PageTable::from_token(token);
    let start_va = VirtAddr::from(ts_addr);
    let end_va = VirtAddr::from(ts_addr + core::mem::size_of::<TimeVal>());
    let mut current_va: VirtPageNum = start_va.floor();
    while current_va <= end_va.floor() {
        let pte = match page_table.translate(current_va) {
            Some(pte) => pte,
            None => return -1, // 页面未映射
        };
        if !pte.is_valid() || !pte.writable() {
            return -1; // 页面无效、非用户页面或不可写
        }
        current_va.step();
    }

    // 获取跨页缓冲区
    let buffers = translated_byte_buffer(token, ts as *const u8, core::mem::size_of::<TimeVal>());
    if buffers.is_empty() {
        return -1;
    }

    // 获取当前时间
    let us = get_time_us();
    let ts_val = TimeVal {
        sec: us / 1_000_000,
        usec: us % 1_000_000,
    };
    let ts_bytes = unsafe {
        core::slice::from_raw_parts(
            &ts_val as *const _ as *const u8,
            core::mem::size_of::<TimeVal>(),
        )
    };

    // 写入用户空间
    let mut offset = 0;
    for buffer in buffers {
        let copy_len = buffer.len().min(core::mem::size_of::<TimeVal>() - offset);
        unsafe {
            core::ptr::copy_nonoverlapping(
                ts_bytes.as_ptr().add(offset),
                buffer.as_mut_ptr(),
                copy_len,
            );
        }
        offset += copy_len;
    }

    0
}
/// TODO: Finish sys_trace to pass testcases
/// HINT: You might reimplement it with virtual memory management.
pub fn sys_trace(trace_request: usize, id: usize, data: usize) -> isize {
    trace!("kernel: sys_trace");
    let task = current_task().unwrap();
    let token = task.get_user_token();
    let page_table = PageTable::from_token(token);
    //println!("!!!trace_request = {}", trace_request);
    match trace_request {
        0 => {
            let va = VirtAddr::from(id);
            let pte = match page_table.translate(va.floor()) {
                Some(pte) => pte,
                None => return -1,
            };

            if !pte.is_valid() || !pte.readable() || !pte.userable() {
                return -1;
            }

            let buffers = translated_byte_buffer(token, id as *const u8, 1);
            if buffers.is_empty() {
                return -1;
            }
            buffers[0][0] as isize
        }
        1 => {
            let va = VirtAddr::from(id);
            let pte = match page_table.translate(va.floor()) {
                Some(pte) => pte,
                None => return -1,
            };

            if !pte.is_valid() || !pte.readable() || !pte.writable() {
                return -1;
            }

            let mut buffers = translated_byte_buffer(token, id as *const u8, 1);
            if buffers.is_empty() {
                return -1;
            }
            buffers[0][0] = data as u8;
            0
        }
        2 => {
            //println!("%%%%%%%%%%%");
            // syscall_count of SYSCALL_TRACE
            //println!("TRACEsyscall_count = {}", task.get_syscall_count(410));
            let count = task.get_syscall_count(id);
            //let task_mut = current_task_mut().unwrap();
            //task_mut.inc_syscall_count(id);
            count as isize
        }
        _ => -1,
    }
}

/// 检查地址是否按页面大小对齐
fn is_page_aligned(addr: usize) -> bool {
    addr % PAGE_SIZE == 0
}

// TODO: Implement mmap.
pub fn sys_mmap(start: usize, len: usize, prot: usize) -> isize {
    trace!("kernel: sys_mmap");
    let task = current_task_mut().unwrap();
    let start_va = VirtAddr::from(start);

    // 检查页面对齐
    if !is_page_aligned(start) {
        //println!("00000 fault because page not aligned");
        return -1;
    }
    // 计算结束地址
    let page_count = (len + PAGE_SIZE - 1) / PAGE_SIZE;
    if page_count == 0 {
        return 0;
    }
    if prot & !0x7 != 0 {
        return -1;
    }
    if prot & 0x7 == 0 {
        return -1;
    }

    let end_va = VirtAddr::from(start + page_count * PAGE_SIZE);
    let start_vpn = start_va.floor();
    let end_vpn = VirtPageNum::from((end_va.0 - 1) >> 12); // 最后一个页面

    for area in task.memory_set.areas.iter() {
        let area_start = area.vpn_range.get_start();
        let area_end = area.vpn_range.get_end();
        if (start_vpn < area_end && end_vpn >= area_start)
        //|| start_vpn >= area_end && end_vpn < area_start
        //|| start_vpn >= area_start && end_vpn > area_end
        || (start_vpn <= area_start && end_vpn <= area_end && end_vpn >= area_start)
        {
            return -1;
        }
    }
    // 转换 prot 到 MapPermission
    let mut permission = MapPermission::U;
    if prot & 0x1 != 0 {
        permission |= MapPermission::R;
    }
    if prot & 0x2 != 0 {
        permission |= MapPermission::W;
    }
    if prot & 0x4 != 0 {
        permission |= MapPermission::X;
    }

    // 映射整个区域
    task.memory_set
        .insert_framed_area(start_va, end_va, permission);

    0
}

pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap");
    let task = current_task_mut().unwrap();
    let start_va = VirtAddr::from(start);

    if !is_page_aligned(start) {
        return -1;
    }

    let page_count = (len + PAGE_SIZE - 1) / PAGE_SIZE;
    if page_count == 0 {
        return 0;
    }
    let end_va = VirtAddr::from(start + page_count * PAGE_SIZE);

    let mut current_va = start_va.floor();
    while current_va < end_va.floor() {
        if task.memory_set.translate(current_va).is_none() {
            return -1;
        }
        current_va.step();
    }
    //println!("RRRRRremove_framed_area");
    if task
        .memory_set
        .remove_framed_area(start_va, end_va)
        .is_err()
    {
        return -1;
    }

    0
}
/// change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}
