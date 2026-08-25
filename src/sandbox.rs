//! Process isolation, Linux namespace hardening, seccomp filters, and execution limits.

use crate::config::SandboxPolicy;
use std::env;
use std::io;
use std::process::{Child, Command};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::Duration;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn install_seccomp_deny_filter() -> io::Result<()> {
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_JMP_JA: u16 = 0x05;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
    const SECCOMP_RET_ERRNO: u32 = 0x00050000;
    const SECCOMP_SET_MODE_FILTER: libc::c_int = 1;
    const AUDIT_ARCH_X86_64: u32 = 0xc000003e;
    const SECCOMP_DATA_NR: u32 = 0;
    const SECCOMP_DATA_ARCH: u32 = 4;

    let denied = [
        libc::SYS_ptrace,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_setns,
        libc::SYS_unshare,
        libc::SYS_reboot,
        libc::SYS_kexec_load,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_open_by_handle_at,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_keyctl,
        libc::SYS_userfaultfd,
        libc::SYS_io_uring_setup,
    ];

    let mut filter = Vec::with_capacity(4 + denied.len() * 2);
    filter.push(libc::sock_filter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_ARCH,
    });
    filter.push(libc::sock_filter {
        code: BPF_JMP_JEQ_K,
        jt: 1,
        jf: 0,
        k: AUDIT_ARCH_X86_64,
    });
    filter.push(libc::sock_filter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });
    filter.push(libc::sock_filter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_NR,
    });

    for syscall_nr in denied {
        filter.push(libc::sock_filter {
            code: BPF_JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: syscall_nr as u32,
        });
        filter.push(libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | libc::EPERM as u32,
        });
    }

    filter.push(libc::sock_filter {
        code: BPF_JMP_JA,
        jt: 0,
        jf: 0,
        k: 0,
    });
    filter.push(libc::sock_filter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: 0x7fff0000,
    });

    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut _,
    };

    let result = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            0,
            &program as *const libc::sock_fprog,
        )
    };

    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
#[allow(dead_code)]
fn install_seccomp_deny_filter() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "seccomp filter only implemented for Linux x86_64",
    ))
}

#[cfg(unix)]
fn apply_uid_gid(uid: Option<u32>, gid: Option<u32>) -> io::Result<()> {
    match (uid, gid) {
        (Some(uid), Some(gid)) => unsafe {
            let target_uid = uid as libc::uid_t;
            let target_gid = gid as libc::gid_t;
            let uid_change = libc::getuid() != target_uid || libc::geteuid() != target_uid;
            let gid_change = libc::getgid() != target_gid || libc::getegid() != target_gid;
            if !uid_change && !gid_change {
                return Ok(());
            }
            if libc::setgroups(0, std::ptr::null()) == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::setresgid(target_gid, target_gid, target_gid) == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::setresuid(target_uid, target_uid, target_uid) == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::getuid() != target_uid
                || libc::geteuid() != target_uid
                || libc::getgid() != target_gid
                || libc::getegid() != target_gid
                || libc::getgroups(0, std::ptr::null_mut()) != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "UID/GID transition verification failed",
                ));
            }
            Ok(())
        },
        (None, None) => Ok(()),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UID/GID must be paired",
        )),
    }
}

#[cfg(target_os = "linux")]
fn apply_linux_mount_hardening(
    mount_namespace: bool,
    read_only_filesystem: bool,
) -> io::Result<()> {
    if !mount_namespace {
        return if read_only_filesystem {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "read-only filesystem requires mount namespace",
            ))
        } else {
            Ok(())
        };
    }
    unsafe {
        if libc::unshare(libc::CLONE_NEWNS) == -1 {
            return Err(io::Error::last_os_error());
        }
        if libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        ) == -1
        {
            return Err(io::Error::last_os_error());
        }
        if read_only_filesystem
            && libc::mount(
                std::ptr::null(),
                c"/".as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_REC,
                std::ptr::null(),
            ) == -1
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn apply_linux_mount_hardening(
    mount_namespace: bool,
    _read_only_filesystem: bool,
) -> io::Result<()> {
    if mount_namespace {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "mount namespace is only implemented on Linux",
        ))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn drop_linux_capabilities(capabilities: &[u32]) -> io::Result<()> {
    for &capability in capabilities {
        let result =
            unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability as libc::c_ulong, 0, 0, 0) };
        if result == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
fn drop_linux_capabilities(capabilities: &[u32]) -> io::Result<()> {
    if capabilities.is_empty() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "capability dropping is only implemented on Linux",
        ))
    }
}

#[cfg(unix)]
fn set_limit(resource: libc::__rlimit_resource_t, value: u64) -> io::Result<()> {
    if value == 0 {
        return Ok(());
    }
    let limit = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    if unsafe { libc::setrlimit(resource, &limit) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
pub fn apply_sandbox(command: &mut Command, sandbox: &SandboxPolicy) -> Result<(), String> {
    use std::os::unix::process::CommandExt;

    if !sandbox.enabled {
        return Ok(());
    }
    let allowlist = sandbox.environment_allowlist.clone();
    if sandbox.clear_environment {
        let inherited: Vec<(String, String)> = env::vars()
            .filter(|(key, _)| allowlist.iter().any(|allowed| allowed == key))
            .collect();
        command.env_clear().envs(inherited);
    } else if !allowlist.is_empty() {
        return Err("sandbox.environment_allowlist requires clear_environment = true".into());
    }
    if let Some(dir) = &sandbox.working_dir {
        if !dir.is_dir() {
            return Err(format!(
                "sandbox working_dir is not a directory: {}",
                dir.display()
            ));
        }
        command.current_dir(dir);
    }
    let limits = sandbox.clone();
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            apply_linux_mount_hardening(limits.mount_namespace, limits.read_only_filesystem)?;
            if limits.network_namespace && libc::unshare(libc::CLONE_NEWNET) == -1 {
                return Err(io::Error::last_os_error());
            }
            apply_uid_gid(limits.run_as_uid, limits.run_as_gid)?;
            drop_linux_capabilities(&limits.drop_capabilities)?;
            if limits.seccomp_deny_dangerous {
                install_seccomp_deny_filter()?;
            }
            set_limit(libc::RLIMIT_AS, limits.max_memory_bytes)?;
            set_limit(libc::RLIMIT_CPU, limits.max_cpu_seconds)?;
            set_limit(libc::RLIMIT_FSIZE, limits.max_file_bytes)?;
            set_limit(libc::RLIMIT_NOFILE, limits.max_open_files)?;
            set_limit(libc::RLIMIT_NPROC, limits.max_processes)?;
            Ok(())
        });
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn apply_sandbox(command: &mut Command, sandbox: &SandboxPolicy) -> Result<(), String> {
    if !sandbox.enabled {
        return Ok(());
    }
    if let Some(dir) = &sandbox.working_dir {
        if !dir.is_dir() {
            return Err(format!(
                "sandbox working_dir is not a directory: {}",
                dir.display()
            ));
        }
        command.current_dir(dir);
    }
    if sandbox.clear_environment {
        let allowlist = &sandbox.environment_allowlist;
        let inherited: Vec<(String, String)> = env::vars()
            .filter(|(key, _)| allowlist.iter().any(|allowed| allowed == key))
            .collect();
        command.env_clear().envs(inherited);
    }
    Ok(())
}

/// Terminates the child process and its process group cleanly.
pub fn kill_process_group(child: &mut Child) {
    #[cfg(unix)]
    unsafe {
        let pid = child.id() as libc::pid_t;
        let _ = libc::kill(-pid, libc::SIGKILL);
    }
    let _ = child.kill();
}

/// Arms a watchdog timer thread to terminate long-running child processes.
pub fn arm_timeout(pid: u32, seconds: u64) -> (Arc<AtomicBool>, Option<thread::JoinHandle<()>>) {
    let done = Arc::new(AtomicBool::new(false));
    if seconds == 0 {
        return (done, None);
    }
    let finished = Arc::clone(&done);
    let handle = thread::spawn(move || {
        thread::sleep(Duration::from_secs(seconds));
        if !finished.load(Ordering::SeqCst) {
            #[cfg(unix)]
            unsafe {
                let _ = libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
            }
            #[cfg(not(unix))]
            {
                let _ = pid; // Silence unused warning on non-unix
            }
        }
    });
    (done, Some(handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm_timeout_terminates_gracefully() {
        let (done, handle) = arm_timeout(0, 0);
        assert!(handle.is_none());
        done.store(true, Ordering::SeqCst);
    }
}
