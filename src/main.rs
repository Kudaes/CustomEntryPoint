use std::{fs, io::Write, env};
use getopts::Options;

fn main() {
    unsafe
    {

        let args: Vec<String> = env::args().collect();
        let program = args[0].clone();
        let mut opts = Options::new();
        opts.optflag("h", "help", "Print this help menu.");
        opts.optopt("i", "input", "Input dll's path.","");
        opts.optopt("o", "output", "Path where the resulting dll should be written to.","");
        opts.optopt("f", "function", "Exported function to use as the new entry point.","");

        let matches = match opts.parse(&args[1..]) {
            Ok(m) => { m }
            Err(x) => {println!("{}",x);print!("{}","[x] Invalid arguments. Use -h for detailed help."); return; }
        };

        if matches.opt_present("h") || !matches.opt_present("i") ||!matches.opt_present("o") || !matches.opt_present("f"){
            print_usage(&program, opts);
            return;
        }

        let input = matches.opt_str("i").unwrap();
        let output = matches.opt_str("o").unwrap();
        let function = matches.opt_str("f").unwrap();

        let file_content = fs::read(&input).expect("[x] Error opening the specified dll.");
        let pe_ptr = file_content.as_ptr() as *mut u8;
        let mapped_pe = dinvoke::load_library_a(&input);
        let function_addr = dinvoke::get_function_address(mapped_pe, &function);
        if function_addr == 0
        {
            println!("[x] The dll does not export any function with name {}", function);
            return;
        }

        let e_lfanew: usize = *((pe_ptr as usize + 0x3C) as *const u32) as usize;
        println!("[-] Patching entry point at RVA 0x{:x}...", e_lfanew + 0x18 + 16);
        let entry = (pe_ptr as usize +  e_lfanew + 0x18 + 16) as *mut u32;
        *entry = (function_addr-mapped_pe) as u32;
        let mut file = std::fs::File::create(&output).unwrap();
        let _r = file.write(file_content.as_slice()).unwrap();
        println!("[+] Done! New dll written to {}.", output);
    
    }
   
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}