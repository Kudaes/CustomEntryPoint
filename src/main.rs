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
        opts.optflag("e", "make_exe", "Change the dll's characteristics to those expected from an .exe file.");


        let matches = match opts.parse(&args[1..]) {
            Ok(m) => { m }
            Err(x) => {println!("{}",x);print!("{}","[x] Invalid arguments. Use -h for detailed help."); return; }
        };

        if matches.opt_present("h") || !matches.opt_present("i") || !matches.opt_present("o") || (!matches.opt_present("f") && !matches.opt_present("e")){
            print_usage(&program, opts);
            return;
        }

        let input = matches.opt_str("i").unwrap();
        let output = matches.opt_str("o").unwrap();
        let mut function = String::new();
        if matches.opt_present("f") 
        {
            function = matches.opt_str("f").unwrap();

        }

        let file_content = fs::read(&input).expect("[x] Error opening the specified dll.");
        let pe_ptr = file_content.as_ptr() as *mut u8;
        let mapping_result = dinvoke_rs::manualmap::read_and_map_module(&input, false, false).unwrap();
        let mapped_pe = mapping_result.1;
        let function_addr = dinvoke_rs::dinvoke::get_function_address(mapped_pe, &function);
        if function_addr == 0 && function != String::new()
        {
            println!("[x] The dll does not export any function with name {}", function);
            return;
        }

        let e_lfanew: usize = *((pe_ptr as usize + 0x3C) as *const u32) as usize;

        if matches.opt_present("e")
        {
            let charact = (pe_ptr as usize + e_lfanew as usize + 0x4 + 0x13) as *mut u8; 
            *charact = 0;
            println!("[+] Dll's characteristics have been set to 0. The file can now be run directly.");
        } 

        if function != String::new() 
        {
            println!("[-] Patching entry point at RVA 0x{:x}...", e_lfanew + 0x18 + 16);
            let entry = (pe_ptr as usize +  e_lfanew + 0x18 + 16) as *mut u32;
            *entry = (function_addr - mapped_pe) as u32;
        }
        
        let mut file = std::fs::File::create(&output).unwrap();
        let _r = file.write(file_content.as_slice()).unwrap();
        println!("[+] Done! New file written to {}.", output);
    
    }
   
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}