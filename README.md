# Description
This tool will patch the entry point of the input dll and replace it with the RVA of another exported function in that same dll. This allows to select any exported function in the dll as the new entry point.

The main reason to develop this utility is because, at the time this repository is being created, Rust does not allow to compile to a dll with a custom entry point (unless you forgo using the standard library). Anyway, the tool can be used to patch the entry point of a dll written in other languages as well.

# Compilation

Since we are using [LITCRYPT](https://github.com/anvie/litcrypt.rs) plugin to obfuscate string literals, it is required to set up the environment variable LITCRYPT_ENCRYPT_KEY before compiling the code:

	C:\Users\User\Desktop\CustomEntryPoint> set LITCRYPT_ENCRYPT_KEY="yoursupersecretkey"

After that, simply compile the code and execute it:

	C:\Users\User\Desktop\CustomEntryPoint> cargo build --release
	C:\Users\User\Desktop\CustomEntryPoint\target\release> entry_point.exe -h

# Usage

	C:\Users\User\Desktop> entry_point.exe -i c:\path\to\input\file.dll -f ExportedFunctionName -o c:\output\path\file2.dll
