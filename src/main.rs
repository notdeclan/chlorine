use clap::{App, Arg};

use std::fs::{File, remove_file};
use std::path::Path;
use std::process::exit;
use std::error::Error;
use std::time::Instant;
use std::io;
use std::io::{Read, Write, Seek, SeekFrom};

use sodiumoxide::crypto::secretstream::{Stream, Tag, KEYBYTES, HEADERBYTES, ABYTES};
use sodiumoxide::crypto::secretstream::xchacha20poly1305::{Header, Key};
use sodiumoxide::crypto::pwhash::{Salt, gen_salt, SALTBYTES, MEMLIMIT_INTERACTIVE, OPSLIMIT_INTERACTIVE, OPSLIMIT_SENSITIVE, MEMLIMIT_SENSITIVE};
use sodiumoxide::crypto::pwhash;

use core::fmt;

use flate2::Compression;

use flate2::read::DeflateEncoder;
use flate2::write::DeflateDecoder;


const MAGIC_BYTES: [u8; 4] = [0x1a, 0xfd, 0x1b, 0xff];
const CHUNK_SIZE: usize = 4096;

#[derive(Debug)]
struct EncryptionError {
    message: String,
}

impl EncryptionError {
    fn new(message: &str) -> Self {
        EncryptionError {
            message: message.to_string()
        }
    }
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for EncryptionError { }

fn main() {
    // CLAP Command Line Interface
    let matches = App::new("chlorine")
        .version("1.1.0")
        .about("Simple and fast password based file encryption")
        .author("Declan W <1701185@uad.ac.uk>")
        //Required Arguments
        .arg(
            Arg::with_name("INPUT")
                .value_name("INPUT PATH")
                .takes_value(true)
                .required(true)
                .help("Path to file to encrypt to decrypt"))
        .arg(
            Arg::with_name("OUTPUT")
                .value_name("OUTPUT PATH")
                .takes_value(true)
                .required(true)
                .help("Path to save encrypted or decrypted file"))
        // Optional Arguments
        .arg(
            Arg::with_name("OVERWRITE")
                .short("o")
                .long("overwrite")
                .help("When enabled output files will be overwritten if exists"))
        .arg(
            Arg::with_name("SENSITIVE")
                .short("s")
                .long("sensitive")
                .help("Improves security of Key Derivation Process to secure highly sensitive data"))
        .arg(
            Arg::with_name("COMPRESSED")
                .short("c")
                .long("compression")
                .help("Enables DEFLATE Compression and Decompression"))

        .get_matches();

    // Required Arguments
    let input = matches.value_of("INPUT").unwrap();
    let output = matches.value_of("OUTPUT").unwrap();

    // Optional Arguments
    let overwrite = matches.is_present("OVERWRITE");
    let sensitive = matches.is_present("SENSITIVE");
    let compressed = matches.is_present("COMPRESSED");

    // Create Path objects
    let input_path = Path::new(input);
    let output_path = Path::new(output);

    // Check if Input File specified is a Directory or does not exist
    if input_path.is_dir() || !input_path.is_file() {
        eprintln!("Invalid input file, please specify path to file to encrypt/decrypt.");
        exit(1);
    }

    // Check if paths are the same
    if output_path.eq(input_path) {
        eprintln!("Input and Output paths must not be the same");
        exit(1);
    }

    // Check if Output is valid
    if output_path.exists() && !overwrite {
        // Output File already exists
        eprintln!("Output File already exists, use --overwrite  flag to ignore and overwrite.");
        exit(1);
    }

    // Read Password from STDOUT
    let password = rpassword::prompt_password_stdout("Password: ").unwrap();

    // Convert input paths to File objects
    let mut input_file = File::open(input_path).unwrap();
    let mut output_file = File::create(output_path).unwrap();


    // Start Timer
    let now = Instant::now();

    // Check if File is encrypted and then process
    let result = match is_encrypted(&mut input_file) {
        true => decrypt(&mut input_file, &mut output_file, password.as_str(), sensitive, compressed),
        false => encrypt(&mut input_file, &mut output_file, password.as_str(), sensitive, compressed)
    };

    // End Timer
    let elapsed = now.elapsed();

    // Handle Result
    match result {
        Ok(()) => println!("Operation Successful, finished in {:#?}", elapsed),
        Err(e) => {
            eprintln!("Failed to complete operation: {}", e);
            // Remove Empty Output File
            remove_file(output_path).unwrap();
            exit(1);
        }
    }
}

fn is_encrypted(input: &mut File) -> bool {
    let file_size = input.metadata().unwrap().len();

    if file_size < (MAGIC_BYTES.len() + SALTBYTES + HEADERBYTES) as u64 {
        return false;
    }

    // Check Magic Number
    let mut magic_number = [0u8; MAGIC_BYTES.len()];
    input.read_exact(&mut magic_number).unwrap();

    return magic_number == MAGIC_BYTES;
}

fn derive_key(password: &str, salt: &Salt, sensitive: bool) -> Key {
    let mut key = Key([0; KEYBYTES]);
    let Key(ref mut kb) = key;

    let (ops, mem) = if sensitive {
        (OPSLIMIT_SENSITIVE, MEMLIMIT_SENSITIVE)
    } else {
        (OPSLIMIT_INTERACTIVE, MEMLIMIT_INTERACTIVE)
    };

    pwhash::derive_key(kb, &password.as_bytes(), &salt,
                       ops,
                       mem).unwrap();

    return key;
}

fn encrypt(input: &mut File, output: &mut File, password: &str, sensitive: bool, compressed: bool) -> Result<(), Box<dyn Error>> {
    println!("Started Encryption");

    // Return back to start of file (because we checked for magic number)
    input.seek(SeekFrom::Start(0))?;

    // Generate Salt
    let salt = gen_salt();

    // Derive Key
    let key = derive_key(password, &salt, sensitive);

    println!("Derived Encryption Key");

    // Write Magic Number
    output.write(&MAGIC_BYTES)?;

    // Write Salt
    output.write(&salt.0)?;

    // Initialize Stream
    let (mut stream, header) = Stream::init_push(&key)
        .map_err(|_| EncryptionError::new("Failed to initialize encryption stream"))?;

    // Write Header
    output.write(&header.0)?;

    let mut bytes_left = input.metadata().unwrap().len();
    let mut buffer = [0; CHUNK_SIZE];

    // Initialize Compression
    let mut input: Box<dyn io::Read> = if compressed {
        println!("Initializing Compression");
        Box::new(DeflateEncoder::new(input, Compression::fast()))
    } else {
        Box::new(input)
    };

    loop {
        match input.read(&mut buffer) {
            Ok(bytes_read) if bytes_read > 0 => {
                // Reading File
                bytes_left -= bytes_read as u64;

                let tag = match bytes_left {
                    0 => Tag::Final,
                    _ => Tag::Message
                };

                let encrypted_bytes = &stream.push(&buffer[..bytes_read], None, tag)
                    .map_err(|_| EncryptionError::new("Failed to encrypt"))?;

                output.write(encrypted_bytes)?;

                continue;
            }
            Err(e) => Err(e)?, // Upon Exception
            _ => break // End of File
        }
    }

    Ok(())
}


fn decrypt(input: &mut File,  output: &mut File, password: &str, sensitive: bool, compressed: bool) -> Result<(), Box<dyn Error>> {
    println!("Started Decryption");

    // Extract Salt
    let mut salt = [0u8; SALTBYTES];
    input.read_exact(&mut salt).unwrap();

    let salt = Salt(salt);

    // Extract Header
    let mut header = [0u8; HEADERBYTES];
    input.read_exact(&mut header).unwrap();

    let header = Header(header);

    // Derive Key
    let key = derive_key(password, &salt, sensitive);

    println!("Derived Encryption Key");

    // Initialize Decryption Stream
    let mut stream = Stream::init_pull(&header, &key).unwrap();

    // The cipher text length is guaranteed to always be message length + ABYTES.
    let mut buffer = [0u8; CHUNK_SIZE + ABYTES];

    // Initialize Decompression
    let mut output: Box<dyn io::Write> = if compressed {
        println!("Initializing Decompression");
        Box::new(DeflateDecoder::new(output))
    } else {
        Box::new(output)
    };

    while stream.is_not_finalized() {
        match input.read(&mut buffer) {
            Ok(bytes_read) if bytes_read > 0 => {
                let read = &buffer[..bytes_read];

                let (decrypted, _tag) = stream.pull(read, None)
                    .map_err(|_| EncryptionError::new("Incorrect Password"))?;

                output.write(&decrypted)?;
                continue;
            }
            Err(e) => Err(e)?,
            _ => break
        }
    }

    Ok(())
}