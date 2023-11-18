use std::{env, fs};
use tfhe::{prelude::*, FheInt32};
use tfhe::{
    prelude::{FheDecrypt, FheEncrypt},
    ClientKey, CompressedFheInt32, CompressedServerKey, ConfigBuilder,
};

fn main() {
    let args: Vec<String> = env::args().collect();
    let args = args.iter().map(|x| x.as_str()).collect::<Box<_>>();
    match args.as_ref() {
        [_, "client", "gen_key"] => client_gen(),
        [_, "client", "encrypt", a, b, c] => client_encrypt(a, b, c),
        [_, "client", "decrypt", result_path] => client_decrypt(result_path),
        [_, "server", "sort", data_path] => server_sort(data_path),
        _ => {
            println!(
                r#"
playground-tfhe client gen_key => 作为客户端生成2个key,
playground-tfhe client encrypt a b c => 作为客户端加密3个数字,
playground-tfhe server sort encrypted_numbers => 作为服务器进行排序计算,
playground-tfhe client decrypt result_path => 作为客户端解密得到的结果,
            "#
            )
        }
    }
}

fn server_sort(data_path: &str) {
    let sk_bytes = fs::read("server_key").expect("these is no server_key");
    let compressed_sk: CompressedServerKey =
        bincode::deserialize(&sk_bytes).expect("server_key deserialize error");
    let sk = compressed_sk.decompress();

    let data = fs::read(data_path).expect("data read error");
    let (a, b, c): (CompressedFheInt32, CompressedFheInt32, CompressedFheInt32) =
        bincode::deserialize(&data).expect("compressed three numbers deserialize error");
    let a = a.decompress();
    let b = b.decompress();
    let c = c.decompress();

    tfhe::set_server_key(sk);

    let min = a.min(&b).min(&c);
    let max = a.max(&b).max(&c);
    let mid = a + b + c - &max - &min;

    let result = (min, mid, max);
    let result_bytes = bincode::serialize(&result).expect("sorting result serialization error");

    fs::write("sort_result", result_bytes).expect("sort_result written error");
}

fn client_decrypt(x_path: &str) {
    let ck_bytes = fs::read("client_key").expect("these is no client_key");
    let ck: ClientKey = bincode::deserialize(&ck_bytes).expect("client_key deserialize error");

    let encrypted_result_bytes = fs::read(x_path).expect("read encrypted result error");
    let (enc_a, enc_b, enc_c): (FheInt32, FheInt32, FheInt32) =
        bincode::deserialize(&encrypted_result_bytes).expect("encrypted result deserialize error");

    let a: i32 = enc_a.decrypt(&ck);
    let b: i32 = enc_b.decrypt(&ck);
    let c: i32 = enc_c.decrypt(&ck);

    println!("The sorting result is: {a} {b} {c}");
}

fn client_encrypt(a: &str, b: &str, c: &str) {
    let ck_bytes = fs::read("client_key").expect("these is no client_key");
    let ck: ClientKey = bincode::deserialize(&ck_bytes).expect("client_key deserialize error");

    let a: i32 = a.parse().expect("parse the first number to i32 error");
    let b: i32 = b.parse().expect("parse the second number to i32 error");
    let c: i32 = c.parse().expect("parse the third number to i32 error");

    let enc_a = CompressedFheInt32::encrypt(a, &ck);
    let enc_b = CompressedFheInt32::encrypt(b, &ck);
    let enc_c = CompressedFheInt32::encrypt(c, &ck);

    let data_bytes =
        bincode::serialize(&(enc_a, enc_b, enc_c)).expect("data_bytes serialization error");
    fs::write("encrypted_numbers", data_bytes).expect("encrypted_numbers written error");
}

fn client_gen() {
    let config = ConfigBuilder::all_disabled()
        .enable_default_integers()
        .build();

    let ck = ClientKey::generate(config);
    let sk = ck.generate_compressed_server_key();

    let ck_bytes = bincode::serialize(&ck).expect("ck_bytes serialization error");
    let sk_bytes = bincode::serialize(&sk).expect("sk_bytes serialization error");

    fs::write("client_key", ck_bytes).expect("client_key written error");
    fs::write("server_key", sk_bytes).expect("server_key written error");
}
