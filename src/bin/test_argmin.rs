#![allow(non_snake_case)]
use concrete::*;

fn main() -> Result<(), CryptoAPIError> {

    let path = "keys";
    
    println!("loading LWE key... \n");
    let sk0_LWE_path = format!("{}/sk0_LWE.json",path);
    let sk0 = LWESecretKey::load(&sk0_LWE_path).unwrap();    
    
    // create an encoder
    let enc = Encoder::new(0., 10., 6, 4)?;

    let x: Vec<f64> = vec![2.54, 2.1, 1.5];
    println!("plaintext value {:?}\n", x);
    
    let x0 = VectorLWE::encode_encrypt(&sk0, &x, &enc)?;  
    println!("encrypted value {:?}", x0.decrypt_decode(&sk0).unwrap());
    x0.pp();
    
    let o0 = VectorLWE::encode_encrypt(&sk0, &vec![1., 1., 1.], &enc)?;

    let tmp = vec![o0.clone(), o0.clone(), o0.clone()];
    
    Ok(())
}
