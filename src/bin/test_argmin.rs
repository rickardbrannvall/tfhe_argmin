#![allow(non_snake_case)]
#![allow(dead_code)]

use concrete::*;

fn sum_vector_with_static_encoder(x: &VectorLWE) -> VectorLWE{
    let min = x.encoders[0].get_min() as f64;
    let delta = x.encoders[0].delta as f64;
    let x_sum = x.sum_with_new_min(min).unwrap();
    let x_mod = x_sum.add_constant_static_encoder(&vec![0.9999f64 * delta]).unwrap();
    return x_mod;
}

fn sum_vector_with_dynamic_encoder(x: &[VectorLWE]) -> VectorLWE{
    // should assert that n is power of 2 to ensure same padding for each addition
    let n = x.len();
    let m = n/2;
    println!("n,m: {},{}", n, m);
    if n > 1 {
        let x_i = sum_vector_with_dynamic_encoder(&x[..m]);
        let x_j = sum_vector_with_dynamic_encoder(&x[m..]);
        return x_i.add_with_padding(&x_j).unwrap();
    }
    else {
        return x[0].clone();
    }
}

//fn sum_vector_with_dynamic_encoder_zeropadd(x: &VectorLWE, z: &VectorLWE) -> VectorLWE{
fn sum_vector_with_dynamic_encoder_zeropadd(x: &VectorLWE) -> VectorLWE{
    let z = x.extract_nth(0).unwrap().mul_constant_static_encoder(&[0i32]).unwrap();
    let n = x.nb_ciphertexts;
    println!("{}", n);    
    let m = (n as f64).log(2.0).ceil() as u32;
    println!("{}", m);
    let m = 2usize.pow(m);
    println!("{}", m);
    let mut v = vec![z.clone(); m];
    for i in 0..n {
        v[i] = x.extract_nth(i).unwrap();
    }
    println!("len(v) {}", v.len());
    return sum_vector_with_dynamic_encoder(&v);
}

fn ind(v: f64) -> f64 {
    if v > 0.0 {
        0.999
    } else {
        0.001
    }
} 

fn main() -> Result<(), CryptoAPIError> {

    let path = "keys";
    
    // load LWE keys
    
    println!("loading LWE key... \n");
    let sk0_LWE_path = format!("{}/sk0_LWE.json",path);
    let sk0 = LWESecretKey::load(&sk0_LWE_path).unwrap();    
    let sk1_LWE_path = format!("{}/sk1_LWE.json",path);
    let sk1 = LWESecretKey::load(&sk1_LWE_path).unwrap();       
    let enc = Encoder::new(0., 10., 6, 2)?;

    // set-up for bootstrapping
    
    println!("Load Bootstrapping Key 01 ... \n");
    let bsk01_path = format!("{}/bsk01_LWE.json", path);
    let bsk01 = LWEBSK::load(&bsk01_path);    
    let enc_sum = Encoder::new(0.0, 1.0, 1, 4).unwrap();
    
    println!("Load Bootstrapping Key 10 ... \n");
    let bsk10_path = format!("{}/bsk10_LWE.json", path);
    let bsk10 = LWEBSK::load(&bsk10_path);    
    let enc_one = Encoder::new(0.0, 1.0, 1, 1).unwrap();
    
    let x: Vec<f64> = vec![2.54, 2.1, 1.5];
    //let x: Vec<f64> = vec![1.0, 3.14, 1.73, 2.72];
    println!("plaintext value {:?}\n", x);
    
    let N = x.len();
    println!("{:?}", N);
    
    let x0 = VectorLWE::encode_encrypt(&sk0, &x, &enc)?;  
    println!("encrypted value {:?}", x0.decrypt_decode(&sk0).unwrap());
    x0.pp();
    
    let o0 = VectorLWE::encode_encrypt(&sk0, &vec![1.; N-1], &enc)?;

    let mut tmp = vec![o0.clone(); N];
    println!("tmp.len {:?}", tmp.len());

    let mut tst = vec![vec![0.; N-1]; N];
    println!("tst.len {:?}", tst.len());
        
    for i in 0..N {
        for j in i+1..N {
            println!("i,j = {},{}: {},{} and {},{}",i,j,i,j-1,j,i);
            let flag = if (x[i]-x[j])>0. {1.0} else {0.0};
            tst[i][j-1] = flag;
            tst[j][i] = 1.0-flag;
            let x_j = x0.extract_nth(j).unwrap();
            let x_i = x0.extract_nth(i).unwrap();
            let mut temp = x_i.sub_with_padding(&x_j)?;
            temp = temp.bootstrap_nth_with_function(&bsk01, |x| ind(x), &enc_sum, 0)?;
            tmp[i].copy_in_nth_nth_inplace(j-1, &temp, 0).unwrap();
            temp.opposite_nth_inplace(0)?;
            temp.add_constant_dynamic_encoder_inplace(&vec![1.])?;
            tmp[j].copy_in_nth_nth_inplace(i, &temp, 0)?;
        }
    }
    
    println!("{:?}", tst);
    let mut s = vec![0.; N];
    let mut r = vec![0.; N];
    let mut s1 = VectorLWE::encode_encrypt(&sk0, &vec![0.; N], &enc)?;
    let mut r1 = VectorLWE::encode_encrypt(&sk0, &vec![0.; N], &enc)?;
    for i in 0..N {
        s[i] = tst[i].iter().sum::<f64>() - N as f64 + 1.0 + 0.5;
        r[i] = if s[i] > 0.0 {1.0} else {0.0}; 
        //println!("encrypted value {:?}", tmp[i].decrypt_decode(&sk0).unwrap());
        println!("encrypted value {:?}", tmp[i].decrypt_decode(&sk1).unwrap());
        //let mut temp = tmp[i].sum_with_new_min(0.0).unwrap();
        //let mut temp = sum_vector_with_static_encoder(&tmp[i]);
        let mut temp = sum_vector_with_dynamic_encoder_zeropadd(&tmp[i]);
        temp.add_constant_dynamic_encoder_inplace(&vec![-(N as f64 - 1.0 - 0.5)])?;
        println!("temp {:?}", temp.decrypt_decode(&sk1).unwrap());  
        s1.copy_in_nth_nth_inplace(i, &temp, 0)?;
        let mut test = temp.clone();
        test = test.bootstrap_nth_with_function(&bsk10, |x| ind(x), &enc_one, 0).unwrap();
        println!("test {:?}", test.decrypt_decode(&sk0).unwrap());  
        r1.copy_in_nth_nth_inplace(i, &test, 0)?;
    }      
    println!("s {:?}", s);
    println!("s1 {:?}", s1.decrypt_decode(&sk1).unwrap());
    println!("r {:?}", r);
    println!("r1 {:?}", r1.decrypt_decode(&sk0).unwrap());
    
    Ok(())
}
