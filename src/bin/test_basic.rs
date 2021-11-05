#![allow(non_snake_case)]
use concrete::*;

//use std::num::Float;



fn sum_vector_with_static_encoder(x: &VectorLWE) -> VectorLWE{
    let min = x.encoders[0].get_min() as f64;
    let delta = x.encoders[0].delta as f64;
    let x_sum = x.sum_with_new_min(min).unwrap();
    let x_mod = x_sum.add_constant_static_encoder(&vec![0.9999f64 * delta]).unwrap();
    return x_mod;
}

fn main() -> Result<(), CryptoAPIError> {

    let path = "keys";
    
    println!("loading LWE key... \n");
    let sk0_LWE_path = format!("{}/sk0_LWE.json",path);
    let sk0 = LWESecretKey::load(&sk0_LWE_path).unwrap();    
    
    // create an encoder
    let enc = Encoder::new(0., 10., 6, 4)?;

    let m0: Vec<f64> = vec![2.54];
    println!("plaintext value {:?}\n", m0);
    
    let c0 = VectorLWE::encode_encrypt(&sk0, &m0, &enc)?;  
    println!("encrypted value {:?}", c0.decrypt_decode(&sk0).unwrap());
    c0.pp();
    
    let constants: Vec<f64> = vec![1.0];
    
    let mut ct = VectorLWE::encode_encrypt(&sk0, &m0, &enc)?;  
    ct.add_constant_static_encoder_inplace(&constants)?; 
    println!("add constant one {:?}", ct.decrypt_decode(&sk0).unwrap());
    ct.pp();   

    let mut ct = VectorLWE::encode_encrypt(&sk0, &m0, &enc)?;  
    ct.add_with_padding_inplace(&c0)?;
    println!("add with padding {:?}", ct.decrypt_decode(&sk0).unwrap());
    ct.pp();       

    ct = VectorLWE::encode_encrypt(&sk0, &m0, &enc)?;  
    ct.add_with_new_min_inplace(&c0, &vec![0.0])?;
    println!("add with new min {:?}", ct.decrypt_decode(&sk0).unwrap());
    ct.pp();     

    let max_constant: f64 = 1.0;
    let nb_bit_padding = 4;

    ct = VectorLWE::encode_encrypt(&sk0, &m0, &enc)?;  
    ct.mul_constant_with_padding_inplace(&constants, max_constant, nb_bit_padding)?;
    println!("mul constant one {:?}", ct.decrypt_decode(&sk0).unwrap());
    ct.pp();      

    ct = VectorLWE::encode_encrypt(&sk0, &m0, &enc)?;  
    ct.opposite_nth_inplace(0).unwrap();
    println!("negation of val {:?}", ct.decrypt_decode(&sk0).unwrap());
    ct.pp();      
    
    /*
    let zero: Vec<f64> = vec![0.0];
    let z_star = VectorLWE::encode_encrypt(&sk0, &zero, &enc)?;
    let encfile = "z_star.enc";
    z_star.save(&encfile).unwrap();
    
    let a_star = z_star.add_constant_static_encoder(&vec![3.0])?;
    let b_star = z_star.add_constant_static_encoder(&vec![5.0])?;
    
    let c_star = b_star.sub_with_padding(&a_star)?;
    println!("c {:?}", c_star.decrypt_decode(&sk0).unwrap());
    c_star.pp();      
    
    let encfile = "c_star.enc";
    c_star.save(&encfile).unwrap();

    let z_dagg = VectorLWE::encode_encrypt(&sk0, &zero, &enc)?;
    let encfile = "z_dagg.enc";
    z_dagg.save(&encfile).unwrap();

    let b_dagg = z_dagg.add_constant_static_encoder(&vec![5.0])?;

    let c_dagg = b_dagg.sub_with_padding(&a_star)?;
    println!("c {:?}", c_dagg.decrypt_decode(&sk0).unwrap());
    c_dagg.pp();      
    
    let encfile = "c_dagg.enc";
    c_dagg.save(&encfile).unwrap();
    */
    
    //let x: Vec<f64> = vec![1.0, 3.14, 1.73, 2.72];
    let x: Vec<f64> = vec![0.5, 1.0, 1.5, 2.0];
    let x0 = VectorLWE::encode_encrypt(&sk0, &x, &enc)?;  
    println!("x0 {:?}", x0.decrypt_decode(&sk0).unwrap());

    let s0 = sum_vector_with_static_encoder(&x0);
    println!("s0 {:?}", s0.decrypt_decode(&sk0).unwrap());

    let x_i = x0.extract_nth(0).unwrap();
    let x_j = x0.extract_nth(1).unwrap();
    let tmp = x_i.add_with_padding(&x_j)?;
    println!("tmp {:?}", tmp.decrypt_decode(&sk0).unwrap());
    
    let x_i = x0.extract_nth(2).unwrap();
    let x_j = x0.extract_nth(3).unwrap();
    let tst = x_i.add_with_padding(&x_j)?;
    println!("tst {:?}", tst.decrypt_decode(&sk0).unwrap());

    let sum = tmp.add_with_padding(&tst)?;
    println!("sum {:?}", sum.decrypt_decode(&sk0).unwrap());  
    
    let sum = sum_vector(&x);
    println!("sum {:?}", sum);  
    
    println!("{}", sum.log(2.0).ceil() as usize);
    println!("{}", 2i32.pow(3));
    
    let sum = sum_vector_zeropadd(&x);
    println!("sum {:?}", sum);  

    let sum = sum_vector_zeropadd(&vec![1.0;7]);
    println!("sum {:?}", sum);  

    let x = VectorLWE::encode_encrypt(&sk0, &vec![1.0;7], &enc)?;  
    //let z = VectorLWE::encode_encrypt(&sk0, &vec![0.0], &enc)?;    
    //let z = VectorLWE::zero(x.dimension, 1).unwrap();
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
    
    let sum = sum_vector_with_dynamic_encoder(&v);
    println!("sum {:?}", sum.decrypt_decode(&sk0).unwrap());  

    let sum = sum_vector_with_dynamic_encoder_zeropadd(&x);
    println!("sum {:?}", sum.decrypt_decode(&sk0).unwrap());  
    
    let res = minfun(0f64,1f64);
    println!("{:?} {:?}", res.0, res.1);
    
    let z: Vec<f64> = vec![2.54, 2.1, 1.5, 1.5]; 
    println!("z = {:?}", z);
    
    let tmp = min_vector(&z);
    println!("{} {:?}", tmp.0, tmp.1);

    let z: Vec<f64> = vec![2.54, 2.1, 1.5, 1.6, 1.7, 1.8]; 
    println!("z = {:?}", z);
    
    let tmp = min_vector_samepadd(&z);
    println!("{} {:?}", tmp.0, tmp.1);
    
    
    Ok(())
}

fn minfun(x_i:f64, x_j:f64) -> (f64, Vec<f64>) {
    let tst = x_i - x_j;
    let cmp = if tst <= 0.0 {0f64} else {1f64};
    let tmp = if tst <= 0.0 {0f64} else {tst};
    let min = x_i - tmp;
    let idx = vec![cmp,1.0-cmp];
    return (min, idx);
}

fn min_vector(x: &[f64]) -> (f64, Vec<Vec<f64>>) {
    let n = x.len();
    let k = (n as f64).log(2.0).ceil() as usize;
    println!("{}", k);
    let m = 2usize.pow(k as u32 - 1u32); 
    //let m = n-n/2;
    println!("n,m: {},{}", n, m);
    if n > 1 {
        let x_i = min_vector(&x[..m]);
        let x_j = min_vector(&x[m..]);
        let res = minfun(x_i.0,x_j.0);
        println!("x_i.1.len(): {}",x_i.1.len());
        println!("x_j.1.len(): {}",x_j.1.len());
        let mut idx = vec![res.1];
        for k in 0..x_i.1.len() {
            let mut tmp = x_i.1[k].clone();
            let tst = x_j.1[k].clone();
            tmp.extend(tst);
            idx.push(tmp); 
        }  
        return (res.0, idx); 
    }
    else {
        return (x[0],vec![vec![0f64]]);
    }
}


//fn min_vector_samepadd(x: &[f64]) -> (f64, Vec<Vec<f64>>) {
fn min_vector_samepadd(x: &[f64]) -> (f64, Vec<f64>) {
    let n = x.len();
    let k = (n as f64).log(2.0).ceil() as usize;
    println!("{}", k);
    let m = 2usize.pow(k as u32); // n; // 
    println!("{}", m);
    let mut v = vec![x[n-1]; m];
    println!("{:?}", v);
    for i in 0..n {
        v[i] = x[i];
    }
    println!("{:?}", v);
    let res = min_vector(&v);
    println!("{} {:?}", res.0, res.1);
    let mut tst = vec![0f64; m];
    let mut idx = vec![0f64; m];
    for i in 0..m {
        let mut tmp = vec![0f64; k];
        for j in 0..k {
            let mut l = 2usize.pow(k as u32 - 1 - j as u32);
            l = i / l;
            println!("i,j,l: {},{},{}",i,j,l);
            tmp[j] = res.1[j][l];
        }
        tst[i] = sum_vector(&tmp);
        idx[i] = if tst[i] < 0.5 {1f64} else {0f64};
    }
    println!("tst {:?}", tst);
    println!("idx {:?}", idx);
    return (res.0, idx[..n].to_vec());
}


fn sum_vector(x: &[f64]) -> f64{
    let n = x.len();
    let m = n/2;
    println!("n,m: {},{}", n, m);
    if n > 1 {
        return sum_vector(&x[..m]) + sum_vector(&x[m..]); 
    }
    else {
        return x[0];
    }
}

fn sum_vector_zeropadd(x: &[f64]) -> f64{
    let n = x.len();
    let m = (n as f64).log(2.0).ceil() as u32;
    println!("{}", m);
    let m = 2usize.pow(m);
    println!("{}", m);
    let mut v = vec![0.0; m];
    println!("{:?}", v);
    for i in 0..n {
        v[i] = x[i];
    }
    println!("{:?}", v);
    return sum_vector(&v);
}

fn sum_vector_with_dynamic_encoder(x: &[VectorLWE]) -> VectorLWE{
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
