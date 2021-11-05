#![allow(non_snake_case)]

fn step(x: f64) -> f64 {
    if x <= 0.0 {0f64} else {1f64}
}

fn relu(x: f64) -> f64 {
    if x <= 0.0 {0f64} else {x}
}


fn minfun(x_i:f64, x_j:f64) -> (f64,f64,f64) {
    let tst = x_i - x_j;
    let cmp = step(tst);
    let tmp = relu(tst);
    let min = x_i - tmp;
    return (min, cmp, 1.0-cmp);
}

fn minvec(x: &[f64]) -> (f64, Vec<Vec<f64>>) {
    let n = x.len();
    if n==1 {
        return (x[0], vec![vec![]]);
    }
    let m = n/2;
    let mut r = minvec(&x[..m]);
    let mut s = minvec(&x[m..]);
    let t = minfun(r.0,s.0);
    for v in r.1.iter_mut() {
        v.push(t.1);
    }
    for v in s.1.iter_mut() {
        v.push(t.2);
    }
    r.1.extend(s.1);
    return (t.0, r.1);
}

fn onehot(t: &Vec<Vec<f64>>) -> Vec<f64> {
    let s = t.iter().map(|v| v.iter().sum()).collect::<Vec<f64>>();
    return s.iter().map(|x| step(0.5-x)).collect::<Vec<f64>>();
}
    
fn main() {
    let x = vec![1.54, 2.45, 1.15, 2.2, 2.6, 3.14, 2.72];
    println!("values {:?}",x);
    
    println!("\ncompute minfun of first two elements");
    let res = minfun(x[0],x[1]);
    println!("min val: {}",res.0);
    println!("one hot: {},{}",res.1,res.2);

    println!("\ncompute minvec of whole vector");
    //let a = Vec::<f64>::new();
    let res = minvec(&x);
    println!("min val: {}",res.0);
    println!("scores: {:?}",res.1);
    println!("one hot: {:?}",onehot(&res.1));   
}

