use class_group::primitives::cl_dl_public_setup::*;
use class_group::BinaryQF;
use curv::elliptic::curves::{Bls12_381_1,Bls12_381_2, Point, Scalar};
use curv::BigInt;
use curv::arithmetic::traits::*;
use serde::{Serialize, Deserialize};
use std::io::Write;
use std::fs::File;
use std::io::Read;
use std::fs;
use std::any::type_name;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLGroupString
{
    delta_k_str:String,
    delta_q_str:String,
    gq_a_str:String,
    gq_b_str:String,
    gq_c_str:String,
    stilde_str:String
}
// 提前固定好group，只需要关注new
pub fn new()-> CLGroup
{
    const SEED: &str =  "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"; 
    let group = CLGroup::new_from_setup(&1600, &BigInt::from_str_radix(SEED, 10).unwrap());
    
    let delta_k_str = "-b048231b14306838d6406000810e521b5c8ead9f9869f4491134c49eba58508b31948adf69305eb6f6f98b95dfb98668272246888986beb97279f9e6732669fcf0e7979800f6cee070f01f42ab583de30cd05a28e6f483a3df9fb5e006f88904b5982d0e56d3d565a5742745faf1e64ee72c21d188cd168ab6d01a384b7b3e04a9eaf29df231ebaff053530191a19ab57d0c975fd9fc4cf4ecb484b4e611adae1dc362f3581a1a86e63380ffc201bd52097928e4db20ec2d4fed9a365d517d2fa91e8a9fe8938b3b";
    let delta_q_str="-24265dadf4b2a512ff8993afe8d61ed5afbfd300923ee7daaf9005aaf81a072daf649d4ee928a269cf2206a3917792ed57ed291a035a1b7c2459b9bb6f4fd808917cca84adf770e2d8327dd353ca628dfba874dc508f9adb1b282276cbe6335567cd96708904008bba764c52e2e80e6de73d511dd5eaadf960451c8f540ae5dce6c2ba2d084851d407e926ec2747dc5587c4f76d999cfe6954c858362563269db57a9605506b830a3d4bd1aba6789da316472b40782b7d0e57f718b19c671351819e8e1bb405ca2f8ba72d66c2efb2b14f13768b5eaa81a18e74438aa2b0020e8d3ef4182ea6a662d40a6abd71f86c5863f1ab23079e200ffc46ebeb01a744b4d7f77429e8938b3b";
    let gq_a_str="178e7b3e79a8e44adf1f4273ad39d8e082dd773a7f52cd70f77cc881f20713ad2ee35c64e871724d0264a43a358d7171a1aabacfda692df59e126465d10a8fa07be1c1d576fc79b0c39f5e7e4a52758deb0a4cdb546b4ec225689903a802e074ac99d63b1b27808c2443c8cd2d62a7587f9b920097d7101ba16aab766092422a1162dbc5";
    let gq_b_str="-10c0e418efbd9a24d30692fdb960ce890925a7f46923236f1f65965d46953797239ce356eaba05647d07588a85a2599ac788ddd315041eb34def6fc81b08074bd28ef3255a2bd519ec5d63602070cc33ab795ebc2b42e2bfbca31592a7d71d1dbb4a9833388da0e5938fb826df74113dfe875d2a276f3d1c0432ecef5bdfb80716bcbb7b";
    let gq_c_str="65316c89893796529db2f3cecdab31adb7866525a1d19fab6af42ccc45ce797d6fe8d1135dcebedd1177baea466efa76a12b858273b2fc6f0837f5bf5b8289350bab6294f26e0229e2b80efd64dc7826c5e6d77196258d4bd46234cf0450a065d3a83734a379d8983c2d27c9ed45a198f0012383476e0ea4eac603c7d6e7303f3de5ce11";
    let stilde_str="249da4ad3cb924cdf7089daaef172cca58496a4da4113f4a52f8f4fff82b9e8e2e6323b37d361e4e3e29a403093d0532adab0f787152d43f7df983933e8db53ec111febeca02d447948f37f6f5a489f9a78ab0c4c51a0128da131861314b06ad49d20c86996";

    CLGroup 
    { 
        delta_k: BigInt::from_hex(delta_k_str).unwrap(), 
        delta_q: BigInt::from_hex(delta_q_str).unwrap(), 
        gq: BinaryQF 
        { 
            a: BigInt::from_hex(gq_a_str).unwrap(), 
            b: BigInt::from_hex(gq_b_str).unwrap(), 
            c: BigInt::from_hex(gq_c_str).unwrap() 
        }, 
        stilde: BigInt::from_hex(stilde_str).unwrap() 
    }
}

pub fn new_from_file()-> CLGroup
{
    let mut config_file = File::open("group.json").expect("Fail to open file!");
    let mut config_str = String::new();
    config_file.read_to_string(&mut config_str).expect("Fail to read file contents");
    let group_fromjson:CLGroupString = serde_json::from_str(&config_str).unwrap();

    CLGroup
    {
        delta_k:BigInt::from_hex(&group_fromjson.delta_k_str).unwrap(),
        delta_q:BigInt::from_hex(&group_fromjson.delta_q_str).unwrap(),
        gq:BinaryQF 
        { 
            a: BigInt::from_hex(&group_fromjson.gq_a_str).unwrap(), 
            b: BigInt::from_hex(&group_fromjson.gq_b_str).unwrap(), 
            c: BigInt::from_hex(&group_fromjson.gq_c_str).unwrap() 
        },
        stilde:BigInt::from_hex(&group_fromjson.stilde_str).unwrap()
    }

}

pub fn group_gen()
{
    // let mut config_file = File::open("group.json").expect("Fail to open file!");
    // let mut config_str = String::new();
    // config_file.read_to_string(&mut config_str).expect("Fail to read file contents");
    let mut config_str = fs::read_to_string("group.json").expect("Unable to read file");
    let group_fromjson:CLGroupString = serde_json::from_str(&config_str).unwrap();

    //assert_eq!(group_str.delta_k_str,group_fromjson.delta_k_str);

    let new_group = CLGroup
    {
        delta_k:BigInt::from_hex(&group_fromjson.delta_k_str).unwrap(),
        delta_q:BigInt::from_hex(&group_fromjson.delta_q_str).unwrap(),
        gq:BinaryQF 
        { 
            a: BigInt::from_hex(&group_fromjson.gq_a_str).unwrap(), 
            b: BigInt::from_hex(&group_fromjson.gq_b_str).unwrap(), 
            c: BigInt::from_hex(&group_fromjson.gq_c_str).unwrap() 
        },
        stilde:BigInt::from_hex(&group_fromjson.stilde_str).unwrap()
    };
    println!("{:?}",new_group);
    let (sk,pk) = new_group.keygen();
    let a = Scalar::<Bls12_381_1>::random();
    let g = Point::<Bls12_381_1>::generator() * Scalar::<Bls12_381_1>::from(1);
    let g_a = &g * &a;
    let (c,_) = encrypt(&new_group, &pk, &a);
    //println!("{:?}",c);
}


pub fn group_gen2()
{
    const SEED: &str =  "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"; 
    let group = CLGroup::new_from_setup(&1600, &BigInt::from_str_radix(SEED, 10).unwrap());
    // println!("{:?}",group);
    // let group_str = CLGroupString
    // {
    //     delta_k_str:group.delta_k.to_hex(),
    //     delta_q_str:group.delta_q.to_hex(),
    //     gq_a_str:group.gq.a.to_hex(),
    //     gq_b_str:group.gq.b.to_hex(),
    //     gq_c_str:group.gq.c.to_hex(),
    //     stilde_str:group.stilde.to_hex()
    // };
    // println!("{:?}",group_str);
    // let group_json = serde_json::to_string(&group_str).unwrap();
    // // let mut file = File::create("group.json").expect("create failed");
    // // file.write(group_json.as_bytes()).expect("write failed");
    
    // fs::write("group.json", group_json).expect("Unable to write file");

    // //drop(file);

    // // let mut config_file = File::open("group.json").expect("Fail to open file!");
    // // let mut config_str = String::new();
    // // config_file.read_to_string(&mut config_str).expect("Fail to read file contents");
    let mut config_str = fs::read_to_string("group.json").expect("Unable to read file");
    let group_fromjson:CLGroupString = serde_json::from_str(&config_str).unwrap();

    //assert_eq!(group_str.delta_k_str,group_fromjson.delta_k_str);
    //file.write_all("group_json".as_bytes()).expect("write failed");


    // let filename = partyid.clone() + "3.txt";
    //     let q = serde_json::to_string(&constant_fx.to_bigint().to_hex())
    //         .map_err(|why| format_err!("To string failed in keygen phase five, cause {}", why))?;
    //     fs::write(filename, q.clone()).expect("Unable to write to file");



    let new_group = CLGroup
    {
        delta_k:BigInt::from_hex(&group_fromjson.delta_k_str).unwrap(),
        delta_q:BigInt::from_hex(&group_fromjson.delta_q_str).unwrap(),
        gq:BinaryQF 
        { 
            a: BigInt::from_hex(&group_fromjson.gq_a_str).unwrap(), 
            b: BigInt::from_hex(&group_fromjson.gq_b_str).unwrap(), 
            c: BigInt::from_hex(&group_fromjson.gq_c_str).unwrap() 
        },
        stilde:BigInt::from_hex(&group_fromjson.stilde_str).unwrap()
    };
    println!("{:?}",new_group);
    let (sk,pk) = new_group.keygen();
    let a = Scalar::<Bls12_381_1>::random();
    let g = Point::<Bls12_381_1>::generator() * Scalar::<Bls12_381_1>::from(1);
    let g_a = &g * &a;
    let (c,_) = encrypt(&new_group, &pk, &a);
    //println!("{:?}",c);

    //group_gen()

}

pub fn group_gen3()
{
    const SEED: &str =  "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848"; 
    let new_group = CLGroup::new_from_setup(&1600, &BigInt::from_str_radix(SEED, 10).unwrap());
    let (sk,pk) = new_group.keygen();
    let a = Scalar::<Bls12_381_1>::random();
    let g = Point::<Bls12_381_1>::generator() * Scalar::<Bls12_381_1>::from(1);
    let g_a = &g * &a;
    let (c,_) = encrypt(&new_group, &pk, &a);
    //println!("{:?}",c);
}

pub fn group_gen4()
{
    let new_group = new();
    let (sk,pk) = new_group.keygen();
    let a = Scalar::<Bls12_381_1>::random();
    let g = Point::<Bls12_381_1>::generator() * Scalar::<Bls12_381_1>::from(1);
    let g_a = &g * &a;
    let (c,_) = encrypt(&new_group, &pk, &a);
    println!("{:?}",c);
}
#[test]
fn test_group_gen(){
    group_gen()
}

#[test]
fn test_group2_gen(){
    group_gen2()
}

#[test]
fn test_group3_gen(){
    group_gen3()
}

#[test]
fn test_group4_gen(){
    group_gen4()
}