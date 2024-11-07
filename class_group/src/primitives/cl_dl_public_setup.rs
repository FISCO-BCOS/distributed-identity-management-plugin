//! Implementation verifiable encryption of discrete logarithms in the Castagnos
//! and Laguillaumie cryptosystem where the CL group has a public setup.
//!
//!
//! The advantage of the CL cryptosystem is that you can generate a CL-group of
//! unknown order by where the discrete logarithm is **easy** for a subgroup of
//! an order of your choosing. For example, this allows you to generate a group
//! where you can verifiably encrypt the private key of a Bitcoin public key.
//!
//! 1. CL-groups were defined in https://eprint.iacr.org/2015/047.pdf, along
//!    with the original CPA-secure encryption scheme.
//! 2. The particular group generation algorithm, where you pass in the order of
//!    the DL-easy subgroup was shown in https://eprint.iacr.org/2019/503.pdf.
//! 3. The proof of equivalence between the discrete logarithm of a DL group
//!    element and the plaintext of a CL ciphertext in a CL-group with a public
//!    setup is given in https://eprint.iacr.org/2020/084.pdf (see section 5.2)

use super::ErrorReason;
use crate::bn_to_gen;
use crate::isprime;
use crate::pari_init;
use crate::primitives::is_prime;
use crate::primitives::numerical_log;
use crate::primitives::prng;
use crate::BinaryQF;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::elliptic::curves::{Bls12_381_1, Point, Scalar};
use curv::BigInt;
use serde_json::from_str;
use sha2::Sha256;
use std::os::raw::c_int;
use std::ops::Add;

const SECURITY_PARAMETER: usize = 128;
const C: usize = 10;

#[derive(Clone,Debug, Serialize, Deserialize)]
pub struct CLGroup {
    pub delta_k: BigInt,
    pub delta_q: BigInt,
    pub gq: BinaryQF,
    pub stilde: BigInt,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Ciphertext {
    pub c1: BinaryQF,
    pub c2: BinaryQF,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TTriplets {
    pub t1: BinaryQF,
    pub t2: BinaryQF,
    pub T: Point<Bls12_381_1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct U1U2 {
    pub u1: BigInt,
    pub u2: BigInt,
}

#[derive(Debug, Clone)]
pub struct ProofError;

impl CLGroup {
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
    pub fn new_from_setup(lam: &usize, seed: &BigInt) -> Self {
        let q = Scalar::<Bls12_381_1>::group_order();
        unsafe { pari_init(100000000, 2) };
        let mu = q.bit_length();
        assert!(lam > &(mu + 2));
        let k = lam - mu;
        let two = BigInt::from(2);
        let mut r = BigInt::sample_range(
            &two.pow((k - 1) as u32),
            &(two.pow(k as u32) - BigInt::one()),
        );

        let mut qtilde = next_probable_prime(&r);

        while (q * &qtilde).mod_floor(&BigInt::from(4)) != BigInt::from(3)
            || jacobi(q, &qtilde).unwrap() != -1
        {
            r = BigInt::sample_range(
                &two.pow((k - 1) as u32),
                &(two.pow(k as u32) - BigInt::one()),
            );
            qtilde = next_probable_prime(&r);
        }

        debug_assert!(BigInt::from(4) * q < qtilde);

        let delta_k = -q * &qtilde;
        let delta_q = &delta_k * q.pow(2);

        let delta_k_abs: BigInt = -(&delta_k);
        let log_delta_k_abs = numerical_log(&delta_k_abs);
        let delta_k_abs_sqrt = delta_k_abs.sqrt();
        let stilde = log_delta_k_abs * delta_k_abs_sqrt;

        // Assuming GRH the prime forms f_p with p<=6 ln^2(|delta_k|) generate the class group cf.
        // Cohen course comp. algebraic. number theory 5.5.1.
        // In practice we take only ln(-deltak)/ln(ln(-deltak))  primes and exponents up to 20 (cf. 5.5.2)
        // But as in https://eprint.iacr.org/2018/705.pdf page 20 we need pairwise coprime exponents
        // for the strong root assumption to hold so we take greater exponents to ensure that,
        // say up to 15 bits. (in fact for our purposes exponents globally coprime might be sufficient instead of pairwise coprimes)
        let mut prime_forms_vec: Vec<BinaryQF> = Vec::new();
        let mut r = BigInt::from(3);
        let ln_delta_k = numerical_log(&(-&delta_k));

        let num_of_prime_forms = ln_delta_k.div_floor(&numerical_log(&ln_delta_k));

        let mut i = BigInt::zero();
        while i < num_of_prime_forms {
            while jacobi(&delta_k, &r).unwrap() != 1 {
                r = next_probable_small_prime(&r)
            }
            prime_forms_vec.push(BinaryQF::primeform(&delta_k, &r));
            r = next_probable_small_prime(&r);
            i += 1;
        }
        let mut rgoth = BinaryQF::binary_quadratic_form_principal(&delta_k);

        //pseudo random element of class group Cl(delta_k) : prod f_p^e_p, with pairwise coprime exponents
        // generate enough pseudo randomness : 15 bits per exponents e_p

        // find exponent
        let mut i = 0;
        let mut rand_bits_i: BigInt;
        let mut prod_exponent = BigInt::one();
        while i < prime_forms_vec.len() {
            // extract 15bits
            rand_bits_i = prng(seed, i, 15);
            while rand_bits_i.gcd(&prod_exponent) != BigInt::one() {
                rand_bits_i += 1;
            }
            rgoth = rgoth
                .compose(&prime_forms_vec[i].exp(&rand_bits_i))
                .reduce();
            prod_exponent *= &rand_bits_i;
            i += 1;
        }

        let rgoth_square = rgoth.compose(&rgoth).reduce();

        let gq_tmp = rgoth_square.phi_q_to_the_minus_1(q).reduce();

        let gq = gq_tmp.exp(q);

        CLGroup {
            delta_k,
            delta_q,
            gq,
            stilde,
        }
    }

    //repeat random element g_q generation using seed and delta_k
    pub fn setup_verify(&self, seed: &BigInt) -> Result<(), ErrorReason> {
        unsafe { pari_init(100000000, 2) };

        let mut prime_forms_vec: Vec<BinaryQF> = Vec::new();
        let ln_delta_k = numerical_log(&(-&self.delta_k));
        let num_of_prime_forms = ln_delta_k.div_floor(&numerical_log(&ln_delta_k));

        let mut r = BigInt::from(3);
        let mut i = BigInt::zero();
        while i < num_of_prime_forms {
            while jacobi(&self.delta_k, &r).unwrap() != 1 {
                r = next_probable_small_prime(&r)
            }
            prime_forms_vec.push(BinaryQF::primeform(&self.delta_k, &r));
            r = next_probable_small_prime(&r);
            i += 1;
        }

        let mut rgoth = BinaryQF::binary_quadratic_form_principal(&self.delta_k);

        //pseudo random element of class group Cl(delta_k) : prod f_p^e_p, with pairwise coprime exponents
        // generate enough pseudo randomness : 15 bits per exponents e_p

        // find exponent
        let mut i = 0;
        let mut rand_bits_i: BigInt;
        let mut prod_exponent = BigInt::one();
        while i < prime_forms_vec.len() {
            // extract 15bits
            rand_bits_i = prng(seed, i, 15);
            while rand_bits_i.gcd(&prod_exponent) != BigInt::one() {
                rand_bits_i += 1;
            }
            rgoth = rgoth
                .compose(&prime_forms_vec[i].exp(&rand_bits_i))
                .reduce();
            prod_exponent *= &rand_bits_i;
            i += 1;
        }

        let rgoth_square = rgoth.compose(&rgoth).reduce();

        let gq_tmp = rgoth_square
            .phi_q_to_the_minus_1(Scalar::<Bls12_381_1>::group_order())
            .reduce();

        let gq = gq_tmp.exp(Scalar::<Bls12_381_1>::group_order());
        match gq == self.gq {
            true => Ok(()),
            false => Err(ErrorReason::SetupError),
        }
    }

    /// randomly sample a scalar (secret key) and compute its corresponding group element (public key) by multiplying g_q
    pub fn keygen(&self) -> (SK, PK) {
        let sk = SK(BigInt::sample_below(
            &(&self.stilde * BigInt::from(2).pow(40)),
        ));
        let pk = self.pk_for_sk(&sk);
        (sk, pk)
    }

    /// Return the CL public key for a given secret key
    pub fn pk_for_sk(&self, sk: &SK) -> PK {
        let group_element = self.gq.exp(&sk.0);
        PK(group_element)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PK(pub BinaryQF);
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SK(pub BigInt);

impl From<SK> for BigInt {
    fn from(sk: SK) -> Self {
        sk.0
    }
}

impl From<BigInt> for SK {
    fn from(bi: BigInt) -> Self {
        Self(bi)
    }
}

// copied from https://docs.rs/crate/quadratic/0.3.1/source/src/lib.rs
// changed to support BigInt
// TODO: put in utility module, expend to Kronecker
fn jacobi(a: &BigInt, n: &BigInt) -> Option<i8> {
    let zero = BigInt::zero();
    // jacobi symbol is only defined for odd positive moduli
    if n.mod_floor(&BigInt::from(2)) == zero || n <= &BigInt::zero() {
        return None;
    }

    // Raise a mod n, then start the unsigned algorithm
    let mut acc = 1;
    let mut num = a.mod_floor(n);
    let mut den = n.clone();
    loop {
        // reduce numerator
        num = num.mod_floor(&den);
        if num == zero {
            return Some(0);
        }

        // extract factors of two from numerator
        while num.mod_floor(&BigInt::from(2)) == zero {
            acc *= two_over(&den);
            num = num.div_floor(&BigInt::from(2));
        }
        // if numerator is 1 => this sub-symbol is 1
        if num == BigInt::one() {
            return Some(acc);
        }
        // shared factors => one sub-symbol is zero
        if num.gcd(&den) > BigInt::one() {
            return Some(0);
        }
        // num and den are now odd co-prime, use reciprocity law:
        acc *= reciprocity(&num, &den);
        let tmp = num;
        num = den.clone();
        den = tmp;
    }
}

fn two_over(n: &BigInt) -> i8 {
    if n.mod_floor(&BigInt::from(8)) == BigInt::one()
        || n.mod_floor(&BigInt::from(8)) == BigInt::from(7)
    {
        1
    } else {
        -1
    }
}

fn reciprocity(num: &BigInt, den: &BigInt) -> i8 {
    if num.mod_floor(&BigInt::from(4)) == BigInt::from(3)
        && den.mod_floor(&BigInt::from(4)) == BigInt::from(3)
    {
        -1
    } else {
        1
    }
}

fn next_probable_prime(r: &BigInt) -> BigInt {
    let one = BigInt::from(1);
    let mut qtilde = r + &one;
    while !is_prime(&qtilde) {
        qtilde += &one;
    }
    qtilde
}

// used for testing small primes where our prime test fails. We use Pari isprime which provides
// determinstic perfect primality checking.
fn next_probable_small_prime(r: &BigInt) -> BigInt {
    let one = BigInt::from(1);
    let mut qtilde = r + &one;
    let mut qtilde_gen = bn_to_gen(&(r + &one));
    unsafe {
        while isprime(qtilde_gen) as c_int != 1 {
            qtilde += &one;
            qtilde_gen = bn_to_gen(&qtilde);
        }
    }
    qtilde
}

/// CL encrypts the message under the public key.
///
/// Returns the secret randomness used.
pub fn encrypt(group: &CLGroup, public_key: &PK, m: &Scalar<Bls12_381_1>) -> (Ciphertext, SK) {
    unsafe { pari_init(10000000, 2) };
    let (r, R) = group.keygen();
    let exp_f = BinaryQF::expo_f(
        Scalar::<Bls12_381_1>::group_order(),
        &group.delta_q,
        &m.to_bigint(),
    );
    let h_exp_r = public_key.0.exp(&r.0);

    (
        Ciphertext {
            c1: R.0,
            c2: h_exp_r.compose(&exp_f).reduce(),
        },
        r,
    )
}

pub fn encrypt_predefined_randomness(
    group: &CLGroup,
    public_key: &PK,
    m: &Scalar<Bls12_381_1>,
    r: &SK,
) -> Ciphertext {
    unsafe { pari_init(10000000, 2) };
    let exp_f = BinaryQF::expo_f(
        Scalar::<Bls12_381_1>::group_order(),
        &group.delta_q,
        &m.to_bigint(),
    );
    let h_exp_r = public_key.0.exp(&r.0);

    Ciphertext {
        c1: group.gq.exp(&r.0),
        c2: h_exp_r.compose(&exp_f).reduce(),
    }
}

pub fn verifiably_encrypt(
    group: &CLGroup,
    public_key: &PK,
    DL_pair: (&Scalar<Bls12_381_1>, &Point<Bls12_381_1>),
) -> (Ciphertext, CLDLProof) {
    let (x, X) = DL_pair;
    let (ciphertext, r) = encrypt(group, public_key, x);

    let proof = CLDLProof::prove(group, (x, &r), (public_key, &ciphertext, X));
    (ciphertext, proof)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CLDLProof {
    pub t_triple: TTriplets,
    pub u1u2: U1U2,
}

impl CLDLProof {
    fn prove(
        group: &CLGroup,
        witness: (&Scalar<Bls12_381_1>, &SK),
        statement: (&PK, &Ciphertext, &Point<Bls12_381_1>),
    ) -> Self {
        unsafe { pari_init(10000000, 2) };
        let (x, r) = witness;
        let (public_key, ciphertext, X) = statement;

        let r1 = BigInt::sample_below(
            &(&group.stilde
                * BigInt::from(2).pow(40)
                * BigInt::from(2).pow(SECURITY_PARAMETER as u32)
                * BigInt::from(2).pow(40)),
        );
        let r2_fe = Scalar::<Bls12_381_1>::random();
        let r2 = r2_fe.to_bigint();
        let fr2 = BinaryQF::expo_f(Scalar::<Bls12_381_1>::group_order(), &group.delta_q, &r2);
        let pkr1 = public_key.0.exp(&r1);
        let t2 = fr2.compose(&pkr1).reduce();
        let T = Point::<Bls12_381_1>::generator() * r2_fe;
        let t1 = group.gq.exp(&r1);
        let t_triple = TTriplets { t1, t2, T };

        let k = Self::challenge(public_key, &t_triple, ciphertext, X);

        let u1 = r1 + &k * &r.0;
        let u2 = BigInt::mod_add(
            &r2,
            &(&k * x.to_bigint()),
            Scalar::<Bls12_381_1>::group_order(),
        );
        let u1u2 = U1U2 { u1, u2 };

        Self { t_triple, u1u2 }
    }

    /// Compute the Fiat-Shamir challenge for the proof.
    fn challenge(
        public_key: &PK,
        t: &TTriplets,
        ciphertext: &Ciphertext,
        X: &Point<Bls12_381_1>,
    ) -> BigInt {
        let hash256 = Sha256::new()
            // hash the statement i.e. the discrete log of Q is encrypted in (c1,c2) under encryption key h.
            .chain_point(X)
            .chain(ciphertext.c1.to_bytes())
            .chain(ciphertext.c2.to_bytes())
            .chain(public_key.0.to_bytes())
            // hash Sigma protocol commitments
            .chain(t.t1.to_bytes())
            .chain(t.t2.to_bytes())
            .chain_point(&t.T)
            .finalize();

        BigInt::from_bytes(&hash256[..SECURITY_PARAMETER / 8])
    }

    pub fn verify(
        &self,
        group: &CLGroup,
        public_key: &PK,
        ciphertext: &Ciphertext,
        X: &Point<Bls12_381_1>,
    ) -> Result<(), ProofError> {
        unsafe { pari_init(10000000, 2) };
        let mut flag = true;

        // reconstruct k
        let k = Self::challenge(public_key, &self.t_triple, ciphertext, X);

        let sample_size = &group.stilde
            * (BigInt::from(2).pow(40))
            * BigInt::from(2).pow(SECURITY_PARAMETER as u32)
            * (BigInt::from(2).pow(40) + BigInt::one());

        //length test u1:
        if self.u1u2.u1 > sample_size || self.u1u2.u1 < BigInt::zero() {
            flag = false;
        }
        // length test u2:
        if &self.u1u2.u2 > Scalar::<Bls12_381_1>::group_order() || self.u1u2.u2 < BigInt::zero() {
            flag = false;
        }

        let c1k = ciphertext.c1.exp(&k);
        let t1c1k = self.t_triple.t1.compose(&c1k).reduce();
        let gqu1 = group.gq.exp(&self.u1u2.u1);
        if t1c1k != gqu1 {
            flag = false;
        };

        let k_bias_fe: Scalar<Bls12_381_1> = Scalar::<Bls12_381_1>::from(&(&k + BigInt::one()));
        let g = Point::<Bls12_381_1>::generator();
        let t2kq = (&self.t_triple.T + X * &k_bias_fe) - X;
        let u2p = g * Scalar::<Bls12_381_1>::from(&self.u1u2.u2);
        if t2kq != u2p {
            flag = false;
        }

        let pku1 = public_key.0.exp(&self.u1u2.u1);
        let fu2 = BinaryQF::expo_f(
            Scalar::<Bls12_381_1>::group_order(),
            &group.delta_q,
            &self.u1u2.u2,
        );
        let c2k = ciphertext.c2.exp(&k);
        let t2c2k = self.t_triple.t2.compose(&c2k).reduce();
        let pku1fu2 = pku1.compose(&fu2).reduce();
        if t2c2k != pku1fu2 {
            flag = false;
        }
        match flag {
            true => Ok(()),
            false => Err(ProofError),
        }
    }
}

pub fn decrypt(group: &CLGroup, secret_key: &SK, c: &Ciphertext) -> Scalar<Bls12_381_1> {
    unsafe { pari_init(10000000, 2) };
    let c1_x = c.c1.exp(&secret_key.0);
    let c1_x_inv = c1_x.inverse();
    let tmp = c.c2.compose(&c1_x_inv).reduce();
    let plaintext =
        BinaryQF::discrete_log_f(Scalar::<Bls12_381_1>::group_order(), &group.delta_q, &tmp);
    debug_assert!(&plaintext < Scalar::<Bls12_381_1>::group_order());
    Scalar::<Bls12_381_1>::from(&plaintext)
}

/// Multiplies the encrypted value by `val`.
pub fn eval_scal(c: &Ciphertext, val: &BigInt) -> Ciphertext {
    unsafe { pari_init(10000000, 2) };

    Ciphertext {
        c1: c.c1.exp(val),
        c2: c.c2.exp(val),
    }
}

/// Homomorphically adds two ciphertexts so that the resulting ciphertext is the sum of the two input ciphertexts
pub fn eval_sum(c1: &Ciphertext, c2: &Ciphertext) -> Ciphertext {
    unsafe { pari_init(10000000, 2) };

    Ciphertext {
        c1: c1.c1.compose(&c2.c1).reduce(),
        c2: c1.c2.compose(&c2.c2).reduce(),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const seed: &str =  "314159265358979323846264338327950288419716939937510582097494459230781640628620899862803482534211706798214808651328230664709384460955058223172535940812848";
    #[test]
    fn encrypt_and_decrypt() {
        let group = CLGroup::new_from_setup(&1600, &BigInt::from_str_radix(seed, 10).unwrap());
        let (secret_key, public_key) = group.keygen();
        let message = Scalar::<Bls12_381_1>::random();
        let (ciphertext, _) = encrypt(&group, &public_key, &message);
        let plaintext = decrypt(&group, &secret_key, &ciphertext);
        assert_eq!(plaintext, message);
    }

    #[test]
    fn compute_discrete_log_in_DLEasy_subgroup() {
        let group = CLGroup::new_from_setup(&1600, &BigInt::from_str_radix(seed, 10).unwrap());
        let m = BigInt::from(10000);
        let exp_f = BinaryQF::expo_f(Scalar::<Bls12_381_1>::group_order(), &group.delta_q, &m);
        let m_tag =
            BinaryQF::discrete_log_f(Scalar::<Bls12_381_1>::group_order(), &group.delta_q, &exp_f);
        assert_eq!(m, m_tag);
    }

    #[test]
    fn verifiably_encrypt_verify_and_decrypt() {
        let group = CLGroup::new_from_setup(&1600, &BigInt::from_str_radix(seed, 10).unwrap());
        let (secret_key, public_key) = group.keygen();
        let dl_keypair = {
            let sk = Scalar::<Bls12_381_1>::random();
            let pk = Point::<Bls12_381_1>::generator() * &sk;
            (sk, pk)
        };
        let (ciphertext, proof) =
            verifiably_encrypt(&group, &public_key, (&dl_keypair.0, &dl_keypair.1));

        let wrong_dl_pk = &dl_keypair.1 + Point::<Bls12_381_1>::generator();

        assert!(
            proof
                .verify(&group, &public_key, &ciphertext, &dl_keypair.1)
                .is_ok(),
            "proof is valid against valid DL key"
        );

        assert!(
            proof
                .verify(&group, &public_key, &ciphertext, &wrong_dl_pk)
                .is_err(),
            "proof is invalid against invalid DL key"
        );

        assert_eq!(
            decrypt(&group, &secret_key, &ciphertext),
            dl_keypair.0,
            "plaintext matches what was encrypted"
        );
    }

    #[test]
    fn multiply_ciphertext_by_scalar() {
        let group = CLGroup::new_from_setup(&1600, &BigInt::from_str_radix(seed, 10).unwrap());
        let (secret_key, public_key) = group.keygen();
        let scalar = Scalar::<Bls12_381_1>::random();

        let (ciphertext, _) = encrypt(&group, &public_key, &scalar);

        let multiply_by = Scalar::<Bls12_381_1>::random();
        let mutated_ciphertext = eval_scal(&ciphertext, &multiply_by.to_bigint());
        let plaintext = decrypt(&group, &secret_key, &mutated_ciphertext);
        let expected = scalar * multiply_by;

        assert_eq!(plaintext, expected, "plaintext was multiplied");
    }

    #[test]
    fn add_ciphertexts() {
        let group = CLGroup::new_from_setup(&1600, &BigInt::from_str_radix(seed, 10).unwrap());
        let (secret_key, public_key) = group.keygen();
        let scalar1 = Scalar::<Bls12_381_1>::random();
        let scalar2 = Scalar::<Bls12_381_1>::random();

        let (ciphertext1, _) = encrypt(&group, &public_key, &scalar1);
        let (ciphertext2, _) = encrypt(&group, &public_key, &scalar2);

        let combined = eval_sum(&ciphertext1, &ciphertext2);
        let plaintext = decrypt(&group, &secret_key, &combined);
        let expected = scalar1 + scalar2;

        assert_eq!(plaintext, expected, "ciphertexts were added");
    }

    #[test]
    fn cl_dl_test_setup() {
        let parsed_seed = BigInt::from_str_radix(seed, 10).unwrap();
        let group = CLGroup::new_from_setup(&1600, &parsed_seed);
        assert!(group.setup_verify(&parsed_seed).is_ok());
    }
    
}
