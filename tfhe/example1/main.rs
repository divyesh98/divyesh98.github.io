use tfhe::integer::RadixCiphertext;
use tfhe::integer::IntegerCiphertext;
use tfhe::integer::gen_keys_radix;

use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2;

fn main(){
  let num_blocks = 4;
  let (cks, sks) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2, num_blocks);
  let num = 47u8;

  let cipher = cks.encrypt(num);

  let shortint_sk: tfhe::shortint::ServerKey = sks.clone().into();

  let output: RadixCiphertext = sks.create_trivial_radix(0u64, num_blocks);

  let mut res1 = sks.smart_scalar_eq_parallelized(&mut cipher, 47);
  let res2 = shortint_sk.create_trivial(1);

  res1.into_radix(num_blocks, &sks);

  let res1_blocks = res1.blocks_mut();
  shortint_sk.smart_mul_lsb_assign(&mut res1_blocks[num_blocks - 1], &mut res2);

  sks.smart_add_assign_parallelized(&mut output, &mut res1);
}
