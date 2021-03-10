
using namespace libsnark;

namespace TrustedAI {


template<typename FieldT>
mimc_cipher<FieldT>::mimc_cipher(
    protoboard<FieldT>& pb,
    const pb_variable<FieldT>& input,
    const pb_variable<FieldT>& key,
    const pb_variable<FieldT>& hash,
    const std::string& annotation_prefix):
    gadget<FieldT>(pb, annotation_prefix),
    input_(input), key_(key), hash_(hash)
{

}

template<typename FieldT>
void mimc_cipher<FieldT>::allocate()
{
    //input[i] ----> ROUND(i) -----> input[i+1]
    intermediate_inputs_.allocate(this->pb, ROUNDS+1, "intermediate_inputs");
    intermediate_lc2_.allocate(this->pb, ROUNDS, "intermediate_lc2");
    intermediate_lc4_.allocate(this->pb, ROUNDS, "intermediate_lc4");
    intermediate_lc6_.allocate(this->pb, ROUNDS, "intermediate_lc6");
}    

template<typename FieldT>
void mimc_cipher<FieldT>::generate_r1cs_constraints()
{
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(
            intermediate_inputs_[0],
            1,
            input_), "intermediate_[0] = input[0]");

    for(size_t i=0; i < ROUNDS; ++i) {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                intermediate_inputs_[i] + key_ + round_constants_[i],
                intermediate_inputs_[i] + key_ + round_constants_[i],
                intermediate_lc2_[i]), "a=input+key+rc");
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                intermediate_lc2_[i],
                intermediate_lc2_[i],
                intermediate_lc4_[i]), "a4 = a2*a2");
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                intermediate_lc4_[i],
                intermediate_lc2_[i],
                intermediate_lc6_[i]), "a6=a4*a2");
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                intermediate_inputs_[i] + key_ + round_constants_[i],
                intermediate_lc6_[i],
                intermediate_inputs_[i+1]), "input[i+1]=f(input[i])");
    }

    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(
            intermediate_inputs_[ROUNDS] + key_,
            1,
            hash_), "hash_ = final_input + key");
}

template<typename FieldT>
void mimc_cipher<FieldT>::generate_r1cs_witness()
{
    this->pb.val(intermediate_inputs_[0]) = this->pb.val(input_);
    for(size_t i=0; i < ROUNDS; ++i) {
        pb_linear_combination<FieldT> lc;
        lc.assign(this->pb, intermediate_inputs_[i] + key_ + round_constants_[i]);
        lc.evaluate(this->pb);
        this->pb.val(intermediate_lc2_[i]) = this->pb.lc_val(lc) * this->pb.lc_val(lc);
        this->pb.val(intermediate_lc4_[i]) = this->pb.val(intermediate_lc2_[i]) * this->pb.val(intermediate_lc2_[i]);
        this->pb.val(intermediate_lc6_[i]) = this->pb.val(intermediate_lc4_[i]) * this->pb.val(intermediate_lc2_[i]);
        this->pb.val(intermediate_inputs_[i+1]) = this->pb.lc_val(lc) * this->pb.val(intermediate_lc6_[i]);
    }
    
    this->pb.val(hash_) = this->pb.val(intermediate_inputs_[ROUNDS]) + this->pb.val(key_);
}


template<typename FieldT, size_t N, size_t P>
void mimc_hash_column<FieldT, N, P>::allocate()
{
    size_t num_hashers = mimc_hashers_.size();
    intermediate_keys_.allocate(this->pb, num_hashers+1, "intermediate_keys");
    packed_input_.allocate(this->pb, num_hashers, "packed_input");

    for(size_t i=0; i < mimc_hashers_.size(); ++i) {
        mimc_hashers_[i].reset(new mimc_cipher<FieldT>(
            this->pb,
            packed_input_[i],
            intermediate_keys_[i],
            intermediate_keys_[i+1],
            "mimc_hasher_iterations"));
        mimc_hashers_[i]->allocate();
    }
}

template<typename FieldT, size_t N, size_t P>
void mimc_hash_column<FieldT, N, P>::generate_r1cs_constraints()
{
    size_t num_hashers = mimc_hashers_.size();
    size_t chunk_size = FieldT::capacity()/P;

    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(intermediate_keys_[0], 1, 0), "keys[0] = 0");

    // generate packing constraints
    for(size_t i=0; i < N; i = i+P) {
        size_t u = ((i+P) > N)?N:(i+P);
        FieldT x = Power<FieldT>::power_of_two(chunk_size);
        linear_combination<FieldT> lc(input_[u-1]);
         
        for(ssize_t j=u-2; j >= ssize_t(i); j=j-1) {
            lc = input_[size_t(j)] + x * lc;
        }
        
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(lc, 1, packed_input_[i/P]), "packing constraint");
        
    }
   
    // generate hasher constraints
    for(size_t i=0; i < num_hashers; ++i)
        mimc_hashers_[i]->generate_r1cs_constraints();
 
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(intermediate_keys_[num_hashers], 1, hash_), "hash=keys[num_hashers]");
    
}

template<typename FieldT, size_t N, size_t P>
void mimc_hash_column<FieldT, N, P>::generate_r1cs_witness()
{
    size_t num_hashers = mimc_hashers_.size();
    size_t chunk_size = FieldT::capacity()/P;
       
    this->pb.val(intermediate_keys_[0]) = FieldT::zero();
    
    // generate packed field elements
    for(size_t i=0; i < N; i=i+P) {
        size_t u = ((i+P) > N)?N:(i+P);
        FieldT x = Power<FieldT>::power_of_two(chunk_size);
        linear_combination<FieldT> lc = input_[u-1];
        for(ssize_t j=u-2; j >= ssize_t(i); --j)
            lc = input_[size_t(j)] + x * lc;
        
        pb_linear_combination<FieldT> plc;
        plc.assign(this->pb, lc);
        plc.evaluate(this->pb);
        this->pb.val(packed_input_[i/P]) = this->pb.lc_val(plc);
    }

    // generate hasher witnesses
    for(size_t i=0; i < mimc_hashers_.size(); ++i)
        mimc_hashers_[i]->generate_r1cs_witness();

    // set the final hash value
    this->pb.val(hash_) = this->pb.val(intermediate_keys_[num_hashers]);
}

template<typename FieldT, size_t N, size_t P>
void mimc_hash_integer<FieldT, N, P>::allocate()
{
    hash_intermediate_.allocate(this->pb, "hash_intermediate");
    mimc_hasher_.reset(new mimc_hash_column<FieldT, N, P>(
        this->pb,
        input_->get_pb_vals(),
        hash_intermediate_,
        "mimc_hasher"));

    mimc_hasher_->allocate();

    mimc_final_hasher_.reset(new mimc_cipher<FieldT>(
        this->pb,
        input_->vsize_,
        hash_intermediate_,
        hash_,
        "mimc_final_hasher"));
    mimc_final_hasher_->allocate();
}

template<typename FieldT, size_t N, size_t P>
void mimc_hash_integer<FieldT, N, P>::generate_r1cs_constraints()
{
    mimc_hasher_->generate_r1cs_constraints();
    mimc_final_hasher_->generate_r1cs_constraints();
}

template<typename FieldT, size_t N, size_t P>
void mimc_hash_integer<FieldT, N, P>::generate_r1cs_witness()
{
    mimc_hasher_->generate_r1cs_witness();
    mimc_final_hasher_->generate_r1cs_witness();
}

template<typename FieldT, size_t N, size_t P>
void mimc_hash_categorical<FieldT, N, P>::allocate()
{
    hash_intermediate_.allocate(this->pb, "hash_intermediate");
    mimc_hasher_.reset(new mimc_hash_column<FieldT, N, P>(
        this->pb,
        input_->get_pb_vals(),
        hash_intermediate_,
        "mimc_hasher"));
    mimc_final_hasher_.reset(new mimc_cipher<FieldT>(
        this->pb,
        input_->vsize_,
        hash_intermediate_,
        hash_,
        "mimc_final_hasher"));
    mimc_hasher_->allocate();
    mimc_final_hasher_->allocate();

}

template<typename FieldT, size_t N, size_t P>
void mimc_hash_categorical<FieldT, N, P>::generate_r1cs_constraints()
{
    mimc_hasher_->generate_r1cs_constraints();
    mimc_final_hasher_->generate_r1cs_constraints();
}

template<typename FieldT, size_t N, size_t P>
void mimc_hash_categorical<FieldT, N, P>::generate_r1cs_witness()
{
    mimc_hasher_->generate_r1cs_witness();
    mimc_final_hasher_->generate_r1cs_witness();
}


template<typename FieldT, size_t N, size_t P>
void mimc_hash_signed<FieldT, N, P>::allocate()
{
    hash_intermediate_.allocate(this->pb, "hash_intermediate");
    for(size_t i=0; i < N; ++i)
        sign_free_vals[i].allocate(this->pb, "sign_free_vals");
     
    mimc_hasher_.reset(new mimc_hash_column<FieldT, N, P>(
        this->pb,
        sign_free_vals,
        hash_intermediate_,
        "mimc_hasher"));
    mimc_final_hasher_.reset(new mimc_cipher<FieldT>(
        this->pb,
        input_->vsize_,
        hash_intermediate_,
        hash_,
        "mimc_final_hasher"));
    mimc_hasher_->allocate();
    mimc_final_hasher_->allocate();

}

template<typename FieldT, size_t N, size_t P>
void mimc_hash_signed<FieldT, N, P>::generate_r1cs_constraints()
{

    auto input_vals = input_->get_pb_vals();
    auto input_signs = input_->get_pb_vals_signs();

    for(size_t i=0; i < N; ++i) {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                input_vals[i],
                1 - 2*input_signs[i],
                sign_free_vals[i]), "sign_free_val[i] = (1-2s[i]).v[i]");
    }
                
    mimc_hasher_->generate_r1cs_constraints();
    mimc_final_hasher_->generate_r1cs_constraints();
}

template<typename FieldT, size_t N, size_t P>
void mimc_hash_signed<FieldT, N, P>::generate_r1cs_witness()
{
    auto input_vals = input_->get_pb_vals();
    auto input_signs = input_->get_pb_vals_signs();

    for(size_t i=0; i < N; ++i) {
        this->pb.val(sign_free_vals[i]) = (FieldT::one() - FieldT(2)*this->pb.val(input_signs[i])) * this->pb.val(input_vals[i]);
    }

    mimc_hasher_->generate_r1cs_witness();
    mimc_final_hasher_->generate_r1cs_witness();
}




} // end of namespace
