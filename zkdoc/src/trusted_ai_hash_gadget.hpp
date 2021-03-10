#ifndef __TRUSTED_AI_HASH_GADGET_HPP__
#define __TRUSTED_AI_HASH_GADGET_HPP__

using namespace libsnark;

namespace TrustedAI {

template<typename FieldT>
class Power {
public:
    static FieldT power_of_two(size_t N) {
        if (N == 0) return FieldT::one();

        if (N % 2 == 0) 
            return Power<FieldT>::power_of_two(N/2) * 
                Power<FieldT>::power_of_two(N/2);
        else
            return Power<FieldT>::power_of_two(N/2) * 
                Power<FieldT>::power_of_two(N/2) * FieldT(2);

    };
};


// computes hash of a column of field elements
// where P elements are packed into a single
// field element.
template<typename FieldT, size_t N, size_t P>
class mimc_hash_column;

template<typename FieldT>
class mimc_cipher : public gadget<FieldT> {
public:
    static const size_t ROUNDS = 64;
    pb_variable<FieldT> input_, key_, hash_;
    std::vector<FieldT> round_constants_ {
		42,
		43,
		170,
		2209,
		16426,
		78087,
		279978,
		823517,
		2097194,
		4782931,
		10000042,
		19487209,
		35831850,
		62748495,
		105413546,
		170859333,
		268435498,
		410338651,
		612220074,
		893871697,
		1280000042,
		1801088567,
		2494357930,
		3404825421,
		4586471466,
		6103515587,
		8031810218,
		10460353177,
		13492928554,
		17249876351,
		21870000042,
		27512614133,
		34359738410,
		42618442955,
		52523350186,
		64339296833,
		78364164138,
		94931877159,
		114415582634,
		137231006717,
		163840000042,
		194754273907,
		230539333290,
		271818611081,
		319277809706,
		373669453167,
		435817657258,
		506623120485,
		587068342314,
		678223072891,
		781250000042,
		897410677873,
		1028071702570,
		1174711139799,
		1338925210026,
		1522435234413,
		1727094849578,
		1954897493219,
		2207984167594,
		2488651484857,
		2799360000042,
		3142742835999,
		3521614606250,
		3938980639125
    };

private:
    pb_variable_array<FieldT> intermediate_inputs_;
    pb_variable_array<FieldT> intermediate_lc2_;
    pb_variable_array<FieldT> intermediate_lc4_;
    pb_variable_array<FieldT> intermediate_lc6_;
    
public:
    mimc_cipher(
        protoboard<FieldT>& pb,
        const pb_variable<FieldT>& input,
        const pb_variable<FieldT>& key,
        const pb_variable<FieldT>& hash,
        const std::string& annotation_prefix);
    
    void allocate();
    void generate_r1cs_constraints();
    void generate_r1cs_witness();

}; // end of class definition mimc_cipher

template<typename FieldT, size_t N, size_t P>
class mimc_hash_column : public gadget<FieldT> {
public:
    std::vector<pb_variable<FieldT>> input_;
    pb_variable<FieldT> hash_;

private:
    std::vector<std::shared_ptr<mimc_cipher<FieldT>>> mimc_hashers_;
    pb_variable_array<FieldT> packed_input_;
    pb_variable_array<FieldT> intermediate_keys_;

public:
    mimc_hash_column(
        protoboard<FieldT>& pb,
        const std::vector<pb_variable<FieldT>>& input,
        const pb_variable<FieldT>& hash,
        const std::string& annotation_prefix=""):
        gadget<FieldT>(pb, annotation_prefix),
        input_(input), hash_(hash) {
            mimc_hashers_.resize(libff::div_ceil(N, P));
        };

    void allocate();
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};


template<typename FieldT, size_t N, size_t P>
class mimc_hash_integer : public gadget<FieldT> {
public:
    std::shared_ptr<integer_vector<FieldT, N>> input_;
    pb_variable<FieldT> hash_;

private:
    std::shared_ptr<mimc_hash_column<FieldT, N, P>> mimc_hasher_;
    std::shared_ptr<mimc_cipher<FieldT>> mimc_final_hasher_;
    pb_variable<FieldT> hash_intermediate_;

public:
    mimc_hash_integer(
        protoboard<FieldT>& pb,
        const std::shared_ptr<integer_vector<FieldT, N>> input,
        const pb_variable<FieldT>& hash,
        const std::string& annotation_prefix=""):
        gadget<FieldT>(pb, annotation_prefix),
        input_(input), hash_(hash) {};

    void allocate();
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename FieldT, size_t N, size_t P>
class mimc_hash_categorical : public gadget<FieldT> {
public:
    std::shared_ptr<categorical_vector<FieldT, N>> input_;
    pb_variable<FieldT> hash_;

private:
    std::shared_ptr<mimc_hash_column<FieldT, N, P>> mimc_hasher_;
    std::shared_ptr<mimc_cipher<FieldT>> mimc_final_hasher_;
    pb_variable<FieldT> hash_intermediate_;

public:
    mimc_hash_categorical(
        protoboard<FieldT>& pb,
        const std::shared_ptr<categorical_vector<FieldT, N>> input,
        const pb_variable<FieldT>& hash,
        const std::string& annotation_prefix=""):
        gadget<FieldT>(pb, annotation_prefix),
        input_(input), hash_(hash) {};

    void allocate();
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename FieldT, size_t N, size_t P>
class mimc_hash_signed : public gadget<FieldT> {
public:
    std::shared_ptr<signed_vector<FieldT, N>> input_;
    pb_variable<FieldT> hash_;

private:
    std::shared_ptr<mimc_hash_column<FieldT, N, P>> mimc_hasher_;
    std::shared_ptr<mimc_cipher<FieldT>> mimc_final_hasher_;
    pb_variable<FieldT> hash_intermediate_;
    std::vector<pb_variable<FieldT>> sign_free_vals;

public:
    mimc_hash_signed(
        protoboard<FieldT>& pb,
        const std::shared_ptr<signed_vector<FieldT, N>> input,
        const pb_variable<FieldT>& hash,
        const std::string& annotation_prefix=""):
        gadget<FieldT>(pb, annotation_prefix),
        input_(input), hash_(hash) { sign_free_vals.resize(N); };

    void allocate();
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

//template<typename FieldT, size_t N, size_t C, size_t M>
//class mimc_hash_datasource

} // end of namespace    

#include <zkdoc/src/trusted_ai_hash_gadget.cpp>

#endif
