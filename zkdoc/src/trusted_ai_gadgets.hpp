#ifndef __TRUSTED_AI_GADGETS__
#define __TRUSTED_AI_GADGETS__

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/edwards/edwards_pp.hpp>
#include <vector>
#include <memory>
#include <tuple>

using namespace libsnark;

namespace TrustedAI {

//! bit size for integer values
const size_t integer_bit_width = 40;
//! bit size for categorical values
const size_t categorical_bit_width = 8;
//! bit size for numeric values
const size_t float_bit_width = 64;

//! maximum permissible precision
const uint64_t float_precision = 10000;
//! precision level used for interfacing variables
const uint64_t float_precision_safe = 100;

//! number of categorical variables packed into a field element
const size_t packing_categorical = 31;
//! number of integer variables packed into a field element
const size_t packing_integer = 6;

//! representation of a double as (s,v,k)
//! Actual value is given by (-1)^s.v/k
typedef std::tuple<uint64_t, uint64_t, uint64_t> safe_tuple_t;

/**
 * Convert a double to (s,v,k) tuple, at given precision
 *\param [in] f
 *\return (s,v,k) representation of f
 */
template<size_t precision>
safe_tuple_t safe_double(double f)
{
    uint64_t s, v, k;
    s = (f >= 0)?0:1;
    v = (abs(f) * precision + 0.5);
    k = precision;
    return {s, v, k};
}

/**
 * Class to represent integer variable
 */
template<typename FieldT>
class integer_variable : public gadget<FieldT> {
private:
    //! gadget linking integer value to bit representation
    std::shared_ptr<packing_gadget<FieldT> > pack_gadget;

public:
    //! integral value
    pb_variable<FieldT> iv;
    //! bit representation of integer value
    pb_variable_array<FieldT> bits;
    //! place holder for value to be assigned to iv
    //! at the time of witness generation.
    uint64_t value_;

public:
    integer_variable(
        protoboard<FieldT>& pb, 
        const std::string &annotation=""): 
    gadget<FieldT>(pb, annotation) {};

    //! allocate internal variables on protoboard
    void allocate() {
        iv.allocate(this->pb, this->annotation_prefix);
        bits.allocate(this->pb, integer_bit_width, this->annotation_prefix);
        pack_gadget.reset(new packing_gadget<FieldT>(this->pb, bits, iv, this->annotation_prefix));
    };

    //! set the witness value
    void set_value(uint64_t value) {
        this->value_ = value;
    };

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

/**
 * Class to represent array of integers
 */
template<typename FieldT>
class integer_variable_array : public gadget<FieldT> {
public:
    /**
     *\param ivVec contains integer variables
     *\param values_ contains the witness
     *\param size_ contains the size of the array
     */
    std::vector<integer_variable<FieldT> > ivVec;
    std::vector<uint64_t> values_;
    size_t size_;

public:
    integer_variable_array(
        protoboard<FieldT>& pb, 
        size_t size,
        const std::string& annotation_prefix=""): 
    gadget<FieldT>(pb, annotation_prefix), size_(size) {
        for(size_t i=0; i < size_; ++i)
            ivVec.emplace_back(integer_variable<FieldT>(pb, annotation_prefix));
     };
    
    //! allocate constituent variables on protoboard
    void allocate() {
        for(size_t i=0; i < ivVec.size(); ++i) 
            ivVec[i].allocate();
    };

    //! set up the witness
    //!\param values the array of values to be set
    void set_values(const std::vector<uint64_t>& values) 
    {
        //! The input array is 0-extend/truncated to size_ elements
        this->values_ = values;
        this->values_.resize(size_, 0);
        for(size_t i=0; i < this->size_; ++i)
            ivVec[i].set_value(values_[i]);
    };

    void generate_r1cs_constraints(bool enforce_boolean = true);
    void generate_r1cs_witness();

};

/**
 * Class to represent categorical variable
 * The documentation for integer variable also
 * applies to this class.
 */
template<typename FieldT>
class categorical_variable : public gadget<FieldT> {
private:
    std::shared_ptr<packing_gadget<FieldT> > pack_gadget;

public:
    pb_variable<FieldT> iv;
    pb_variable_array<FieldT> bits;
    uint64_t value_;

public:
    categorical_variable(
        protoboard<FieldT>& pb, 
        const std::string& annotation_prefix=""): 
    gadget<FieldT>(pb, annotation_prefix) {};

    void allocate() {
        iv.allocate(this->pb, this->annotation_prefix);
        bits.allocate(this->pb, categorical_bit_width, this->annotation_prefix);
        pack_gadget.reset(new packing_gadget<FieldT>(this->pb, bits, iv, this->annotation_prefix));
    };

    void set_value(uint64_t value) {
        this->value_ = value;
    };

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

/**
 * Class for array of categorical variables
 */
template<typename FieldT>
class categorical_variable_array : public gadget<FieldT> {
public:
    std::vector<categorical_variable<FieldT> > ivVec;
    std::vector<uint64_t> values_;
    size_t size_;

public:
    categorical_variable_array(
        protoboard<FieldT>& pb,
        size_t size, 
        const std::string& annotation_prefix=""):
    gadget<FieldT>(pb, annotation_prefix), size_(size) 
    { 
        for(size_t i=0; i < size_; ++i)
            ivVec.emplace_back(categorical_variable<FieldT>(pb, annotation_prefix));
    };
    
    void allocate() 
    {
        for(size_t i=0; i < ivVec.size(); ++i) 
            ivVec[i].allocate();
    };

    void set_values(const std::vector<uint64_t>& values) 
    {
        this->values_ = values;
        this->values_.resize(size_, 0);
        for(size_t i=0; i < size_; ++i)
            ivVec[i].set_value(values_[i]);
    };

    void generate_r1cs_constraints(bool enforce_boolean=true);
    void generate_r1cs_witness();
};


/* Class for signed float varialbes */
template<typename FieldT>
class signed_variable : public gadget<FieldT> {
private:
    std::shared_ptr<packing_gadget<FieldT> > pack_gadget;

public:
    pb_variable<FieldT> iv; // value
    pb_variable<FieldT> ik; // precision bits (power of two)
    pb_variable<FieldT> is; // sign
    pb_variable_array<FieldT> bits; 
    uint64_t value_;
    uint64_t sign_;
    uint64_t k_; // precision bits
public:
    signed_variable(
        protoboard<FieldT>& pb,
        const std::string& annotation_prefix=""): 
    gadget<FieldT>(pb, annotation_prefix) { };
    

    void allocate() 
    {
        iv.allocate(this->pb, this->annotation_prefix);
        is.allocate(this->pb, this->annotation_prefix);
        ik.allocate(this->pb, this->annotation_prefix);
        bits.allocate(this->pb, float_bit_width, this->annotation_prefix);
        pack_gadget.reset(new packing_gadget<FieldT>(this->pb, bits, iv, this->annotation_prefix));
    };

    void set_value(double f) 
    {
        auto tup = safe_double<float_precision_safe>(f); // (s,v,k)
        this->sign_ = std::get<0>(tup);
        this->value_ = std::get<1>(tup);
        this->k_ = std::get<2>(tup);
    };

    void set_value(std::tuple<uint64_t, uint64_t, uint64_t> tup)
    {
        this->sign_ = std::get<0>(tup);
        this->value_ = std::get<1>(tup);
        this->k_ = std::get<2>(tup);
    };

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
 
};

/* Class for array of signed variables */
template<typename FieldT>
class signed_variable_array : public gadget<FieldT> {
public:
    std::vector<signed_variable<FieldT> > ivVec;
    std::vector<double> values_;
    size_t size_;

public:
    signed_variable_array(
        protoboard<FieldT>& pb,
        size_t size,
        const std::string& annotation_prefix=""): 
    gadget<FieldT>(pb, annotation_prefix), size_(size) 
    {
        for(size_t i=0; i < size_; ++i)
            ivVec.emplace_back(signed_variable<FieldT>(pb, annotation_prefix));
    };

    void allocate() 
    {
        for(size_t i=0; i < ivVec.size(); ++i)
            ivVec[i].allocate();
    };

    void set_values(const std::vector<double>& values) {
        this->values_ = values;
        this->values_.resize(size_, 0.0);
        for(size_t i=0; i < size_; ++i)
            ivVec[i].set_value(values_[i]);
    };

    void set_values(const std::vector<safe_tuple_t>& values) {
        assert(values.size() == this->size_);
        for(size_t i=0; i < values.size(); ++i)
            ivVec[i].set_value(values[i]);
    };
    

    void generate_r1cs_constraints(bool enforce_boolean=true);
    void generate_r1cs_witness();
};
        
 

} // namespace 

#include <zkdoc/src/trusted_ai_gadgets.cpp>

#endif

