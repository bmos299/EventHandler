#ifndef __TRUSTED_AI_VECTORS__
#define __TRUSTED_AI_VECTORS__

#include <zkdoc/src/trusted_ai_gadgets.hpp>

using namespace libsnark;

namespace TrustedAI {


/**
 * List of vector gadgets described in this file
 * In the gadgets below, N denote the maximum possible
 * size of the vectors. The vector class contains size as
 * a variable to denote the actual size of the vector.
 */
template<typename FieldT, size_t N>
class integer_vector;

template<typename FieldT, size_t N>
class categorical_vector;

template<typename FieldT, size_t N>
class signed_vector;

/* sum up entries of vector gadgets */
template<typename FieldT, size_t N>
class integer_vector_sum;

template<typename FieldT, size_t N>
class signed_vector_sum;

/* dot product gadgets */
template<typename FieldT, size_t N>
class dot_product_integer;

template<typename FieldT, size_t N>
class dot_product_signed;

template<typename FieldT, size_t N>
class dot_product_integer_signed;


// this gadget helps in sepcifying size
// of the column. Essentially given a variable
// size_, specifying the size of column, it 
// creates a selector vector selector, such that
// selector[i] = (i < size)
template<typename FieldT, size_t N>
class size_selector_gadget : public gadget<FieldT> {
public:
    // variable to denote size 
    pb_variable<FieldT> vsize_;
    pb_variable_array<FieldT> selector_;
    // auxiliary columns to link vsize_ --> reverse_ --> selector_
    // see the generate_r1cs_constraints() for more details of 
    // constraints.
    pb_variable_array<FieldT> reverse_;
    pb_variable_array<FieldT> z_;
    pb_variable_array<FieldT> inverse_;
    pb_variable_array<FieldT> w_;

public:
    size_selector_gadget(
        protoboard<FieldT>& pb,
        const pb_variable<FieldT>& vsize,
        const pb_variable_array<FieldT>& selector,
        const std::string& annotation_prefix = "") : 
            gadget<FieldT>(pb, annotation_prefix), 
            vsize_(vsize), selector_(selector) {};

    std::vector<pb_variable<FieldT> > get_pb_vals() { 
        std::vector<pb_variable<FieldT> > pb_vals;
        std::copy(selector_.begin(), selector_.end(), back_inserter(pb_vals));
        return pb_vals;
    };

    // allocates the auxiliary witness
    void allocate();
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};


template<typename FieldT, size_t N>
class integer_vector : public gadget<FieldT> {
public:
    std::vector<uint64_t> values_;
    // integer variables array for vector contents
    std::shared_ptr<integer_variable_array<FieldT> > contents_;
    // pointer to selector gadget
    std::shared_ptr<size_selector_gadget<FieldT, N> > size_selector_;
    // variable denoting the size of the vector
    pb_variable<FieldT> vsize_;
    // store the size for generating witness
    size_t size_;

public:
    integer_vector(
        protoboard<FieldT>& pb,
        const size_t size,
        const std::shared_ptr<size_selector_gadget<FieldT, N> > size_selector,
        const std::string& annotation_prefix="");

    std::vector<pb_variable<FieldT> > get_pb_vals();

    void set_values(const std::vector<uint64_t>& values);
    void allocate();
    void generate_r1cs_constraints(bool enforce_bound=true);
    void generate_r1cs_witness();
};


template<typename FieldT, size_t N>
class categorical_vector : public gadget<FieldT> {
public:
    std::shared_ptr<categorical_variable_array<FieldT> > contents_;
    std::shared_ptr<size_selector_gadget<FieldT, N> > size_selector_;
    pb_variable<FieldT> vsize_;
    size_t size_;

public:
    categorical_vector(
        protoboard<FieldT>& pb,
        const size_t size,
        const std::shared_ptr<size_selector_gadget<FieldT, N> > size_selector,
        const std::string& annotation_prefix="");

    std::vector<pb_variable<FieldT> > get_pb_vals();
    
    void set_values(const std::vector<uint64_t>& values);
    void allocate();
    void generate_r1cs_constraints(bool enforce_bound=true);
    void generate_r1cs_witness();
};


template<typename FieldT, size_t N>
class signed_vector : public gadget<FieldT> {
public:
    std::shared_ptr<signed_variable_array<FieldT> > contents_;
    pb_variable<FieldT> vsize_;
    std::shared_ptr<size_selector_gadget<FieldT, N> > size_selector_;
    size_t size_;

public:
    signed_vector(
        protoboard<FieldT>& pb,
        const size_t size,
        const std::shared_ptr<size_selector_gadget<FieldT, N> > size_selector,
        const std::string& annotation_prefix="");

    std::vector<pb_variable<FieldT> > get_pb_vals();
    std::vector<pb_variable<FieldT> > get_pb_vals_prec();
    std::vector<pb_variable<FieldT> > get_pb_vals_signs();

    void set_values(const std::vector<double>& values);
    void set_values(const std::vector<safe_tuple_t>& values);
    void allocate();
    void generate_r1cs_constraints(bool enforce_bound=true);
    void generate_r1cs_witness();
};

/* scalar combination gadgets */
template<typename FieldT, size_t N>
class integer_vector_sum : public gadget<FieldT> {
public:
    std::vector<FieldT> coefficients_;
    std::shared_ptr<integer_vector<FieldT, N> > vector_;
    std::shared_ptr<integer_variable<FieldT> > result_;
    // auxiliary variables
    pb_variable_array<FieldT> terms_;

public:
    // this gadget asserts that <coefficients, vector> = result
    integer_vector_sum(
        protoboard<FieldT>& pb,
        const std::vector<FieldT>& coefficients,
        const std::shared_ptr<integer_vector<FieldT, N> >  vector,
        const std::shared_ptr<integer_variable<FieldT> > result,
        const std::string& annotation_prefix=""):
        gadget<FieldT>(pb, annotation_prefix),
        coefficients_(coefficients),
        vector_(vector), 
        result_(result)
        { coefficients_.resize(N, FieldT::zero()); };

    void allocate();
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename FieldT, size_t N>
class signed_vector_sum : public gadget<FieldT> {
public:
    std::vector<FieldT> coefficients_;
    std::shared_ptr<signed_vector<FieldT, N> > vector_;
    std::shared_ptr<signed_variable<FieldT> > result_;
    // auxiliary variables
    pb_variable_array<FieldT> terms_, termsP_;

public:
    // this gadget asserts that <coefficients, vector> = result
    signed_vector_sum(
        protoboard<FieldT>& pb,
        const std::vector<FieldT>& coefficients,
        const std::shared_ptr<signed_vector<FieldT, N> > vector,
        const std::shared_ptr<signed_variable<FieldT> > result,
        const std::string& annotation_prefix=""):
        gadget<FieldT>(pb, annotation_prefix),
        coefficients_(coefficients),
        vector_(vector),
        result_(result)
        { coefficients_.resize(N, FieldT::zero()); };

    void allocate();
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};


template<typename FieldT, size_t N>
class dot_product_integer : public gadget<FieldT> {
public:
    std::shared_ptr<integer_vector<FieldT, N> > vleft_;
    std::shared_ptr<integer_vector<FieldT, N> > vright_;
    std::shared_ptr<integer_variable<FieldT> > result_;
    // auxiliary variables
    std::shared_ptr<integer_vector<FieldT, N> > product_;
    // auxiliary gadgets
    std::shared_ptr<integer_vector_sum<FieldT, N>> sum_product_;
    
public:
    // this gadget asserts that <velft, vright> = result
    dot_product_integer(
        protoboard<FieldT>& pb,
        const std::shared_ptr<integer_vector<FieldT, N> > vleft,
        const std::shared_ptr<integer_vector<FieldT, N> > vright,
        const std::shared_ptr<integer_variable<FieldT> > result,
        const std::string& annotation_prefix="");

    void allocate();
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename FieldT, size_t N>
class dot_product_signed : public gadget<FieldT> {
public:
    std::shared_ptr<signed_vector<FieldT, N> > vleft_;
    std::shared_ptr<signed_vector<FieldT, N> > vright_;
    std::shared_ptr<signed_variable<FieldT> > result_;
    // auxiliary variables
    std::shared_ptr<signed_vector<FieldT, N> > product_;
    std::shared_ptr<signed_vector_sum<FieldT, N> > sum_product_;

public:
    // this gadget asserts that <vleft, vright> = result
    dot_product_signed(
        protoboard<FieldT>& pb,
        const std::shared_ptr<signed_vector<FieldT, N> > vleft,
        const std::shared_ptr<signed_vector<FieldT, N> > vright,
        const std::shared_ptr<signed_variable<FieldT> > result,
        const std::string& annotation_prefix="");

    void allocate();
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename FieldT, size_t N>
class dot_product_integer_signed : public gadget<FieldT> {
public:
    std::shared_ptr<integer_vector<FieldT, N> > vleft_;
    std::shared_ptr<signed_vector<FieldT, N> > vright_;
    std::shared_ptr<signed_variable<FieldT> > result_;
    // auxiliary variables
    std::shared_ptr<signed_vector<FieldT, N> > product_;
    std::shared_ptr<signed_vector_sum<FieldT, N> > sum_product_;
    

public:
    // this gadget asserts that <vleft, vright> = result
    dot_product_integer_signed(
        protoboard<FieldT>& pb,
        const std::shared_ptr<integer_vector<FieldT, N> > vleft,
        const std::shared_ptr<signed_vector<FieldT, N> > vright,
        const std::shared_ptr<signed_variable<FieldT> > result,
        const std::string& annotation_prefix="");

    void allocate();
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};


} // namespace

#include <zkdoc/src/trusted_ai_vectors.cpp>
#endif

