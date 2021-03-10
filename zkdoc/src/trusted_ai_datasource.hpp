#ifndef __TRUSTED_AI_DATASOURCE_HPP__
#define __TRUSTED_AI_DATASOURCE_HPP__

#include <zkdoc/src/trusted_ai_gadgets.hpp>
#include <zkdoc/src/trusted_ai_vectors.hpp>
#include <zkdoc/src/trusted_ai_benes_multirouting.hpp>
#include <zkdoc/src/trusted_ai_hash_gadget.hpp>

using namespace libsnark;
using namespace lemon;

namespace TrustedAI {

// the classes below denote a data source
// with upto N rows and M columns
// each data source should also be attached
// with a row_selector and column_selector

template<typename FieldT, size_t N, size_t M>
class data_source_integer : public gadget<FieldT> {
public:
    typedef std::shared_ptr<integer_vector<FieldT, N>> intvec_ptr_t;
    typedef std::shared_ptr<size_selector_gadget<FieldT, N>> selector_ptr_t;
    
public:
    std::vector<intvec_ptr_t> columns_;
    pb_variable<FieldT> vsize_;
    size_t size_;

public:
    data_source_integer(
        protoboard<FieldT>& pb,
        size_t size,
        const std::string& annotation_prefix);

    void allocate();
    // expects values[i] to contain the i^th column.
    void set_values(const std::vector<std::vector<uint64_t> >& values);
    void generate_r1cs_constraints();
    void generate_r1cs_witness();

public:
    selector_ptr_t size_selector_;
    pb_variable_array<FieldT> row_selector_;
    // @todo: hash gadget
};


template<typename FieldT, size_t N, size_t M>
class data_source_categorical : public gadget<FieldT> {
public:
    typedef std::shared_ptr<categorical_vector<FieldT, N>> catvec_ptr_t;
    typedef std::shared_ptr<size_selector_gadget<FieldT, N>> selector_ptr_t;
    
public:
    std::vector<catvec_ptr_t> columns_;
    pb_variable<FieldT> vsize_;
    size_t size_;

public:
    data_source_categorical(
        protoboard<FieldT>& pb,
        size_t size,
        const std::string& annotation_prefix);

    void allocate();
    // expects values[i] to contain the i^th column.
    void set_values(const std::vector<std::vector<uint64_t> >& values);
    void generate_r1cs_constraints();
    void generate_r1cs_witness();

public:
    selector_ptr_t size_selector_;
    pb_variable_array<FieldT> row_selector_;
    // @todo: hash gadget
};

template<typename FieldT, size_t N, size_t C, size_t M>
class data_source : public gadget<FieldT> {
public:
    std::shared_ptr<data_source_categorical<FieldT, N, C>> categorical_features_;
    std::shared_ptr<data_source_integer<FieldT, N, M>> integer_features_;
    size_t size_;
    std::vector<std::vector<uint64_t>> categorical_values_;
    std::vector<std::vector<uint64_t>> integer_values_;
    std::vector<std::vector<double>> numeric_values_;

public:
    // hash related members
    std::vector<pb_variable<FieldT>> categorical_col_hashes_; // (C);
    std::vector<pb_variable<FieldT>> integer_col_hashes_; // (M);
    std::vector<FieldT> cHashes_; //(C);
    std::vector<FieldT> iHashes_; // (M);

private:
    // hashers for the columns
    std::vector<std::shared_ptr<mimc_hash_categorical<FieldT, N, packing_categorical>>> cat_hashers_; //(C);
    std::vector<std::shared_ptr<mimc_hash_integer<FieldT, N, packing_integer>>> int_hashers_; //(M);

public:
    data_source(
        protoboard<FieldT>& pb,
        size_t size,
        const std::string& annotation_prefix=""): 
        gadget<FieldT>(pb, annotation_prefix) 
    {
        cat_hashers_.resize(C);
        int_hashers_.resize(M);
        categorical_col_hashes_.resize(C);
        integer_col_hashes_.resize(M);
        cHashes_.resize(C);
        iHashes_.resize(M);
        categorical_features_.reset(new data_source_categorical<FieldT, N, C>(
            this->pb,
            size,
            this->annotation_prefix));
        integer_features_.reset(new data_source_integer<FieldT, N, M>(
            this->pb,
            size,
            this->annotation_prefix));
    };

    void allocate()
    {
        categorical_features_->allocate();
        integer_features_->allocate();
        for(size_t i=0; i < C; ++i) categorical_col_hashes_[i].allocate(this->pb, "cat_hashes");
        for(size_t i=0; i < M; ++i) integer_col_hashes_[i].allocate(this->pb, "int_hashes");
        // set up the hashers
        for(size_t i=0; i < C; ++i) {
            cat_hashers_[i].reset(new mimc_hash_categorical<FieldT, N, packing_categorical>(
                this->pb,
                categorical_features_->columns_[i],
                categorical_col_hashes_[i],
                "cat_hasher"));
            cat_hashers_[i]->allocate();
        }

        for(size_t i=0; i < M; ++i) {
            int_hashers_[i].reset(new mimc_hash_integer<FieldT, N, packing_integer>(
                this->pb,
                integer_features_->columns_[i],
                integer_col_hashes_[i],
                "int_hasher"));
            int_hashers_[i]->allocate();
        }
    };

    void set_values(
        const std::vector<std::vector<uint64_t>>& categorical_values,
        const std::vector<std::vector<uint64_t>>& integer_values) 
    {
        categorical_values_ = categorical_values;
        integer_values_ = integer_values;
        categorical_features_->set_values(categorical_values_);
        integer_features_->set_values(integer_values_);
    };

    void generate_r1cs_constraints()
    {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                categorical_features_->vsize_,
                1,
                integer_features_->vsize_),
                "size-match");
        categorical_features_->generate_r1cs_constraints();
        integer_features_->generate_r1cs_constraints();
        for(auto hasher: cat_hashers_) hasher->generate_r1cs_constraints();
        for(auto hasher: int_hashers_) hasher->generate_r1cs_constraints();
    };

    void generate_r1cs_witness()
    {
        categorical_features_->generate_r1cs_witness();
        integer_features_->generate_r1cs_witness();
        for(auto hasher: cat_hashers_) hasher->generate_r1cs_witness();
        for(auto hasher: int_hashers_) hasher->generate_r1cs_witness();
        for(size_t i=0; i < C; ++i)
            cHashes_[i] = this->pb.val(categorical_col_hashes_[i]);
        for(size_t i=0; i < M; ++i)
            iHashes_[i] = this->pb.val(integer_col_hashes_[i]);
    };

};


/**
 * This class represents a public data source with
 * C categorical columns and M integer columns. Here
 * N denotes the maximum possible rows in the data-source
 * This data-source does not implement hashing constraints
 */
template<typename FieldT, size_t N, size_t C, size_t M>
class data_source_public : public gadget<FieldT> {
public:
    std::shared_ptr<data_source_categorical<FieldT, N, C>> categorical_features_;
    std::shared_ptr<data_source_integer<FieldT, N, M>> integer_features_;
    size_t size_;
    std::vector<std::vector<uint64_t>> categorical_values_;
    std::vector<std::vector<uint64_t>> integer_values_;
    std::vector<std::vector<double>> numeric_values_;

public:
    data_source_public(
        protoboard<FieldT>& pb,
        size_t size,
        const std::string& annotation_prefix=""): 
        gadget<FieldT>(pb, annotation_prefix) 
    {
        categorical_features_.reset(new data_source_categorical<FieldT, N, C>(
            this->pb,
            size,
            this->annotation_prefix));
        integer_features_.reset(new data_source_integer<FieldT, N, M>(
            this->pb,
            size,
            this->annotation_prefix));
    };

    void allocate()
    {
        categorical_features_->allocate();
        integer_features_->allocate();
    };

    void set_values(
        const std::vector<std::vector<uint64_t>>& categorical_values,
        const std::vector<std::vector<uint64_t>>& integer_values) 
    {
        categorical_values_ = categorical_values;
        integer_values_ = integer_values;
        categorical_features_->set_values(categorical_values_);
        integer_features_->set_values(integer_values_);
    };

    void generate_r1cs_constraints()
    {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                categorical_features_->vsize_,
                1,
                integer_features_->vsize_),
                "size-match");
        categorical_features_->generate_r1cs_constraints();
        integer_features_->generate_r1cs_constraints();
    };

    void generate_r1cs_witness()
    {
        categorical_features_->generate_r1cs_witness();
        integer_features_->generate_r1cs_witness();
    };

};

    
} // end of namespace

#include <zkdoc/src/trusted_ai_datasource.cpp>

#endif
