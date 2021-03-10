#ifndef __TRUSTED_AI_INTERFACE_GADGETS__
#define __TRUSTED_AI_INTERFACE_GADGETS__

using namespace libsnark;

namespace TrustedAI {
/**
 * This gadget proves the provenance of a private model
 * on private data. We describe conventions for input
 * Data: N x (C+M+1) matrix with C categorical features,
 * M integral features and 1 target feature as the last
 * column. Model is a vector of M+1 coefficients.  
 * we put the offset (c_0) as the last element of the 
 * coefficient array.
 * Statement: Hashes[0...(C+M)], mHash, R2
 * Witness: there exists data (D) and model (LM) such that
 * Hash(D) = Hashes and Hash(LM) = mHash and LM achieves 
 * Rsquare accuracy of R2, when predicting the target column
 * from feature columns(C,..C+M-1).
 */
template<typename FieldT, size_t N, size_t C, size_t M>
class model_provenance_gadget : public gadget<FieldT> {
public:
    // variables part of the statement
    pb_variable<FieldT> catColHashes_[C];
    pb_variable<FieldT> intColHashes_[M+1];
    pb_variable<FieldT> modelHash_;
    pb_variable<FieldT> R2_;
    //@todo add data size as part of public input

private:
    std::shared_ptr<data_source<FieldT, N, C, M>> data_;
    std::shared_ptr<data_source<FieldT, N, 0, 1>> target_;
    std::shared_ptr<signed_vector<FieldT, M + 1>> model_;
    std::shared_ptr<linear_regression_gadget<FieldT, N, M>> lin_reg_;
    std::shared_ptr<signed_variable<FieldT>> r2_;
    std::shared_ptr<size_selector_gadget<FieldT, M+1>> size_selector_w_;
    std::shared_ptr<mimc_hash_signed<FieldT, M+1, 1>> model_hasher_;
    pb_variable_array<FieldT> selector_w_;
    pb_variable<FieldT> dsize_, wsize_;
    size_t size_;

public:
    model_provenance_gadget(
        protoboard<FieldT>& pb,
        const size_t size,
        const std::string& annotation_prefix):
        gadget<FieldT>(pb, annotation_prefix), size_(size)
    {
        // allocate the public variables first
        for(size_t i=0; i < C; ++i)
            catColHashes_[i].allocate(this->pb, "catColHash_"+std::to_string(i));
        for(size_t i=0; i < (M+1); ++i)
            intColHashes_[i].allocate(this->pb, "intColHash_"+std::to_string(i));

        modelHash_.allocate(this->pb, "modelHash");
        R2_.allocate(this->pb, "R2");
        this->pb.set_input_sizes(C+M+3);
        
        // allocate other gadgets
        dsize_.allocate(this->pb, "dsize");
        wsize_.allocate(this->pb, "wsize");
        selector_w_.allocate(this->pb, M+1, "selector_w");
        size_selector_w_.reset(new size_selector_gadget<FieldT, M+1>(
            this->pb,
            wsize_,
            selector_w_,
            "size_selector_w"));
        size_selector_w_->allocate();
        
        model_.reset(new signed_vector<FieldT, M+1>(
            this->pb,
            M+1,
            size_selector_w_,
            "model"));
        model_->allocate();
    
        r2_.reset(new signed_variable<FieldT>(this->pb, "r2"));
        r2_->allocate();

        data_.reset(new data_source<FieldT, N, C, M>(this->pb, size_, "data"));
        data_->allocate();

        target_.reset(new data_source<FieldT, N, 0, 1>(this->pb, size_, "target"));
        target_->allocate();

        lin_reg_.reset(new linear_regression_gadget<FieldT, N, M>(
            this->pb,
            model_,
            data_->integer_features_,
            target_->integer_features_->columns_[0],
            r2_,
            "linear regression"));
        lin_reg_->allocate();

        model_hasher_.reset(new mimc_hash_signed<FieldT, M+1, 1>(
            this->pb,
            model_,
            modelHash_,
            "model_hasher"));
        model_hasher_->allocate();


    };

    void generate_r1cs_constraints()
    {

        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(this->dsize_, 1, data_->integer_features_->vsize_), "dsize=data.size");

        size_selector_w_->generate_r1cs_constraints();
        model_->generate_r1cs_constraints();
        r2_->generate_r1cs_constraints();
        data_->generate_r1cs_constraints();
        target_->generate_r1cs_constraints();
        lin_reg_->generate_r1cs_constraints();
        model_hasher_->generate_r1cs_constraints();
        
        // match the hashes
        for(size_t i=0; i < C; ++i)
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    catColHashes_[i],
                    1,
                    data_->categorical_col_hashes_[i]), "cat-hash-match");
        for(size_t i=0; i < M; ++i)
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    intColHashes_[i],
                    1,
                    data_->integer_col_hashes_[i]), "int-hash-match");
        
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                intColHashes_[M],
                1,
                target_->integer_col_hashes_[0]), "target-hash-match");

        // r2 match
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                R2_,
                1,
                r2_->iv), "R2=r2");
    };

    void generate_r1cs_witness( 
        const std::vector<std::vector<uint64_t>>& categorical_matrix,
        const std::vector<std::vector<uint64_t>>& integer_matrix,
        const std::vector<std::vector<uint64_t>>& target,
        const std::vector<double>& model_coefficients)
    {
        assert(categorical_matrix.size() == C);
        assert(integer_matrix.size() == M);
        assert(model_coefficients.size() == M+1);
        assert(target.size() == 1);
       
        this->pb.val(wsize_) = M+1;
        this->pb.val(dsize_) = size_;
        size_selector_w_->generate_r1cs_witness();
        model_->set_values(model_coefficients);
        model_->generate_r1cs_witness();
        data_->set_values(categorical_matrix, integer_matrix);
        data_->generate_r1cs_witness();
        target_->set_values(std::vector<std::vector<uint64_t>>(), target);
        target_->generate_r1cs_witness();
        lin_reg_->generate_r1cs_witness();
        model_hasher_->generate_r1cs_witness();
        r2_->generate_r1cs_witness();
 
        // copy the variables
        for(size_t i=0; i < C; ++i)
            this->pb.val(catColHashes_[i]) = this->pb.val(data_->categorical_col_hashes_[i]);
        for(size_t i=0; i < M; ++i)
            this->pb.val(intColHashes_[i]) = this->pb.val(data_->integer_col_hashes_[i]);
        this->pb.val(intColHashes_[M]) = this->pb.val(target_->integer_col_hashes_[0]);
        

        // R2
        this->pb.val(R2_) = this->pb.val(r2_->iv);

    };
    

}; // end of class definition

template<typename FieldT, size_t N, size_t C, size_t M>
class model_inference_gadget : public gadget<FieldT> {
public:
    // variables comprising the primary input
    pb_variable<FieldT> feature_matrix_[N][M];
    std::vector<pb_variable<FieldT>> scores_; 
    pb_variable<FieldT> model_hash_;
    pb_variable<FieldT> dsize_; // batch size <= N

public:
    std::shared_ptr<signed_vector<FieldT, M+1>> model_;
    std::shared_ptr<data_source_public<FieldT, N, C, M>> X_;
    std::shared_ptr<signed_vector<FieldT, N>> z_;
private:
    std::shared_ptr<linear_combination_gadget<FieldT, N, M>> lc_gadget_;
    std::shared_ptr<size_selector_gadget<FieldT, M+1>> size_selector_w_;
    std::shared_ptr<mimc_hash_signed<FieldT, M+1, 1>> model_hasher_;
    std::shared_ptr<assert_equal_gadget<FieldT, N, float_precision_safe>> eq_gadget_;

    pb_variable_array<FieldT> selector_w_;
    pb_variable<FieldT> wsize_;
    size_t size_;


public:
    model_inference_gadget(
        protoboard<FieldT>& pb,
        size_t size,
        const std::string& annotation_prefix=""):
        gadget<FieldT>(pb, annotation_prefix),
        size_(size)
    {
        // allocate the public variables first
        scores_.resize(N);
        for(size_t i=0; i < N; ++i)
            for(size_t j=0; j < M; ++j) 
               feature_matrix_[i][j].allocate(this->pb, "feature_matrix");

        for(size_t i=0; i < N; ++i)
            scores_[i].allocate(this->pb, "scores");
        
        model_hash_.allocate(this->pb, "model_hash");
        dsize_.allocate(this->pb, "dsize");
        this->pb.set_input_sizes(M*N+N+2);
        
        wsize_.allocate(this->pb, "wsize");
        selector_w_.allocate(this->pb, M+1, "selector_w");
        size_selector_w_.reset(new size_selector_gadget<FieldT, M+1>(
            this->pb,
            wsize_,
            selector_w_,
            "size_selector_w"));
        size_selector_w_->allocate();

        model_.reset(new signed_vector<FieldT, M+1>(
            this->pb,
            M+1,
            size_selector_w_,
            "model"));
        model_->allocate();

        X_.reset(new data_source_public<FieldT, N, C, M>(
            this->pb,
            size_,
            "X"));
        X_->allocate();

        z_.reset(new signed_vector<FieldT, N>(
            this->pb,
            size_,
            X_->integer_features_->size_selector_,
            "z"));
        z_->allocate();

        lc_gadget_.reset(new linear_combination_gadget<FieldT, N, M>(
            this->pb,
            X_->integer_features_,
            model_,
            z_,
            "lc_gadget"));
        lc_gadget_->allocate();

        eq_gadget_.reset(new assert_equal_gadget<FieldT, N, float_precision_safe>(
            this->pb,
            scores_,
            z_,
            "eq_gadget"));
        eq_gadget_->allocate();

        model_hasher_.reset(new mimc_hash_signed<FieldT, M+1, 1>(
            this->pb,
            model_,
            model_hash_,
            "model_hasher"));
        model_hasher_->allocate();
    };

    void generate_r1cs_constraints()
    {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(this->dsize_, 1, X_->integer_features_->vsize_), "X.size=dsize");

        // assert equality of feature_matrix with X_->integer_features_
        for(size_t i=0; i < M; ++i) {
            auto pb_vals = X_->integer_features_->columns_[i]->get_pb_vals();
            for(size_t j=0; j < N; ++j)
                this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(
                        pb_vals[j],
                        1,
                        feature_matrix_[j][i]), "X_=feature_matrix");
        }
    
        size_selector_w_->generate_r1cs_constraints();
        model_->generate_r1cs_constraints();
        X_->generate_r1cs_constraints();
        z_->generate_r1cs_constraints();
        lc_gadget_->generate_r1cs_constraints();
        eq_gadget_->generate_r1cs_constraints();
        model_hasher_->generate_r1cs_constraints();
    };

    void generate_r1cs_witness(
        const std::vector<std::vector<uint64_t>>& categorical_matrix,
        const std::vector<std::vector<uint64_t>>& integer_matrix,
        const std::vector<double>& model_coefficients)
    {
        assert(categorical_matrix.size() == C);
        assert(integer_matrix.size() == M);
        assert(model_coefficients.size() == M+1);

        this->pb.val(dsize_) = size_;
        this->pb.val(wsize_) = M+1;

        size_selector_w_->generate_r1cs_witness();
        model_->set_values(model_coefficients);
        model_->generate_r1cs_witness();
        X_->set_values(categorical_matrix, integer_matrix);
        X_->generate_r1cs_witness();

        for(size_t i=0; i < M; ++i) {
            auto pb_vals = X_->integer_features_->columns_[i]->get_pb_vals();
            for(size_t j=0; j < N; ++j) 
                this->pb.val(feature_matrix_[j][i]) = this->pb.val(pb_vals[j]);
        }
    
        lc_gadget_->generate_r1cs_witness();
        z_->generate_r1cs_witness();
        model_hasher_->generate_r1cs_witness();
        eq_gadget_->generate_r1cs_witness();
    };

};

} // namespace

#endif
