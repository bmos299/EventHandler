#ifndef __TRUSTED_AI_LINEAR_REGRESSION_HPP__
#define __TRUSTED_AI_LINEAR_REGRESSION_HPP__

#include <zkdoc/src/trusted_ai_datasource.hpp>

using namespace libsnark;

namespace TrustedAI {


template<typename FieldT, size_t N, size_t prec>
class mean_computation_gadget : public gadget<FieldT> {
public:
    std::shared_ptr<integer_vector<FieldT, N>> ivec_;
    std::shared_ptr<signed_variable<FieldT>> mean_;

private:
    std::shared_ptr<integer_vector_sum<FieldT, N>> sum_gadget_;
    std::shared_ptr<integer_variable<FieldT>> sum_;
    std::shared_ptr<comparison_gadget<FieldT>> comparison1_;
    std::shared_ptr<comparison_gadget<FieldT>> comparison2_;
    pb_variable<FieldT> prod1_, prod2_, prod3_;
    pb_variable<FieldT> less1_, less2_;
    pb_variable<FieldT> less_or_equal1_, less_or_equal2_;


public:
    mean_computation_gadget(
        protoboard<FieldT>& pb,
        const std::shared_ptr<integer_vector<FieldT, N>> ivec,
        const std::shared_ptr<signed_variable<FieldT>> mean,
        const std::string& annotation_prefix=""): 
        gadget<FieldT>(pb, annotation_prefix),
        ivec_(ivec),
        mean_(mean)
    {
        std::vector<FieldT> coefficients(N, FieldT::one());
        sum_.reset(new integer_variable<FieldT>(this->pb, this->annotation_prefix));
        
        sum_gadget_.reset(new integer_vector_sum<FieldT, N>(
            this->pb,
            coefficients,
            this->ivec_,
            this->sum_,
            this->annotation_prefix));

        
    };

    void allocate();

    void generate_r1cs_constraints();

    void generate_r1cs_witness();
 

}; // gadget definition


// gadget to compute z = [X | 1]w for matrix X and vector w
template<typename FieldT, size_t N, size_t M>
class linear_combination_gadget : public gadget<FieldT> {
    typedef std::shared_ptr<dot_product_integer_signed<FieldT, M+1>> dot_product_t;
public:
    std::shared_ptr<data_source_integer<FieldT, N, M>> X_;
    std::shared_ptr<signed_vector<FieldT, M+1>> w_;
    std::shared_ptr<signed_vector<FieldT, N>> z_;

private:
    std::shared_ptr<data_source_integer<FieldT, M+1, N>> tX_; // transpose
    std::vector<dot_product_t> dot_product_gadgets_; // dot product gadgets
    std::vector<std::shared_ptr<signed_variable<FieldT>>> copy_z_;
     
public:
    linear_combination_gadget(
        protoboard<FieldT>& pb,
        std::shared_ptr<data_source_integer<FieldT, N, M>> X,
        std::shared_ptr<signed_vector<FieldT, M+1>> w,
        std::shared_ptr<signed_vector<FieldT, N>> z,
        const std::string& annotation_prefix) : 
        gadget<FieldT>(pb, annotation_prefix),
        X_(X), w_(w), z_(z) {};

    void allocate();
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

// converts between a value expressed with 
// precision B1 to one with precision B2
// we assume B1 > B2. We downgrade precision
// For e.g.: adaptor<1000,100>(5.634) = 5.63
// 5634, 1000 ==> 563, 100
template<typename FieldT, size_t B1, size_t B2>
class adaptor_gadget : public gadget<FieldT> {
public:
    std::shared_ptr<signed_variable<FieldT>> v1_, v2_;
    std::shared_ptr<comparison_gadget<FieldT>> comparison1_, comparison2_;
    pb_variable<FieldT> less1_, less2_, less_or_eq1_, less_or_eq2_;
    pb_variable<FieldT> prod1_, prod2_, prod3_;

public:
    adaptor_gadget(
        protoboard<FieldT>& pb,
        std::shared_ptr<signed_variable<FieldT>> v1,
        std::shared_ptr<signed_variable<FieldT>> v2,
        const std::string& annotation_prefix):
        gadget<FieldT>(pb, annotation_prefix),
        v1_(v1),
        v2_(v2) {};

    void allocate();
    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename FieldT, size_t prec>
class floor_gadget : public gadget<FieldT> {
public:
    pb_variable<FieldT> numer_, denom_;
    pb_variable<FieldT> prod1_, prod2_, prod3_;
    std::shared_ptr<signed_variable<FieldT>> result_;
    // quotient/prec <= numer_/denom_ < (quotient+1)/prec
    // quotient * denom_ <= numer_ * prec < quotient * denom + denom

private:
    std::shared_ptr<comparison_gadget<FieldT>> compare1_, compare2_;
    pb_variable<FieldT> less1_, less_or_eq1_, less2_, less_or_eq2_;

public:
    floor_gadget(
        protoboard<FieldT>& pb,
        const pb_variable<FieldT> numer,
        const pb_variable<FieldT> denom,
        std::shared_ptr<signed_variable<FieldT>> result,
        const std::string& annotation_prefix) : gadget<FieldT>(pb, annotation_prefix),
        numer_(numer), denom_(denom), result_(result)
    {

    };

    void allocate()
    {
        prod1_.allocate(this->pb, "prod1");
        prod2_.allocate(this->pb, "prod2");
        prod3_.allocate(this->pb, "prod3");
        less1_.allocate(this->pb, "less1");
        less_or_eq1_.allocate(this->pb, "less_or_eq1");
        less_or_eq2_.allocate(this->pb, "less_or_eq2");
        compare1_.reset(new comparison_gadget<FieldT>(
            this->pb,
            128,
            prod1_,
            prod2_,
            less1_,
            less_or_eq1_,
            "compare1_float_gadget"));
        compare2_.reset(new comparison_gadget<FieldT>(
            this->pb,
            128,
            prod2_,
            prod3_,
            less2_,
            less_or_eq2_,
            "compare2_float_gadget"));
    };

    void generate_r1cs_constraints() 
    {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(result_->iv, denom_, prod1_), "prod1=result->iv * denom");
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(prec, numer_, prod2_), "prod2=prec * numer");
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(prod1_ + denom_, 1, prod3_), "prod3 = prod1 + denom");
        
        compare1_->generate_r1cs_constraints();
        compare2_->generate_r1cs_constraints();
        
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(less_or_eq1_, 1, 1), "less_or_eq1 = 1");
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(less2_, 1, 1), "less2 = 1");
    };

    void generate_r1cs_witness()
    {
        uint64_t val = (double(this->pb.val(numer_).as_ulong()) * prec)/this->pb.val(denom_).as_ulong();
        result_->set_value({0, val, prec});
        
        this->pb.val(prod1_) = val * this->pb.val(denom_).as_ulong();
        this->pb.val(prod2_) = prec * this->pb.val(numer_).as_ulong();
        this->pb.val(prod3_) = this->pb.val(prod1_) + this->pb.val(denom_);
        
        compare1_->generate_r1cs_witness();
        compare2_->generate_r1cs_witness();
    };

};
    
// asserts a vector of variable is equal to 
// a signed vector. Note only the first "size"
// elements need to be equal.
template<typename FieldT, size_t N, size_t precision>
class assert_equal_gadget : public gadget<FieldT> {
public:
    std::shared_ptr<signed_vector<FieldT, N>> svector_;
    std::vector<pb_variable<FieldT>> variables_;
private:
    // intermediate variables for unsigned ans signed products
    std::vector<pb_variable<FieldT>> terms_, termsS_;
public:
    assert_equal_gadget(
        protoboard<FieldT>& pb,
        const std::vector<pb_variable<FieldT>>& variables,
        const std::shared_ptr<signed_vector<FieldT, N>> svector,
        const std::string& annotation_prefix):
        gadget<FieldT>(pb, annotation_prefix),
        svector_(svector),
        variables_(variables) {};

    void allocate() 
    {
        terms_.resize(N);
        termsS_.resize(N);
        for(size_t i=0; i < N; ++i) {
            terms_[i].allocate(this->pb, "terms_"+std::to_string(i));
            termsS_[i].allocate(this->pb, "termsS_"+std::to_string(i));
        }
    };

    void generate_r1cs_constraints()
    {
        // we want: variables[i] = svector_[i]->iv for i <= size
        // svector[i]->ik = precision for all i
        // compute terms_[i] = (1-2s[i]).S[i].svector[i]->iv
        // assert terms_[i]=variables[i] for all i
        auto pb_vals = svector_->get_pb_vals();
        auto pb_signs = svector_->get_pb_vals_signs();
        auto pb_prec = svector_->get_pb_vals_prec();
        auto selector_vals = svector_->size_selector_->get_pb_vals();

        for(size_t i=0; i < N; ++i) {
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    selector_vals[i],
                    pb_vals[i],
                    terms_[i]), "terms=selector*pb_vals");
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    1 - 2 * pb_signs[i],
                    terms_[i],
                    termsS_[i]), "termsS=(1-2s).terms");
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    variables_[i],
                    selector_vals[i],
                    termsS_[i]), "variables=termsS");
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    pb_prec[i],
                    1,
                    precision), "ensure-precision");
        }

    };

    void generate_r1cs_witness()
    { 
        auto pb_vals = svector_->get_pb_vals();
        auto pb_signs = svector_->get_pb_vals_signs();
        auto pb_prec = svector_->get_pb_vals_prec();
        auto selector_vals = svector_->size_selector_->get_pb_vals();
       
        for(size_t i=0; i < N; ++i) {
            this->pb.val(terms_[i]) = this->pb.val(selector_vals[i]) * this->pb.val(pb_vals[i]);
            this->pb.val(termsS_[i]) = (FieldT::one() - FieldT(2)*this->pb.val(pb_signs[i])) * this->pb.val(terms_[i]);
            this->pb.val(variables_[i]) = this->pb.val(termsS_[i]);
        }

    };

};

template<typename FieldT, size_t N, size_t M>
class linear_regression_gadget : public gadget<FieldT> {

public:
    std::shared_ptr<signed_vector<FieldT, M+1>> W_;
    std::shared_ptr<data_source_integer<FieldT, N, M>> X_;
    std::shared_ptr<integer_vector<FieldT, N>> Y_;
    std::shared_ptr<signed_variable<FieldT>> R2_;

private:
    // auxiliary inputs
    std::shared_ptr<signed_variable<FieldT>> SST_, SSR_, y_;
    std::shared_ptr<integer_variable<FieldT>> sum_Y_, norm_Y_;
    std::shared_ptr<signed_variable<FieldT>> norm_z_, prod_YZ_;
    std::shared_ptr<signed_variable<FieldT>> square_y_, Yy_;
    std::shared_ptr<signed_vector<FieldT, N>> z_; // z = XW
    pb_variable<FieldT> t1_; // size * square_y
    pb_variable<FieldT> t2_; // sign multiplied value of prod_YZ_
    pb_variable<FieldT> R2Num_;

    // subgadgets
    std::shared_ptr<integer_vector_sum<FieldT, N>> sum_Y_gadget_; // <1,Y>
    std::shared_ptr<dot_product_integer<FieldT,N>> norm_Y_gadget_; // <Y,Y>
    std::shared_ptr<dot_product_signed<FieldT, N>> norm_z_gadget_; // <z,z>
    std::shared_ptr<dot_product_integer_signed<FieldT, N>> prod_YZ_gadget_; // <Y,Z>
    std::shared_ptr<mean_computation_gadget<FieldT, N, float_precision_safe>> mean_Y_gadget_; // y
    std::shared_ptr<linear_combination_gadget<FieldT, N, M>> lc_gadget_; // z = XW
    std::shared_ptr<floor_gadget<FieldT, float_precision_safe>> computeR2_;
    //std::shared_ptr<adaptor_gadget<FieldT, float_precision, float_precision_safe>> adapt_y_;
    
public:
    linear_regression_gadget<FieldT, N, M>(
        protoboard<FieldT>& pb,
        const std::shared_ptr<signed_vector<FieldT, M+1>> W, // wieghts
        const std::shared_ptr<data_source_integer<FieldT, N, M>> X, // data
        const std::shared_ptr<integer_vector<FieldT, N>> Y, // target column
        const std::shared_ptr<signed_variable<FieldT>> R2, // R^2 metric
        const std::string& annotation_prefix):
        gadget<FieldT>(pb, annotation_prefix),
        W_(W), X_(X), Y_(Y), R2_(R2) {};

    void allocate();
    void generate_r1cs_constraints();
    void generate_r1cs_witness();

}; // end of gadget



}  // end of namespace
#include <zkdoc/src/trusted_ai_linear_regression.cpp>

#endif
