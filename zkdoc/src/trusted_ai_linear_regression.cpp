using namespace libsnark;

namespace TrustedAI {

template<typename FieldT, size_t N, size_t prec>
void mean_computation_gadget<FieldT, N, prec>::allocate()
{  
    sum_->allocate();
    sum_gadget_->allocate();
    prod1_.allocate(this->pb, this->annotation_prefix);
    prod2_.allocate(this->pb, this->annotation_prefix);
    prod3_.allocate(this->pb, this->annotation_prefix);
    less1_.allocate(this->pb, this->annotation_prefix);
    less_or_equal1_.allocate(this->pb, this->annotation_prefix);
    less2_.allocate(this->pb, this->annotation_prefix);
    less_or_equal2_.allocate(this->pb, this->annotation_prefix);

    comparison1_.reset(new comparison_gadget<FieldT>(
                this->pb,
                128,
                prod1_, // mean->iv * size
                prod2_, // prec * sum->iv
                less1_,
                less_or_equal1_,
                "compare_lower_bound"));

    comparison2_.reset(new comparison_gadget<FieldT>(
                this->pb,
                128,
                prod2_, // prec * sum->iv
                prod3_, // (mean->iv + 1)*size
                less2_,
                less_or_equal2_,
                "compare_upper_bound"));
}

template<typename FieldT, size_t N, size_t prec>
void mean_computation_gadget<FieldT, N, prec>::generate_r1cs_constraints()
{
    // we must have: 
    // sum/ivec_size = f 
    // float_precision * sum >= mean->iv * ivec->size
    // float_precision * sum < (mean->iv + 1) * ivec->size

    // assert positiveness of mean
    this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(mean_->is, 1, 0),
            this->annotation_prefix);
    this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(mean_->iv, ivec_->vsize_, prod1_),
            "prod1 = mean->iv * size");
    this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                prec * sum_->iv,
                1,
                prod2_), "prod2 = sum->iv * size");
    this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                prod1_ + ivec_->vsize_,            
                1,
                prod3_), "prod3_ = prod1_ + size");
    this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                mean_->ik,
                1,
                prec), "mean_->ik=prec");


    sum_->generate_r1cs_constraints();
    sum_gadget_->generate_r1cs_constraints();
    comparison1_->generate_r1cs_constraints();
    comparison2_->generate_r1cs_constraints();
}

template<typename FieldT, size_t N, size_t prec>
void mean_computation_gadget<FieldT, N, prec>::generate_r1cs_witness()
{
    sum_gadget_->generate_r1cs_witness();
    sum_->generate_r1cs_witness();
    uint64_t intsum = this->pb.val(sum_->iv).as_ulong();
    uint64_t data_size = this->pb.val(ivec_->vsize_).as_ulong();
    uint64_t val = (intsum * prec)/data_size;

    mean_->set_value({0, val, prec});
    mean_->generate_r1cs_witness();

    this->pb.val(prod1_) = this->pb.val(mean_->iv) * this->pb.val(ivec_->vsize_);
    this->pb.val(prod2_) = this->pb.val(sum_->iv).as_ulong() * prec;
    this->pb.val(prod3_) = this->pb.val(prod1_) + this->pb.val(ivec_->vsize_);
    comparison1_->generate_r1cs_witness();
    comparison2_->generate_r1cs_witness();

}

template<typename FieldT, size_t N, size_t M>
void linear_combination_gadget<FieldT, N, M>::allocate()
{
    tX_.reset(new data_source_integer<FieldT, M+1, N>(this->pb, M+1, this->annotation_prefix));
    tX_->allocate();

    copy_z_.resize(N);

    for(size_t i=0; i < N; ++i) {
        copy_z_[i].reset(new signed_variable<FieldT>(this->pb, "copy_z"));
        copy_z_[i]->allocate();
    }

    dot_product_gadgets_.resize(N);
    // dot products: z[i] = < tX_[i], w_no_constant_ >
    for(size_t i=0; i < N; ++i) {
        dot_product_gadgets_[i].reset(
            new dot_product_integer_signed<FieldT, M+1>(
                this->pb,
                tX_->columns_[i],
                w_,
                copy_z_[i],
                "dot_product_constraint"));
        dot_product_gadgets_[i]->allocate();
    }
}


template<typename FieldT, size_t N, size_t M>
void linear_combination_gadget<FieldT, N, M>::generate_r1cs_constraints()
{
    // ensure tX_ is transpose of X_
    std::vector<std::vector<pb_variable<FieldT>>> pb_vars_X;
    for(size_t i=0; i < M; ++i) 
        pb_vars_X.emplace_back(X_->columns_[i]->get_pb_vals());

    std::vector<std::vector<pb_variable<FieldT>>> pb_vars_tX;
    for(size_t i=0; i < N; ++i)
        pb_vars_tX.emplace_back(tX_->columns_[i]->get_pb_vals());

    for(size_t i=0; i < M; ++i) {
        for(size_t j=0; j < N; ++j) {
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    pb_vars_X[i][j],
                    1,
                    pb_vars_tX[j][i]),
                    "transposeconstraints");
        }
    }

    for(size_t i=0; i < N; ++i)
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                pb_vars_tX[i][M],
                1,
                1), "tX[][M]=1");
    
    for(size_t i=0; i < N; ++i)
        dot_product_gadgets_[i]->generate_r1cs_constraints();

    // size of z = size of X_
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(
            X_->vsize_,
            1,
            z_->vsize_), "X_size=z_size");
    
    // copy_z = z
    std::vector<pb_variable<FieldT>> z_pb_vars = z_->get_pb_vals();
    std::vector<pb_variable<FieldT>> z_pb_signs = z_->get_pb_vals_signs();
    for(size_t i=0; i < N; ++i) {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                z_pb_vars[i],
                1,
                copy_z_[i]->iv), "copy_z=z (iv)");

        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                z_pb_signs[i],
                1,
                copy_z_[i]->is), "copy_z=z (is)");
            
    }
    
} 

template<typename FieldT, size_t N, size_t M>
void linear_combination_gadget<FieldT, N, M>::generate_r1cs_witness()
{
    // assign values to tX_
    std::vector<std::vector<uint64_t>> values(N, std::vector<uint64_t>(M+1));
    for(size_t i=0; i < M; ++i) {
        auto pb_vals_X = X_->columns_[i]->get_pb_vals();
        for(size_t j=0; j < N; ++j)
            values[j][i] = this->pb.val(pb_vals_X[j]).as_ulong();
    }

    for(size_t i=0; i < N; ++i)
        values[i][M] = 1;

    tX_->set_values(values);
    tX_->generate_r1cs_witness();

    // generate witness from dot product gadgets
    for(size_t i=0; i < N; ++i)
        dot_product_gadgets_[i]->generate_r1cs_witness();

    for(size_t i=0; i < N; ++i)
        copy_z_[i]->generate_r1cs_witness();

    // assign values to z_
    std::vector<safe_tuple_t> fvec;
    for(size_t i=0; i < N; ++i) {
        uint64_t sign = this->pb.val(copy_z_[i]->is).as_ulong();
        uint64_t value = this->pb.val(copy_z_[i]->iv).as_ulong();
        uint64_t precision = this->pb.val(copy_z_[i]->ik).as_ulong();
        fvec.emplace_back(safe_tuple_t({sign, value, precision}));
    }

    z_->set_values(fvec);

}

template<typename FieldT, size_t B1, size_t B2>
void adaptor_gadget<FieldT, B1, B2>::allocate()
{
    less1_.allocate(this->pb, "adaptor_less1");
    less2_.allocate(this->pb, "adaptor_less2");
    less_or_eq1_.allocate(this->pb, "adaptor_less_or_eq1");
    less_or_eq2_.allocate(this->pb, "adaptor_less_or_eq2");
    prod1_.allocate(this->pb, "adaptor_prod1");
    prod2_.allocate(this->pb, "adaptor_prod2");
    prod3_.allocate(this->pb, "adaptor_prod3");

    comparison1_.reset(new comparison_gadget<FieldT>(
        this->pb,
        128,
        prod1_,
        prod2_,
        less1_,
        less_or_eq1_,
        "adaptor_comparison1"));

    comparison2_.reset(new comparison_gadget<FieldT>(
        this->pb,
        128,
        prod2_,
        prod3_,
        less2_,
        less_or_eq2_,
        "adaptor_comparision2"));

} 

template<typename FieldT, size_t B1, size_t B2>
void adaptor_gadget<FieldT, B1, B2>::generate_r1cs_constraints()
{
    // Constraints
    // v2/B2 <= v1/B1 < (v2 + 1)/B2
    // v2 <= v1.B2/B1 < v2 + 1
    // B1.v2 <= B2.v1 < B1.v2 + B1
    // v2 = floor(v1.B2/B1)
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(v1_->ik, 1, B1), "v1.k = B1");
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(v2_->ik, 1, B2), "v2.k = B2");
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(v1_->is, 1, v2_->is), "v1.sign=v2.sign");

    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(B1, v2_->iv, prod1_), "prod1=B1.v2");
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(B2, v1_->iv, prod2_), "prod2=B2.v1");
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(prod1_ + B1, 1, prod3_), "prod3=prod1 + B1");

    comparison1_->generate_r1cs_constraints();
    comparison2_->generate_r1cs_constraints();
    
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(less_or_eq1_, 1, FieldT::one()), "less_or_eq1=1");
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(less2_, 1, FieldT::one()), "less2=1");

}

template<typename FieldT, size_t B1, size_t B2>
void adaptor_gadget<FieldT, B1, B2>::generate_r1cs_witness()
{
    uint64_t val1 = this->pb.val(v1_->iv).as_ulong();
    uint64_t val2 = (B2*val1)/B1;
    uint64_t sign1 = this->pb.val(v1_->is).as_ulong();

    uint64_t prod1 = val2 * B1;
    uint64_t prod2 = val1 * B2;
    uint64_t prod3 = prod1 + B1;
   
    std::cout << prod1 << " " << prod2 << " " << prod3 << std::endl; 
    this->pb.val(prod1_) = prod1;
    this->pb.val(prod2_) = prod2;
    this->pb.val(prod3_) = prod3;

    comparison1_->generate_r1cs_witness();
    comparison2_->generate_r1cs_witness();

    v2_->set_value({sign1, val2, B2});
}

template<typename FieldT, size_t N, size_t M>
void linear_regression_gadget<FieldT, N, M>::allocate()
{
    SST_.reset(new signed_variable<FieldT>(this->pb, "SST"));
    SSR_.reset(new signed_variable<FieldT>(this->pb, "SSR"));
    y_.reset(new signed_variable<FieldT>(this->pb, "y"));
    sum_Y_.reset(new integer_variable<FieldT>(this->pb, "sum_Y"));
    norm_Y_.reset(new integer_variable<FieldT>(this->pb, "norm_Y"));
    norm_z_.reset(new signed_variable<FieldT>(this->pb, "norm_Z"));
    prod_YZ_.reset(new signed_variable<FieldT>(this->pb, "prod_YZ"));
    square_y_.reset(new signed_variable<FieldT>(this->pb, "square_y"));
    Yy_.reset(new signed_variable<FieldT>(this->pb, "Yy"));
    z_.reset(new signed_vector<FieldT, N>(this->pb, X_->size_, X_->size_selector_, "z"));
     
    SST_->allocate();
    SSR_->allocate();
    y_->allocate();
    sum_Y_->allocate();
    norm_Y_->allocate();
    norm_z_->allocate();
    prod_YZ_->allocate();
    square_y_->allocate();
    Yy_->allocate();
    z_->allocate();
    t1_.allocate(this->pb, "t1");
    t2_.allocate(this->pb, "t2");
    R2Num_.allocate(this->pb, "R2Num");

    std::vector<FieldT> coefficients(N, FieldT::one());
    sum_Y_gadget_.reset(new integer_vector_sum<FieldT, N>(
        this->pb,
        coefficients,
        Y_,
        sum_Y_,
        "sum_Y_gadget"));
    sum_Y_gadget_->allocate();

    norm_Y_gadget_.reset(new dot_product_integer<FieldT, N>(
        this->pb,
        Y_,
        Y_,
        norm_Y_,
        "norm_Y_gadget"));
    norm_Y_gadget_->allocate();

    norm_z_gadget_.reset(new dot_product_signed<FieldT, N>(
        this->pb,
        z_,
        z_,
        norm_z_,
        "norm_z_gadget"));
    norm_z_gadget_->allocate();

    prod_YZ_gadget_.reset(new dot_product_integer_signed<FieldT, N>(
        this->pb,
        Y_,
        z_,
        prod_YZ_,
        "prod_YZ_gadget"));
    prod_YZ_gadget_->allocate();

    mean_Y_gadget_.reset(new mean_computation_gadget<FieldT, N, float_precision_safe>(
        this->pb,
        Y_,
        y_,
        "mean_Y_gadget"));
    mean_Y_gadget_->allocate();

    lc_gadget_.reset(new linear_combination_gadget<FieldT, N, M>(
        this->pb,
        X_,
        W_,
        z_,
        "lc_gadget"));
    lc_gadget_->allocate();

    computeR2_.reset(new floor_gadget<FieldT, float_precision_safe>(
        this->pb,
        R2Num_,
        SST_->iv,
        R2_,
        "computeR2"));
    computeR2_->allocate(); 

    //adapt_y_.reset(new adaptor_gadget<FieldT, float_precision, float_precision_safe>(
    //    this->pb,
    //    y_,
    //    ay_,
    //    "adapt_y_gadget"));
    // adapt_y_->allocate();
}

template<typename FieldT, size_t N, size_t M>
void linear_regression_gadget<FieldT, N, M>::generate_r1cs_constraints()
{

    // SST = <Y,Y> - 2y<1,Y> + (size_ * y*y) (dot product_integer, integer_vector_sum)
    // z = X.W  (linear combination gadget)
    // SSR = <Y,Y> - 2<Y,z> + <z,z>  (dot_product_integer_signed, dot_product_signed)
    // t1 = size * square_y
    // square_y = ay * ay
    // SST = norm_Y + t1 - 2Yy (1)
    // SSR = normY + norm_z - 2*prod_YZ (2)
    // SSR->is == 0
    // t2 = (1 - 2*prod_YZ->is) * (prodYZ->iv)
    // SSR->iv + 2*t2->iv = norm_Y->iv + norm_z->iv
    // SST->iv + 2(Yy->iv) = normY->iv + t1
     
    /* Need to add these constraints better.
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(
            norm_Y_ - 2*Yy_ + square_y_,
            1,
            SST_), "SST=<Y,Y>-2Yy+<y,y>");
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(
            norm_Y_ - 2*prod_YZ_ + norm_z_,
            1,
            SSR_), "SSR=<Y,Y> - 2<Y,z> + <z,z>");
    */    

    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(y_->iv, y_->iv, square_y_->iv), "square_y=y.y");
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(y_->ik, y_->ik, square_y_->ik), "square_y=y.y");
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(square_y_->is, 1, 0), "square_y->is = 0");
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(X_->vsize_, square_y_->iv, t1_), "t1=size * square_y");
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(1 - 2*prod_YZ_->is, prod_YZ_->iv, t2_), "t2=prod_YZ");

    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(prod_YZ_->ik, 1, float_precision_safe), "precision_check");
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(norm_z_->ik, 1, float_precision), "precision_check");
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(SSR_->ik, 1, float_precision), "precision_check");
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(SST_->ik, 1, float_precision), "precision_check");


    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(SSR_->iv + 2*float_precision_safe*t2_, 1, float_precision * norm_Y_->iv + norm_z_->iv), "SSR");
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(SST_->iv + 2*float_precision_safe*(Yy_->iv), 1, float_precision * norm_Y_->iv + t1_), "SST");
    
    //std::cout << "[Start ] " << this->pb.num_constraints() << std::endl; 
    SST_->generate_r1cs_constraints();
    //std::cout << "[SST ] " << this->pb.num_constraints() << std::endl; 
    SSR_->generate_r1cs_constraints();
    //std::cout << "[SSR ] " << this->pb.num_constraints() << std::endl; 
    y_->generate_r1cs_constraints();
    sum_Y_->generate_r1cs_constraints();
    //std::cout << "[SumY ] " << this->pb.num_constraints() << std::endl; 
    norm_Y_->generate_r1cs_constraints();
    //std::cout << "[normY ] " << this->pb.num_constraints() << std::endl; 
    norm_z_->generate_r1cs_constraints();
    //std::cout << "[normZ ] " << this->pb.num_constraints() << std::endl; 
    prod_YZ_->generate_r1cs_constraints();
    //std::cout << "[prodYZ ] " << this->pb.num_constraints() << std::endl; 
    square_y_->generate_r1cs_constraints();
    Yy_->generate_r1cs_constraints();
    z_->generate_r1cs_constraints();
    
                
    sum_Y_gadget_->generate_r1cs_constraints();
    //std::cout << "[sumY_Gadget ] " << this->pb.num_constraints() << std::endl; 
    
    norm_Y_gadget_->generate_r1cs_constraints();
    //std::cout << "[normY_Gadget ] " << this->pb.num_constraints() << std::endl; 
    norm_z_gadget_->generate_r1cs_constraints();
    //std::cout << "[normz_Gadget ] " << this->pb.num_constraints() << std::endl; 
    prod_YZ_gadget_->generate_r1cs_constraints();
    //std::cout << "[prodYZ_Gadget ] " << this->pb.num_constraints() << std::endl; 
    mean_Y_gadget_->generate_r1cs_constraints();
    //std::cout << "[mean_Y__Gadget ] " << this->pb.num_constraints() << std::endl; 
    
    lc_gadget_->generate_r1cs_constraints();
    //std::cout << "[lc_Gadget ] " << this->pb.num_constraints() << std::endl; 
    // adapt_y_->generate_r1cs_constraints();
    computeR2_->generate_r1cs_constraints();
}
        
template<typename FieldT, size_t N, size_t M>
void linear_regression_gadget<FieldT, N, M>::generate_r1cs_witness()
{
    // first compute z_ from X_ and W_
    lc_gadget_->generate_r1cs_witness();
    z_->generate_r1cs_witness();

    sum_Y_gadget_->generate_r1cs_witness();
    sum_Y_->generate_r1cs_witness();
    
    norm_Y_gadget_->generate_r1cs_witness();
    norm_Y_->generate_r1cs_witness();

    norm_z_gadget_->generate_r1cs_witness();
    norm_z_->generate_r1cs_witness();

    prod_YZ_gadget_->generate_r1cs_witness();
    prod_YZ_->generate_r1cs_witness();

    mean_Y_gadget_->generate_r1cs_witness();
    y_->generate_r1cs_witness();

    uint64_t k_y = this->pb.val(y_->ik).as_ulong();
    uint64_t v_y = this->pb.val(y_->iv).as_ulong();
    square_y_->set_value({0, v_y * v_y, k_y * k_y});
    square_y_->generate_r1cs_witness();
    // compute sum_Y_.y and square_y
    uint64_t sumY = this->pb.val(sum_Y_->iv).as_ulong();
    Yy_->set_value({0, sumY * v_y, k_y});
    Yy_->generate_r1cs_witness();

    this->pb.val(t1_) = this->pb.val(X_->vsize_) * this->pb.val(square_y_->iv); // float_precision
    this->pb.val(t2_) = (FieldT::one() - FieldT(2)*this->pb.val(prod_YZ_->is)) *
                            this->pb.val(prod_YZ_->iv);
   
    FieldT vSST, vSSR;
    vSST = FieldT(float_precision)*this->pb.val(norm_Y_->iv) + this->pb.val(t1_) - FieldT(2*float_precision_safe) * this->pb.val(Yy_->iv);
    vSSR = FieldT(float_precision)*this->pb.val(norm_Y_->iv) + this->pb.val(norm_z_->iv) - FieldT(2*float_precision_safe)*this->pb.val(t2_);

    if (vSST.as_bigint().num_bits() > float_bit_width) {
        std::cout << "Overflow value of vSST: " << vSST << " " << vSST.as_bigint().num_bits() <<
            std::endl;
        exit(1);
    }

    if (vSSR.as_bigint().num_bits() > float_bit_width) {
        std::cout << "Overflow value of vSSR: " << vSSR << " " << vSSR.as_bigint().num_bits() <<
            std::endl;
        exit(1);
    }

    SST_->set_value({0, vSST.as_ulong(), float_precision});
    SSR_->set_value({0, vSSR.as_ulong(), float_precision});

    SST_->generate_r1cs_witness();
    SSR_->generate_r1cs_witness();

    // SST * R2 = SST - SSR
    // SST/fp * R2/fps = SST/fp - SSR/fp
    // SST * R2 = fps * (SST - SSR)
    // R2 = floor[fps(SST-SSR)/SST]
    this->pb.val(R2Num_) = this->pb.val(SST_->iv) - this->pb.val(SSR_->iv);
    computeR2_->generate_r1cs_witness();
    
    
    uint64_t normY = this->pb.val(norm_Y_->iv).as_ulong();
    double norm_z = double(this->pb.val(norm_z_->iv).as_ulong())/float_precision;
    double prod_YZ = double(this->pb.val(prod_YZ_->iv).as_ulong())/float_precision_safe;
    double y = double(this->pb.val(y_->iv).as_ulong())/float_precision_safe;
    double square_y = double(this->pb.val(square_y_->iv).as_ulong())/float_precision;
    double Yy = double(this->pb.val(Yy_->iv).as_ulong())/float_precision_safe;
    double SST = double(this->pb.val(SST_->iv).as_ulong())/float_precision;
    double SSR = double(this->pb.val(SSR_->iv).as_ulong())/float_precision;

    // diagnositics
    std::cout << "Linear Regression Gadget Diagnostics" << std::endl;
    std::cout << "sumY: " << sumY << std::endl;
    std::cout << "normY: " << normY << std::endl;
    std::cout << "norm_z: " << norm_z << std::endl;
    std::cout << "prod_YZ: " << prod_YZ << std::endl;
    std::cout << "y: " << y << std::endl;
    std::cout << "square_y: " << square_y << std::endl;
    std::cout << "Yy: " << Yy << std::endl;
    std::cout << "SST: " << SST << std::endl;
    std::cout << "SSR: " << SSR << std::endl;

}

} // end of namespace
