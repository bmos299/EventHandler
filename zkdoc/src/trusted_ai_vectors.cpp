
using namespace libsnark;

namespace TrustedAI {

template<typename FieldT, size_t N>
void size_selector_gadget<FieldT, N>::allocate()
{
    // we assume that input and output to the gadget
    // namely vsize_ and selector_ are added to the
    // protoboard by the caller. Here we add the auxiliary 
    // inputs to the protoboard
    this->reverse_.allocate(this->pb, N, this->annotation_prefix);
    this->inverse_.allocate(this->pb, N, this->annotation_prefix);
    this->z_.allocate(this->pb, N-1, this->annotation_prefix);
    this->w_.allocate(this->pb, N, this->annotation_prefix);
}
 
template<typename FieldT, size_t N>
void size_selector_gadget<FieldT, N>::generate_r1cs_constraints()
{
    // We add the following constraints:
    // (1) reverse[0] = vsize
    // (2) reverse[i-1] * (reverse[i] - reverse[i-1] -1) = 0 for 1\leq i < N
    // (3) reverse[i-1] * z[i-1] = reverse[i] for 1\leq i  < N
    // (4) reverse[i] * inverse[i] = selector[i] for 0\leq i < N
    // (5) inverse[i] * w[i] = 1
    // (6) selector[i] * (selector[i] - 1) = 0
    // Constraints (1)-(3) ensure that reverse[i] = max(size - i, 0)
    // Constraints (4)-(6) ensure that selector[i] = (reverse[i] > 0)
    

    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(vsize_ - reverse_[0], 1, FieldT::zero()),
        this->annotation_prefix);  // (1)

    for(size_t i=1; i < N; ++i) {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(reverse_[i] - reverse_[i-1] + 1, reverse_[i-1],0), this->annotation_prefix); // (2)
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(reverse_[i-1], z_[i-1], reverse_[i]), this->annotation_prefix); // (3)
    }

    for(size_t i=0; i < N; ++i) {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(reverse_[i], inverse_[i], selector_[i]),
            this->annotation_prefix); // (4)
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(inverse_[i], w_[i], 1),
            this->annotation_prefix); // (5)
    }

    for(size_t i=0; i < N; ++i)
        generate_boolean_r1cs_constraint<FieldT>(this->pb, selector_[i], this->annotation_prefix); // (6)
    
}

template<typename FieldT, size_t N>
void size_selector_gadget<FieldT, N>::generate_r1cs_witness()
{
    // We assume that vsize is already set (as input)
    size_t size = this->pb.val(this->vsize_).as_ulong();

    for(size_t i=0; i < size; ++i) {
        this->pb.val(reverse_[i]) = size - i;
        this->pb.val(selector_[i]) = 1;
        this->pb.val(inverse_[i]) = FieldT(size - i).inverse();
        this->pb.val(w_[i]) = size - i;
        if ( i < N - 1 ) 
            this->pb.val(z_[i]) = FieldT(size - i - 1) * FieldT(size - i).inverse();
    }

    for(size_t i=size; i < N; ++i) {
        this->pb.val(reverse_[i]) = 0;
        this->pb.val(selector_[i]) = 0;
        this->pb.val(inverse_[i]) = 1;
        this->pb.val(w_[i]) = 1;
    }

    for(size_t i=size; i < N - 1; ++i)
        this->pb.val(z_[i]) = 0;
}
    

template<typename FieldT, size_t N>
integer_vector<FieldT, N>::integer_vector(
    protoboard<FieldT>& pb,
    const size_t size,
    const std::shared_ptr<size_selector_gadget<FieldT, N> > size_selector,
    const std::string& annotation_prefix): 
    gadget<FieldT>(pb, annotation_prefix),
    size_selector_(size_selector), 
    size_(size)
{
    this->contents_.reset(
        new integer_variable_array<FieldT>(pb, N, annotation_prefix));
}

template<typename FieldT, size_t N>
std::vector<pb_variable<FieldT> > 
integer_vector<FieldT, N>::get_pb_vals() 
{
    std::vector< pb_variable<FieldT> > pb_vals;
    std::transform(
            contents_->ivVec.begin(),
            contents_->ivVec.end(),
            std::back_inserter(pb_vals),
            [](integer_variable<FieldT>& v) { return v.iv; }
            );
    return pb_vals;
}

template<typename FieldT, size_t N>
void integer_vector<FieldT, N>::set_values(
    const std::vector<uint64_t>& values)
{
    this->contents_->set_values(values);
}


template<typename FieldT, size_t N>
void integer_vector<FieldT, N>::allocate() 
{
    this->contents_->allocate();
    this->vsize_.allocate(this->pb, this->annotation_prefix);
}


template<typename FieldT, size_t N>
void integer_vector<FieldT, N>::generate_r1cs_constraints(bool enforce_bound)
{
    // skips bounding constraints on integers
    // if set to false.
    if (enforce_bound)
        this->contents_->generate_r1cs_constraints();

    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(
            this->vsize_ - this->size_selector_->vsize_,
            1,
            0), 
        this->annotation_prefix);
}

template<typename FieldT, size_t N>
void integer_vector<FieldT, N>::generate_r1cs_witness()
{
    this->pb.val(vsize_) = this->size_;
    this->contents_->generate_r1cs_witness();
}

template<typename FieldT, size_t N>
categorical_vector<FieldT, N>::categorical_vector(
    protoboard<FieldT>& pb,
    const size_t size,
    const std::shared_ptr<size_selector_gadget<FieldT, N> > size_selector,
    const std::string& annotation_prefix) : 
    gadget<FieldT>(pb, annotation_prefix),
    size_selector_(size_selector),
    size_(size)
{
    this->contents_.reset(
        new categorical_variable_array<FieldT>(pb, N, annotation_prefix));
}

template<typename FieldT, size_t N>
std::vector<pb_variable<FieldT> > 
categorical_vector<FieldT, N>::get_pb_vals() 
{
    std::vector< pb_variable<FieldT> > pb_vals;
    std::transform(
            contents_->ivVec.begin(),
            contents_->ivVec.end(),
            std::back_inserter(pb_vals),
            [](categorical_variable<FieldT>& v) { return v.iv; }
            );
    return pb_vals;
}

template<typename FieldT, size_t N>
void categorical_vector<FieldT, N>::set_values(
    const std::vector<uint64_t>& values)
{
    this->contents_->set_values(values);
}

template<typename FieldT, size_t N>
void categorical_vector<FieldT, N>::allocate() 
{
    this->contents_->allocate();
    this->vsize_.allocate(this->pb, this->annotation_prefix);
}

template<typename FieldT, size_t N>
void categorical_vector<FieldT, N>::generate_r1cs_constraints(bool enforce_bound)
{
    if (enforce_bound)
        this->contents_->generate_r1cs_constraints();

    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(
            this->vsize_ - this->size_selector_->vsize_,
            1,
            0),
        this->annotation_prefix);

}

template<typename FieldT, size_t N>
void categorical_vector<FieldT, N>::generate_r1cs_witness()
{
    this->pb.val(vsize_) = this->size_;
    this->contents_->generate_r1cs_witness();
}

template<typename FieldT, size_t N>
signed_vector<FieldT, N>::signed_vector(
    protoboard<FieldT>& pb,
    const size_t size,
    std::shared_ptr<size_selector_gadget<FieldT, N> > size_selector,
    const std::string& annotation_prefix): 
    gadget<FieldT>(pb, annotation_prefix),
    size_selector_(size_selector),
    size_(size)
{
    this->contents_.reset(
        new signed_variable_array<FieldT>(pb, N, annotation_prefix));
}

template<typename FieldT, size_t N>
std::vector<pb_variable<FieldT> > 
signed_vector<FieldT, N>::get_pb_vals() 
{
    std::vector< pb_variable<FieldT> > pb_vals;
    std::transform(
            contents_->ivVec.begin(),
            contents_->ivVec.end(),
            std::back_inserter(pb_vals),
            [](signed_variable<FieldT>& v) { return v.iv; }
            );
    return pb_vals;
}

template<typename FieldT, size_t N>
std::vector<pb_variable<FieldT> > 
signed_vector<FieldT, N>::get_pb_vals_prec() 
{
    std::vector< pb_variable<FieldT> > pb_vals_prec;
    std::transform(
            contents_->ivVec.begin(),
            contents_->ivVec.end(),
            std::back_inserter(pb_vals_prec),
            [](signed_variable<FieldT>& v) { return v.ik; }
            );
    return pb_vals_prec;
}


template<typename FieldT, size_t N>
std::vector<pb_variable<FieldT> > 
signed_vector<FieldT, N>::get_pb_vals_signs() 
{
    std::vector< pb_variable<FieldT> > pb_vals_signs;
    std::transform(
            contents_->ivVec.begin(),
            contents_->ivVec.end(),
            std::back_inserter(pb_vals_signs),
            [](signed_variable<FieldT>& v) { return v.is; }
            );
    return pb_vals_signs;
}

template<typename FieldT, size_t N>
void signed_vector<FieldT, N>::set_values(
    const std::vector<double>& values)
{
    this->contents_->set_values(values);
}

template<typename FieldT, size_t N>
void signed_vector<FieldT, N>::set_values(
    const std::vector<safe_tuple_t>& values)
{
    this->contents_->set_values(values);
}

template<typename FieldT, size_t N>
void signed_vector<FieldT, N>::allocate() 
{
    this->contents_->allocate();
    this->vsize_.allocate(this->pb, this->annotation_prefix);
}

template<typename FieldT, size_t N>
void signed_vector<FieldT, N>::generate_r1cs_constraints(bool enforce_bound)
{
    if (enforce_bound)
        this->contents_->generate_r1cs_constraints();

    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(
            this->vsize_ - this->size_selector_->vsize_,
            1,
            0),
        this->annotation_prefix);
}

template<typename FieldT, size_t N>
void signed_vector<FieldT, N>::generate_r1cs_witness()
{
    this->pb.val(vsize_) = this->size_;
    this->contents_->generate_r1cs_witness();
}

template<typename FieldT, size_t N>
void integer_vector_sum<FieldT, N>::allocate()
{
    terms_.allocate(this->pb, N, this->annotation_prefix);
}

template<typename FieldT, size_t N>
void integer_vector_sum<FieldT, N>::generate_r1cs_constraints()
{
    auto vector_vals = this->vector_->get_pb_vals();
    auto selector_vals = this->vector_->size_selector_->get_pb_vals();
    for(size_t i=0; i < N; ++i) 
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                vector_vals[i],
                selector_vals[i],
                this->terms_[i]
            ),
            this->annotation_prefix
        );
    
    auto lc = pb_coeff_sum<FieldT>(this->terms_, this->coefficients_);
 
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(
            lc,
            1,
            this->result_->iv),
            this->annotation_prefix
        );
}

template<typename FieldT, size_t N>
void integer_vector_sum<FieldT, N>::generate_r1cs_witness()
{
    auto vector_vals = this->vector_->get_pb_vals();
    auto selector_vals = this->vector_->size_selector_->get_pb_vals();
   
    for(size_t i=0; i < N; ++i)
        this->pb.val(terms_[i]) = 
            this->pb.val(vector_vals[i]) * this->pb.val(selector_vals[i]);
    
 
    pb_linear_combination<FieldT> lc;
    lc.assign(this->pb, pb_coeff_sum<FieldT>(terms_, this->coefficients_));
    lc.evaluate(this->pb);
    this->result_->set_value(this->pb.lc_val(lc).as_ulong());
}

template<typename FieldT, size_t N>
void signed_vector_sum<FieldT, N>::allocate()
{
    termsP_.allocate(this->pb, N, this->annotation_prefix);
    terms_.allocate(this->pb, N, this->annotation_prefix);
}

template<typename FieldT, size_t N>
void signed_vector_sum<FieldT, N>::generate_r1cs_constraints()
{
    /*
     * The computation of F-linear combination of signed numbers
     * is expressed as follows: Let X[i] = (s[i], v[i], k[i]) denote the
     * i^th signed number, and f[i], i\in [N] denote the field elements
     * denoting the linear combination, S[i] denote the selector.
     * To enforce result = (v,s,k) we have:
     * terms[i] = v[i].S[i] (account for selector)
     * termsP[i] = (1-2s[i]).v[i] (value with sign)
     * lcP = F-linear-combination(coefficients, termsP)
     * k[i] = k for all i
     * (1-2s).v = lcP
     */
    std::vector<pb_variable<FieldT> > vector_vals = this->vector_->get_pb_vals();
    std::vector<pb_variable<FieldT> > vector_signs = this->vector_->get_pb_vals_signs();
    std::vector<pb_variable<FieldT> > vector_prec = this->vector_->get_pb_vals_prec();
    std::vector<pb_variable<FieldT> > selector_vals = 
        this->vector_->size_selector_->get_pb_vals();
    
    auto lcP = pb_coeff_sum<FieldT>(this->termsP_, this->coefficients_);
    
    for(size_t i=0; i < N; ++i) {  
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                vector_vals[i],
                selector_vals[i],
                terms_[i]), "terms[i]=v[i].S[i]");
        
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                1 - 2*vector_signs[i],
                terms_[i],
                termsP_[i]), "termsP[i]=(1-2s[i]).terms[i]");

        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                vector_prec[i],
                1,
                result_->ik), "v->k=result->k");

    }    

    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(
            1-2*result_->is,
            result_->iv,
            lcP), "lcP = signed result");
    
}


template<typename FieldT, size_t N>
void signed_vector_sum<FieldT, N>::generate_r1cs_witness()
{
    std::vector<pb_variable<FieldT> > vector_vals = 
        this->vector_->get_pb_vals();
    std::vector<pb_variable<FieldT> > vector_signs = 
        this->vector_->get_pb_vals_signs();
    std::vector<pb_variable<FieldT> > vector_prec = 
        this->vector_->get_pb_vals_prec();

    std::vector<pb_variable<FieldT> > selector_vals = 
        this->vector_->size_selector_->get_pb_vals();
    
    auto lcP = pb_coeff_sum<FieldT>(this->termsP_, this->coefficients_);
   
    for(size_t i=0; i < N; ++i) {
        this->pb.val(terms_[i]) = 
            this->pb.val(vector_vals[i]) * this->pb.val(selector_vals[i]);
        this->pb.val(termsP_[i]) =
            (FieldT::one() - FieldT(2)*this->pb.val(vector_signs[i])) * (this->pb.val(terms_[i]));
    }

    pb_linear_combination<FieldT> PP;
    PP.assign(this->pb, lcP);
    PP.evaluate(this->pb);
    FieldT r = this->pb.lc_val(PP);
    FieldT nr = FieldT::zero() - r;
    
    uint64_t s, v, k;
    if (r.as_bigint().num_bits() < float_bit_width) {
        std::cout << "Positive signed vector sum: " << r << std::endl;
        v = r.as_ulong();
        s = 0;
    } else if (nr.as_bigint().num_bits() < float_bit_width) {
        std::cout << "Negative signed vector sum: " << nr << std::endl;
        v = nr.as_ulong();
        s = 1;
    } else {
        std::cout << "Overflow in signed_vector_sum: " << 
            r.as_bigint().num_bits() << " " << nr.as_bigint().num_bits() << std::endl;
        exit(1);
    }

    k = this->pb.val(vector_prec[0]).as_ulong();
    result_->set_value({s, v, k});
}

template<typename FieldT, size_t N>
dot_product_integer<FieldT, N>::dot_product_integer(
    protoboard<FieldT>& pb,
    const std::shared_ptr<integer_vector<FieldT, N> > vleft,
    const std::shared_ptr<integer_vector<FieldT, N> > vright,
    const std::shared_ptr<integer_variable<FieldT> > result,
    const std::string& annotation_prefix): 
    gadget<FieldT>(pb, annotation_prefix),
    vleft_(vleft), vright_(vright), result_(result)
{
    // initialize the vector of pairwise product
    // and connect it into the summation gadget
    size_t size = this->vleft_->size_;
    product_.reset(new integer_vector<FieldT, N>(
        this->pb,
        size,
        vleft_->size_selector_,
        this->annotation_prefix));

    std::vector<FieldT> coefficients(N, FieldT::one());
    sum_product_.reset(new integer_vector_sum<FieldT, N>(
        this->pb,
        coefficients,
        this->product_,
        this->result_,
        this->annotation_prefix));
}

template<typename FieldT, size_t N>
void dot_product_integer<FieldT, N>::allocate()
{
    product_->allocate();
    sum_product_->allocate();
}

template<typename FieldT, size_t N>
void dot_product_integer<FieldT, N>::generate_r1cs_constraints()
{
    // first make sure all vectors have compatible sizes
    //product_->generate_r1cs_constraints();
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(
            this->vleft_->vsize_,
            1,
            this->vright_->vsize_), this->annotation_prefix);
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(
            this->vleft_->vsize_,
            1,
            this->product_->vsize_), this->annotation_prefix);
   
    // add the constraints product_ = vleft_ . vright_
    auto vL = vleft_->get_pb_vals();
    auto vR = vright_->get_pb_vals();
    auto vP = product_->get_pb_vals();
    
    assert((vL.size() == N) && (vR.size() == N) && (vP.size() == N));

    for(size_t i=0; i < N; ++i)
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                vL[i],
                vR[i],
                vP[i]), this->annotation_prefix);        

    // no need to constrain the size of product terms
    // as we know they don't wrap around as long as
    // prime bit length >= 2*integer_bit_width
    product_->generate_r1cs_constraints(false);
    sum_product_->generate_r1cs_constraints();
}

template<typename FieldT, size_t N>
void dot_product_integer<FieldT, N>::generate_r1cs_witness()
{
    // generate the witness
    std::vector<uint64_t> values;
    auto left_vals = vleft_->get_pb_vals();
    auto right_vals = vright_->get_pb_vals();
    assert(left_vals.size() == right_vals.size());
    for(size_t i=0; i < left_vals.size(); ++i)
        values.emplace_back(
           this->pb.val(left_vals[i]).as_ulong() * this->pb.val(right_vals[i]).as_ulong());
    product_->set_values(values);
    product_->generate_r1cs_witness();
    sum_product_->generate_r1cs_witness();
}

template<typename FieldT, size_t N>
dot_product_signed<FieldT, N>::dot_product_signed(
    protoboard<FieldT>& pb,
    const std::shared_ptr<signed_vector<FieldT, N> > vleft,
    const std::shared_ptr<signed_vector<FieldT, N> > vright,
    const std::shared_ptr<signed_variable<FieldT> > result,
    const std::string& annotation_prefix): 
    gadget<FieldT>(pb, annotation_prefix),
    vleft_(vleft), vright_(vright), result_(result)
{
    // initialize the vector of pairwise product
    // and connect it into the summation gadget
    size_t size = this->vleft_->size_;
    product_.reset(new signed_vector<FieldT, N>(
        this->pb,
        size,
        vleft_->size_selector_,
        this->annotation_prefix));

    std::vector<FieldT> coefficients(N, FieldT::one());
    sum_product_.reset(new signed_vector_sum<FieldT, N>(
        this->pb,
        coefficients,
        this->product_,
        this->result_,
        "sum_product"));
}

template<typename FieldT, size_t N>
void dot_product_signed<FieldT, N>::allocate()
{
    product_->allocate();
    sum_product_->allocate();
}

template<typename FieldT, size_t N>
void dot_product_signed<FieldT, N>::generate_r1cs_constraints()
{
    // first make sure all vectors have compatible sizes
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(
            this->vleft_->vsize_,
            1,
            this->vright_->vsize_), this->annotation_prefix);
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(
            this->vleft_->vsize_,
            1,
            this->product_->vsize_), this->annotation_prefix);
  
    // add constraints: product_ = vleft_ . vright_
    auto vL = vleft_->get_pb_vals();
    auto vR = vright_->get_pb_vals();
    auto kL = vleft_->get_pb_vals_prec();
    auto kR = vright_->get_pb_vals_prec();
    auto sL = vleft_->get_pb_vals_signs();
    auto sR = vright_->get_pb_vals_signs();
    auto vP = product_->get_pb_vals();
    auto sP = product_->get_pb_vals_signs();
    auto kP = product_->get_pb_vals_prec();

    assert((vL.size() == N) && (vR.size() == N));

    for(size_t i=0; i < N; ++i) {
        // product value constraint
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                vL[i],
                vR[i],
                vP[i]), "vP=vL.vR");
        // product sign constraint
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                2 * sL[i],
                sR[i],
                sL[i] + sR[i] - sP[i]), "sP=sL+sR-2sL.sR");
        // precision constraints
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                kL[i],
                kR[i],
                kP[i]), "kP=kL.kR");
    }
            
    product_->generate_r1cs_constraints(false);
    sum_product_->generate_r1cs_constraints();
}

template<typename FieldT, size_t N>
void dot_product_signed<FieldT, N>::generate_r1cs_witness()
{
    // generate the witness
    // 1.237 x 2.546 = 3.149
    std::vector<safe_tuple_t> values;
    auto left_vals = vleft_->get_pb_vals();
    auto right_vals = vright_->get_pb_vals();
    auto left_signs = vleft_->get_pb_vals_signs();
    auto right_signs = vright_->get_pb_vals_signs();
    auto left_prec = vleft_->get_pb_vals_prec();
    auto right_prec = vright_->get_pb_vals_prec();

    assert(left_vals.size() == right_vals.size());
    assert(left_signs.size() == right_signs.size());


    for(size_t i=0; i < left_vals.size(); ++i) {
        auto v1 = this->pb.val(left_vals[i]).as_ulong();
        auto v2 = this->pb.val(right_vals[i]).as_ulong();
        auto k1 = this->pb.val(left_prec[i]).as_ulong();
        auto k2 = this->pb.val(right_prec[i]).as_ulong();
        auto s1 = this->pb.val(left_signs[i]).as_ulong();
        auto s2 = this->pb.val(right_signs[i]).as_ulong();
        
        auto s = (s1 + s2) % 2;
        values.emplace_back(safe_tuple_t({s, v1*v2, k1*k2}));
    }
    
    product_->set_values(values);
    product_->generate_r1cs_witness();
    sum_product_->generate_r1cs_witness();
}

template<typename FieldT, size_t N>
dot_product_integer_signed<FieldT, N>::dot_product_integer_signed(
    protoboard<FieldT>& pb,
    const std::shared_ptr<integer_vector<FieldT, N> > vleft,
    const std::shared_ptr<signed_vector<FieldT, N> > vright,
    const std::shared_ptr<signed_variable<FieldT> > result,
    const std::string& annotation_prefix): 
    gadget<FieldT>(pb, annotation_prefix),
    vleft_(vleft), vright_(vright), result_(result)
{
    // initialize the vector of pairwise product
    // and connect it into the summation gadget
    size_t size = this->vleft_->size_;
    product_.reset(new signed_vector<FieldT, N>(
        this->pb,
        size,
        vleft_->size_selector_,
        this->annotation_prefix));

    std::vector<FieldT> coefficients(N, FieldT::one());
    sum_product_.reset(new signed_vector_sum<FieldT, N>(
        this->pb,
        coefficients,
        this->product_,
        this->result_,
        this->annotation_prefix));
}

template<typename FieldT, size_t N>
void dot_product_integer_signed<FieldT, N>::allocate()
{
    product_->allocate();
    sum_product_->allocate();
}

template<typename FieldT, size_t N>
void dot_product_integer_signed<FieldT, N>::generate_r1cs_constraints()
{
    // first make sure all vectors have compatible sizes
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(
            this->vleft_->vsize_,
            1,
            this->vright_->vsize_), this->annotation_prefix);
    this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(
            this->vleft_->vsize_,
            1,
            this->product_->vsize_), this->annotation_prefix);
   
    // add constraints product_ = vleft_ . vright_
    auto vL = vleft_->get_pb_vals();
    auto vR = vright_->get_pb_vals();
    auto sR = vright_->get_pb_vals_signs();
    auto kR = vright_->get_pb_vals_prec();
    auto vP = product_->get_pb_vals();
    auto sP = product_->get_pb_vals_signs();
    auto kP = product_->get_pb_vals_prec();

    assert((vL.size() == N) && (vR.size() == N));

    for(size_t i=0; i < N; ++i) {
        // product value constraint
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                vL[i],
                vR[i],
                vP[i]), "vP=vL.vR");
        // product sign constraint
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                sR[i],
                1,
                sP[i]), "sP=sR");
        // precision constraint
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(
                kR[i],
                1,
                kP[i]), "kP=kR");
    }

    product_->generate_r1cs_constraints(false);
    
    sum_product_->generate_r1cs_constraints();
}

template<typename FieldT, size_t N>
void dot_product_integer_signed<FieldT, N>::generate_r1cs_witness()
{
    // generate the witness
    // 2 x 2.546 = 3.149
    std::vector<safe_tuple_t> values;
    auto left_vals = vleft_->get_pb_vals();
    auto right_vals = vright_->get_pb_vals();
    auto right_signs = vright_->get_pb_vals_signs();
    auto right_prec = vright_->get_pb_vals_prec();

    assert(left_vals.size() == right_vals.size());

    for(size_t i=0; i < left_vals.size(); ++i) {
        auto v1 = this->pb.val(left_vals[i]).as_ulong();
        auto v2 = this->pb.val(right_vals[i]).as_ulong();
        auto s2 = this->pb.val(right_signs[i]).as_ulong();
        auto k2 = this->pb.val(right_prec[i]).as_ulong();
        values.emplace_back(safe_tuple_t({s2, v1*v2, k2}));
    }
   

    product_->set_values(values);
    product_->generate_r1cs_witness();
    sum_product_->generate_r1cs_witness();
}

} // end of namespace
    
    
     
   
            
    
