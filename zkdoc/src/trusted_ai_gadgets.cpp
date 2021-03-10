
namespace TrustedAI {

template<typename FieldT>
void integer_variable<FieldT>::generate_r1cs_constraints()
{
    pack_gadget->generate_r1cs_constraints(true);
}

template<typename FieldT>
void integer_variable<FieldT>::generate_r1cs_witness()
{
    this->pb.val(iv) = this->value_;
    pack_gadget->generate_r1cs_witness_from_packed();
}


template<typename FieldT>
void integer_variable_array<FieldT>::generate_r1cs_constraints(bool enforce_boolean)
{
    if (!enforce_boolean) return;
    for(size_t i=0; i < ivVec.size(); ++i)
        ivVec[i].generate_r1cs_constraints();

}

template<typename FieldT>
void integer_variable_array<FieldT>::generate_r1cs_witness()
{
    for(size_t i=0; i < ivVec.size(); ++i)
        ivVec[i].generate_r1cs_witness();
}

template<typename FieldT>
void categorical_variable<FieldT>::generate_r1cs_constraints()
{
    this->pack_gadget->generate_r1cs_constraints(true);
}

template<typename FieldT>
void categorical_variable<FieldT>::generate_r1cs_witness()
{
    this->pb.val(iv) = value_;
    this->pack_gadget->generate_r1cs_witness_from_packed();

}

template<typename FieldT>
void categorical_variable_array<FieldT>::generate_r1cs_constraints(bool enforce_boolean)
{
    if (!enforce_boolean) return;
    for(size_t i=0; i < ivVec.size(); ++i)
        ivVec[i].generate_r1cs_constraints();
}

template<typename FieldT>
void categorical_variable_array<FieldT>::generate_r1cs_witness()
{
    for(size_t i=0; i < ivVec.size(); ++i)
        ivVec[i].generate_r1cs_witness();

}


template<typename FieldT>
void signed_variable<FieldT>::generate_r1cs_constraints()
{
    generate_boolean_r1cs_constraint<FieldT>(this->pb, this->is);
    this->pack_gadget->generate_r1cs_constraints(true);    
}

template<typename FieldT>
void signed_variable<FieldT>::generate_r1cs_witness()
{
    this->pb.val(iv) = this->value_;
    this->pb.val(is) = this->sign_;
    this->pb.val(ik) = this->k_;
    this->pack_gadget->generate_r1cs_witness_from_packed();
}


template<typename FieldT>
void signed_variable_array<FieldT>::generate_r1cs_constraints(bool enforce_boolean)
{
    if (!enforce_boolean) return;
    for(size_t i=0; i < ivVec.size(); ++i)
        ivVec[i].generate_r1cs_constraints();
}

template<typename FieldT>
void signed_variable_array<FieldT>::generate_r1cs_witness()
{
    for(size_t i=0; i < ivVec.size(); ++i)
        ivVec[i].generate_r1cs_witness();
}

} // namespace
