
using namespace libsnark;

namespace TrustedAI {

template<typename FieldT, size_t N, size_t M>
data_source_integer<FieldT, N, M>::data_source_integer(
    protoboard<FieldT>& pb,
    size_t size,
    const std::string& annotation_prefix):
    gadget<FieldT>(pb, annotation_prefix),
    size_(size) 
{
    columns_.resize(M);
    // we defer constructing other parts of 
    // the gadget to allocate
    
}

template<typename FieldT, size_t N, size_t M>
void data_source_integer<FieldT, N, M>::allocate()
{
    row_selector_.allocate(this->pb, N, this->annotation_prefix);
    vsize_.allocate(this->pb, this->annotation_prefix);
    size_selector_.reset(new size_selector_gadget<FieldT, N>(
        this->pb, vsize_, row_selector_, this->annotation_prefix));
    size_selector_->allocate();
    
    for(size_t i=0; i < columns_.size(); ++i)
        columns_[i].reset(new integer_vector<FieldT, N>(this->pb, 
            this->size_, 
            this->size_selector_, 
            this->annotation_prefix));
    
    for(size_t i=0; i < columns_.size(); ++i)
        columns_[i]->allocate();

}

template<typename FieldT, size_t N, size_t M>
void data_source_integer<FieldT, N, M>::set_values(
    const std::vector<std::vector<uint64_t> >& values)
{
    assert(values.size() == M);
    for(size_t i=0; i < M; ++i)
        columns_[i]->set_values(values[i]);

}

template<typename FieldT, size_t N, size_t M>
void data_source_integer<FieldT, N, M>::generate_r1cs_constraints()
{
    size_selector_->generate_r1cs_constraints();
    for(size_t i=0; i < M; ++i)
        columns_[i]->generate_r1cs_constraints();
}

template<typename FieldT, size_t N, size_t M>
void data_source_integer<FieldT, N, M>::generate_r1cs_witness()
{
    this->pb.val(vsize_) = this->size_;
    size_selector_->generate_r1cs_witness();
    for(size_t i=0; i < M; ++i)
        columns_[i]->generate_r1cs_witness();

}



template<typename FieldT, size_t N, size_t M>
data_source_categorical<FieldT, N, M>::data_source_categorical(
    protoboard<FieldT>& pb,
    size_t size,
    const std::string& annotation_prefix):
    gadget<FieldT>(pb, annotation_prefix),
    size_(size) 
{
    columns_.resize(M);
    // we defer constructing other parts of 
    // the gadget to allocate
    
}

template<typename FieldT, size_t N, size_t M>
void data_source_categorical<FieldT, N, M>::allocate()
{
    row_selector_.allocate(this->pb, N, this->annotation_prefix);
    vsize_.allocate(this->pb, this->annotation_prefix);
    size_selector_.reset(new size_selector_gadget<FieldT, N>(
        this->pb, vsize_, row_selector_, this->annotation_prefix));
    size_selector_->allocate();
    
    for(size_t i=0; i < columns_.size(); ++i)
        columns_[i].reset(new categorical_vector<FieldT, N>(this->pb, 
            this->size_, 
            this->size_selector_, 
            this->annotation_prefix));
    
    for(size_t i=0; i < columns_.size(); ++i)
        columns_[i]->allocate();

}

template<typename FieldT, size_t N, size_t M>
void data_source_categorical<FieldT, N, M>::set_values(
    const std::vector<std::vector<uint64_t> >& values)
{
    assert(values.size() == M);
    for(size_t i=0; i < M; ++i)
        columns_[i]->set_values(values[i]);

}

template<typename FieldT, size_t N, size_t M>
void data_source_categorical<FieldT, N, M>::generate_r1cs_constraints()
{
    size_selector_->generate_r1cs_constraints();
    for(size_t i=0; i < M; ++i)
        columns_[i]->generate_r1cs_constraints();
}

template<typename FieldT, size_t N, size_t M>
void data_source_categorical<FieldT, N, M>::generate_r1cs_witness()
{
    this->pb.val(vsize_) = this->size_;
    size_selector_->generate_r1cs_witness();
    for(size_t i=0; i < M; ++i)
        columns_[i]->generate_r1cs_witness();

}

} // namespace
    
    



