#ifndef __TRUSTED_AI_BENES_MULTIROUTING_HPP__
#define __TRUSTED_AI_BENES_MULTIROUTING_HPP__

#include <zkdoc/src/trusted_ai_gadgets.hpp>
#include <zkdoc/src/trusted_ai_vectors.hpp>
#include <lemon/list_graph.h>
#include <lemon/matching.h>
#include <lemon/smart_graph.h>
#include <lemon/concepts/graph.h>
#include <lemon/concepts/maps.h>
#include <lemon/adaptors.h>
#include <map>

using namespace libsnark;
using namespace lemon;

namespace TrustedAI {

template<size_t N>
class permutation {
public:
    std::vector<size_t> seq;

public:
    permutation() { seq.resize(N); };
};


template<size_t N>
size_t input_route(size_t index)
{
    if (index % 2 == 0)
        return index/2;
    else
        return N/2 + (index-1)/2;

    // never get here, keep the compiler happy
    return 0;
}

template<size_t N>
size_t input_route_inverse(size_t index)
{
    if (index < N/2) 
        return 2*index;
    else
        return 2*index - N + 1;

    // never get here, keep the compiler happy
    return 0;
}



// Bene's routing gadget
template<typename FieldT, size_t N>
class benes_multirouting_gadget : public gadget<FieldT> {
public:
    typedef std::vector<pb_variable_array<FieldT>> input_matrix_t;

public:
    // left and right denoted allocated variables
    // on the protoboard. Switches constitute the
    // internal witness of this gadget
    input_matrix_t mat_left_;
    input_matrix_t mat_right_;

    // inputs to sub gadgets
    input_matrix_t mat_upper_left_;  // left inputs to upper
    input_matrix_t mat_upper_right_; // right inputs to upper
    input_matrix_t mat_lower_left_;  // left inputs to lower
    input_matrix_t mat_lower_right_; // right inputs to lower

    // switching variables for this layer
    pb_variable_array<FieldT> switches_left_; 
    pb_variable_array<FieldT> switches_right_;
    
    // sub routing gadgets
    std::shared_ptr<benes_multirouting_gadget<FieldT, N/2> > upper_;
    std::shared_ptr<benes_multirouting_gadget<FieldT, N/2> > lower_;

public:

    benes_multirouting_gadget(protoboard<FieldT>& pb,
        const input_matrix_t& mat_left,
        const input_matrix_t& mat_right,
        const std::string& annotation_prefix);

    // computes left indices to be routed to upper gadget
    // other relevant routes can be computed based on these
    std::vector<size_t> upper_indices(const permutation<N>& sigma);

    void allocate();
    void generate_r1cs_constraints();
    void generate_r1cs_witness(const permutation<N>& sigma);

};

// specialize the routing gadget for 2 inputs.
template<typename FieldT>
class benes_multirouting_gadget<FieldT, 2> : public gadget<FieldT> {
public:
    typedef std::vector<pb_variable_array<FieldT>> input_matrix_t;

public:
    input_matrix_t mat_left_;
    input_matrix_t mat_right_;
    pb_variable_array<FieldT> switch_;
 
public:
    benes_multirouting_gadget(protoboard<FieldT>& pb,
        const input_matrix_t& mat_left,
        const input_matrix_t& mat_right,
        const std::string& annotation_prefix):
        gadget<FieldT>(pb, annotation_prefix), 
        mat_left_(mat_left),
        mat_right_(mat_right) {};

    // not really needed for the case N=2
    std::vector<size_t> upper_indices(const permutation<2>& sigma) 
    {
        return {0};
    };

    void allocate() 
    {
        switch_.allocate(this->pb, 1, this->annotation_prefix);
    };

    void generate_r1cs_constraints() 
    {
        // right_[0] = switch.left_[1] + (1-switch).left_[0]
        // right_[1] = switch.left_[0] + (1-switch).left_[1]
        // right_[0] - left_[0] = switch(left_[1] - left_[0])
        // right_[1] - left_[1] = switch(left_[0] - left_[1])
        for(size_t i=0; i < mat_left_.size(); ++i) {
            auto left_ = mat_left_[i];
            auto right_ = mat_right_[i];
            generate_boolean_r1cs_constraint<FieldT>(this->pb, switch_[0], 
                    this->annotation_prefix);
            this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(
                        switch_[0],
                        left_[1] - left_[0],
                        right_[0] - left_[0]),
                    this->annotation_prefix);

            this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(
                        switch_[0],
                        left_[0] - left_[1],
                        right_[1] - left_[1]),
                    this->annotation_prefix);
        }
    };

    void generate_r1cs_witness(const permutation<2>& sigma) 
    {
        if (sigma.seq[0] == 0) {
            // through switch
            this->pb.val(switch_[0]) = 0;
        } else {
            // cross switch
            this->pb.val(switch_[0]) = 1;
        }
    }

};
    
} // end of namespace

#include <zkdoc/src/trusted_ai_benes_multirouting.cpp>

#endif
