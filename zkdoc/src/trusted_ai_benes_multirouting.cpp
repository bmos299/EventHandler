
using namespace lemon;
using namespace libsnark;

namespace TrustedAI {

template<typename FieldT, size_t N>
benes_multirouting_gadget<FieldT, N>::benes_multirouting_gadget(
    protoboard<FieldT>& pb,
    const input_matrix_t& mat_left,
    const input_matrix_t& mat_right,
    const std::string& annotation_prefix): 
    gadget<FieldT>(pb, annotation_prefix), mat_left_(mat_left), mat_right_(mat_right)
{
    mat_upper_left_.resize(mat_left_.size());
    mat_upper_right_.resize(mat_left_.size());
    mat_lower_left_.resize(mat_left_.size());
    mat_lower_right_.resize(mat_left_.size());
}



template<typename FieldT, size_t N>
std::vector<size_t> 
benes_multirouting_gadget<FieldT, N>::upper_indices(const permutation<N>& sigma)
{
    typedef concepts::Graph Graph;

    std::vector<size_t> nodes;
    // build a graph with left nodes VL[N/2] and right nodes VR[N/2]
    ListGraph g;
    std::vector<ListGraph::Node> left_nodes;
    std::vector<ListGraph::Node> right_nodes;

    for(size_t i=0; i < N/2; ++i) {
        left_nodes.emplace_back(g.addNode());
        right_nodes.emplace_back(g.addNode());
    }

    // add arcs depending on the permutation
    for(size_t i=0; i < N; ++i) {
        size_t j = sigma.seq[i];
        if (findEdge(g, left_nodes[i/2], right_nodes[j/2]) == INVALID) 
            g.addEdge(left_nodes[i/2], right_nodes[j/2]);
    }

    // append ids to nodes
    ListGraph::NodeMap<size_t> node_ids(g);
    for(size_t i=0; i < N/2; ++i) {
        node_ids[left_nodes[i]] = i;
        node_ids[right_nodes[i]] = i;
    }

    //Undirector<ListDigraph> ug(g);
    MaxMatching<ListGraph> matching(g);
    matching.run();
    int msize = matching.matchingSize();

    assert(msize == N/2);
    
    // select the nodes from each left switch to be routed to upper
    for(size_t i=0; i < N/2; ++i) {
        size_t j = node_ids[ matching.mate(left_nodes[i]) ];
        if ((sigma.seq[2*i] == 2*j) || (sigma.seq[2*i] == 2*j+1))
            nodes.emplace_back(2*i);
        else
            nodes.emplace_back(2*i+1);
    }

    // print the partners++i) {
    //    std::cout << i << " <------> " << 
    //        node_ids[ matching.mate(left_nodes[i]) ] << std::endl;
    //}

    assert(nodes.size() == N/2);
    return nodes;
}

template<typename FieldT,  size_t N>
void benes_multirouting_gadget<FieldT, N>::allocate()
{
    for(size_t i=0; i < mat_upper_left_.size(); ++i) {
        mat_upper_left_[i].allocate(this->pb, N/2, this->annotation_prefix);
        mat_upper_right_[i].allocate(this->pb, N/2, this->annotation_prefix);
        mat_lower_left_[i].allocate(this->pb, N/2, this->annotation_prefix);
        mat_lower_right_[i].allocate(this->pb, N/2, this->annotation_prefix);
    }

    switches_left_.allocate(this->pb, N/2, this->annotation_prefix);
    switches_right_.allocate(this->pb, N/2, this->annotation_prefix);

    // connect the sub-gadgets
    upper_.reset(new benes_multirouting_gadget<FieldT, N/2>(
        this->pb, mat_upper_left_, mat_upper_right_, this->annotation_prefix));

    lower_.reset(new benes_multirouting_gadget<FieldT, N/2>(
        this->pb, mat_lower_left_, mat_lower_right_, this->annotation_prefix));
    
    upper_->allocate();
    lower_->allocate();

}

template<typename FieldT, size_t N>
void benes_multirouting_gadget<FieldT, N>::generate_r1cs_constraints()
{
    // enforce booleanarity on switches
    for(size_t i=0; i < N/2; ++i) {
        generate_boolean_r1cs_constraint<FieldT>(this->pb, switches_left_[i], this->annotation_prefix);
        generate_boolean_r1cs_constraint<FieldT>(this->pb, switches_right_[i], this->annotation_prefix);
    }

    // propagation constraints across switches
    for(size_t j=0; j < mat_left_.size(); ++j) {
        auto left_ = mat_left_[j];
        auto right_ = mat_right_[j];
        auto upper_left_ = mat_upper_left_[j];
        auto upper_right_ = mat_upper_right_[j];
        auto lower_left_ = mat_lower_left_[j];
        auto lower_right_ = mat_lower_right_[j];

        for(size_t i=0; i < N/2; ++i) {
            size_t upper_idx, lower_idx;
            upper_idx = input_route<N>(2*i);
            lower_idx = input_route<N>(2*i+1) - N/2;
            // for switch = 0: 
            //  left_[2*i] = upper_->left_[upper_idx] 
            //  left_[2*i+1] = lower_->left_[lower_idx - N/2]
            // for switch = 1:
            //  left_[2*i] = lower_->left_[lower_idx - N/2]
            //  left_[2*i+1] = upper_->left_[upper_idx]
            this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(
                        switches_left_[i],
                        left_[2*i+1] - left_[2*i],
                        upper_left_[upper_idx] - left_[2*i]),
                    this->annotation_prefix);

            this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(
                        switches_left_[i],
                        left_[2*i+1] - left_[2*i],
                        left_[2*i+1] - lower_left_[lower_idx]),
                    this->annotation_prefix);

            this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(
                        switches_right_[i],
                        right_[2*i+1] - right_[2*i],
                        upper_right_[upper_idx] - right_[2*i]),
                    this->annotation_prefix);

            this->pb.add_r1cs_constraint(
                    r1cs_constraint<FieldT>(
                        switches_right_[i],
                        right_[2*i+1] - right_[2*i],
                        right_[2*i+1] - lower_right_[lower_idx]),
                    this->annotation_prefix);
        }

    }

    // recursively generate constraints from sub-gadgets
    this->upper_->generate_r1cs_constraints();
    this->lower_->generate_r1cs_constraints();
}

template<typename FieldT, size_t N>
void benes_multirouting_gadget<FieldT, N>::generate_r1cs_witness(
    const permutation<N>& sigma) 
{
    std::vector<size_t> upperIdxLeft = this->upper_indices(sigma);

    /*
     * Orientation of switches:
     * The left wires with indices in upperIdx must be routed
     * to the upper sub-gadget. For each idx in upperIdx
     * if input_route(idx) < N/2, we set switch value to 0 (straight)
     * otherwise we set the switch to 1 (crossed).
     * To orient the right side switches, we re-compute
     * upperIdx = sigma(upperIdx). By the SDR property these indices
     * correspond to distinct right side switches. Next we set the
     * right side switches similarly, so as to route upperIdx to upper
     * sub-gadget
     */

    std::map<size_t, size_t> reverse_left_upper_map;
    std::map<size_t, size_t> reverse_left_lower_map;
    std::map<size_t, size_t> forward_right_upper_map;
    std::map<size_t, size_t> forward_right_lower_map;

    for(auto idx: upperIdxLeft) {
        if (input_route<N>(idx) < N/2) {
            // straight through switch
            size_t n1 = input_route<N>(idx);
            size_t n2 = input_route<N>(idx+1) - N/2;
            reverse_left_upper_map[n1] = idx;
            reverse_left_lower_map[n2] = idx + 1;
            // propagate values for all the channels
            for(size_t j=0; j < mat_left_.size(); ++j) {
                size_t X = this->pb.val(mat_left_[j][idx]).as_ulong();
                size_t Y = this->pb.val(mat_left_[j][idx+1]).as_ulong();
                this->pb.val(mat_upper_left_[j][n1]) = X;
                this->pb.val(mat_lower_left_[j][n2]) = Y;
            }

            this->pb.val(switches_left_[idx/2]) = 0;
            
        } else {
            // crossed switch
            size_t n1 = input_route<N>(idx-1);
            size_t n2 = input_route<N>(idx) - N/2;
            reverse_left_upper_map[n1] = idx;
            reverse_left_lower_map[n2] = idx - 1;
            for(size_t j=0; j < mat_left_.size(); ++j) {
                size_t X = this->pb.val(mat_left_[j][idx-1]).as_ulong();
                size_t Y = this->pb.val(mat_left_[j][idx]).as_ulong();
                this->pb.val(mat_upper_left_[j][n1]) = Y;
                this->pb.val(mat_lower_left_[j][n2]) = X;
            }
            this->pb.val(switches_left_[idx/2]) = 1;
        }
    }

    std::vector<size_t> upperIdxRight;
    for(size_t i=0; i < upperIdxLeft.size(); ++i)
        upperIdxRight.emplace_back(sigma.seq[ upperIdxLeft[i] ]);

    for(auto idx: upperIdxRight) {
        if (input_route<N>(idx) < N/2) {
            // straight through switch
            size_t n1 = input_route<N>(idx);
            size_t n2 = input_route<N>(idx+1) - N/2;
            forward_right_upper_map[idx] = n1;
            forward_right_lower_map[idx+1] = n2;
            for(size_t j=0; j < mat_right_.size(); ++j) {
                size_t X = this->pb.val(mat_right_[j][idx]).as_ulong();
                size_t Y = this->pb.val(mat_right_[j][idx+1]).as_ulong();
                this->pb.val(mat_upper_right_[j][n1]) = X;
                this->pb.val(mat_lower_right_[j][n2]) = Y;
            }
            this->pb.val(switches_right_[idx/2]) = 0;
        } else {
            // crossed switch
            size_t n1 = input_route<N>(idx-1);
            size_t n2 = input_route<N>(idx) - N/2;
            forward_right_upper_map[idx] = n1;
            forward_right_lower_map[idx-1] = n2;
            for(size_t j=0; j < mat_right_.size(); ++j) {
                size_t X = this->pb.val(mat_right_[j][idx-1]).as_ulong();
                size_t Y = this->pb.val(mat_right_[j][idx]).as_ulong();
                this->pb.val(mat_upper_right_[j][n1]) = Y;
                this->pb.val(mat_lower_right_[j][n2]) = X;
            }
            this->pb.val(switches_right_[idx/2]) = 1;
        }
    }
    
    // compute the induced permutations for upper and lower gadgets
    permutation<N/2> sigma_upper, sigma_lower;
    for(size_t i=0; i < N/2; ++i) {
        size_t idx_left = reverse_left_upper_map.at(i);
        size_t idx_right = sigma.seq[idx_left];
        size_t j = forward_right_upper_map.at(idx_right);
        sigma_upper.seq[i] = j;

        idx_left = reverse_left_lower_map.at(i);
        idx_right = sigma.seq[idx_left];
        j = forward_right_lower_map.at(idx_right);
        sigma_lower.seq[i] = j;
    }
                
    upper_->generate_r1cs_witness(sigma_upper);
    lower_->generate_r1cs_witness(sigma_lower);

}


}
    
    



