#include <zkdoc/src/trusted_ai_gadgets.hpp>
#include <zkdoc/src/trusted_ai_vectors.hpp>
#include <zkdoc/src/trusted_ai_benes_multirouting.hpp>
#include <zkdoc/src/trusted_ai_datasource.hpp>
#include <zkdoc/src/trusted_ai_linear_regression.hpp>
#include <zkdoc/src/trusted_ai_hash_gadget.hpp>
#include <zkdoc/src/trusted_ai_interface_gadgets.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <depends/rapidcsv/src/rapidcsv.h>
#include <yaml-cpp/yaml.h>
#include <iostream>
#include <cassert>
#include <iostream>
#include <numeric>
#include <algorithm>
#include <tuple>
#include <set>
#include <cstdlib>
#include <gmp.h>
#include <gmpxx.h>
#include <getopt.h>

using namespace TrustedAI;
using namespace libsnark;

const size_t N = 1024;
const size_t M = 20;
const size_t C = 5;
const size_t B = 10;

typedef libff::edwards_pp snark_pp;
typedef libff::Fr<snark_pp> FieldT;

template<typename FieldT>
void print_protoboard_info(protoboard<FieldT>& pb)
{
    std::cout << "Protoboard Satisfied: [ " << pb.is_satisfied() << " ]" << std::endl;
    std::cout << "Protoboard Constraints: [ " << pb.num_constraints() << " ]" << std::endl;
    std::cout << "Protoboard Variables: [ " << pb.num_variables() << " ]" << std::endl;
}

template<typename T>
void print_matrix(const std::vector<std::vector<T>>& mat)
{
    size_t ncols = mat.size();
    size_t nrows = (ncols > 0)?mat[0].size():0;
    nrows = std::min(nrows, size_t(5));
    
    for(size_t i=0; i < nrows; ++i) {
        for(size_t j=0; j < ncols; ++j)
            std::cout << mat[j][i] << " ";
        std::cout << std::endl;
    }
}
// Schema Descriptor Yaml:
// SchemaDescriptor
//  CategoricalFeatures:
//      - colName1
//      - colName2
//
//  IntegerFeatures:
//      - colName1
//      - colName2
//
//  NumericFeatures:
//      - colName1
//      - colName2

/**
 * Utiliy Function to assign levels to categorical values
 * @ values : a vector of string values
 * @ return : each string value mapped to its lexicographic index
 */
std::map<std::string, uint64_t>
compute_levels(const std::vector<std::string>& values)
{
    std::vector<std::string> vals(values);
    std::sort(vals.begin(), vals.end());
    auto it = std::unique(vals.begin(), vals.end());
    vals.resize(std::distance(vals.begin(), it));
    
    std::map<std::string, uint64_t> levels;
    for(size_t i=0; i < vals.size(); ++i)
        levels[vals[i]] = i+1;
    
    return levels;
}

/**
 * Applies the mapping to string values
 * @param values -- an array of string values
 * @param levels -- a map of levels
 * @return a numeric vector by applying levels to values
 */
std::vector<uint64_t>
apply_levels(const std::vector<std::string>& values,
    const std::map<std::string, uint64_t>& levels)
{
    std::vector<uint64_t> factor;
    for(size_t i=0; i < values.size(); ++i) {
        assert(levels.find(values[i]) != levels.end());
         factor.emplace_back(levels.find(values[i])->second);
    }
    
    return factor;
}

typedef std::tuple<std::string, std::string> col_desc_t;

/**
 * Placeholder class to represent schema yaml
 */
class SchemaDescriptor {
public:
    std::vector<std::string> categorical_features;
    std::vector<std::string> integer_features;
    std::vector<std::string> numeric_features;
};

/**
 * Class to represent datahandle
 * @field: categorical_features -- tuples of categorical column name and hashes
 * @field: integer_features -- tuples of integer column name and hashes
 * @field: numeric_features -- tuples of numeric column name and hashes
 * @field: levels_map -- level map for categorical columns
 */ 
class DataHandle {
public:
    std::vector<col_desc_t> categorical_features;
    std::vector<col_desc_t> integer_features;
    std::vector<col_desc_t> numeric_features;
    // levels map
    std::map<std::string, std::map<std::string, uint64_t>> levels_map;
public:
    // output data handle to a file
    int print(std::ostream& out) { 
        YAML::Emitter yout;
        yout << YAML::BeginMap ;
        yout << YAML::Key << "CategoricalFeatures";
        yout << YAML::Value << YAML::BeginSeq;
        for(size_t i=0; i < categorical_features.size(); ++i)
            yout << YAML::Flow << YAML::BeginSeq <<
                std::get<0>(categorical_features[i]) <<
                std::get<1>(categorical_features[i]) << YAML::EndSeq;
        yout << YAML::EndSeq;

        yout << YAML::Key << "IntegerFeatures";
        yout << YAML::Value << YAML::BeginSeq;
        for(size_t i=0; i < integer_features.size(); ++i)
            yout << YAML::Flow << YAML::BeginSeq <<
                std::get<0>(integer_features[i]) <<
                std::get<1>(integer_features[i]) << YAML::EndSeq;
        yout << YAML::EndSeq;

        // output levels map
        yout << YAML::Key << "LevelsMap";
        yout << YAML::Value << YAML::BeginMap;
        for(auto tup : categorical_features) {
            yout << YAML::Key << std::get<0>(tup);
            yout << YAML::Value << YAML::BeginSeq;
            auto levels = levels_map[std::get<0>(tup)];
            for(auto it=levels.begin(); it != levels.end(); ++it) {
                yout << YAML::Flow << YAML::BeginSeq;
                yout << it->first << it->second << YAML::EndSeq;
            }
            yout << YAML::EndSeq;
        }
        yout << YAML::EndMap;
        yout << YAML::EndMap;
                
        out << yout.c_str();
        return 0;
    };
};


// class to represent a dataset (a csv file)        
class Dataset {
public:
    std::vector<std::vector<std::string>> categorical_matrix;
    std::vector<std::vector<uint64_t>> integer_matrix;
    std::vector<std::vector<double>> numeric_matrix;

    std::vector<std::string> catColNames;
    std::vector<std::string> intColNames;
    std::vector<std::string> numColNames;

public:
    size_t n_cat_features;
    size_t n_integer_features;
    size_t n_numeric_features;
    size_t nrows, ncols;

public:
    Dataset():
        n_cat_features(0), n_integer_features(0), n_numeric_features(0),
        nrows(0), ncols(0) {};

    void print() const
    {
        std::cout << "NROWS: " << nrows << '\t' << "NCOLS: " << ncols << std::endl;
        std::cout << "Categorical Matrix: " << std::endl;
        print_matrix<std::string>(categorical_matrix);
        std::cout << "Integer Matrix: " << std::endl;
        print_matrix<uint64_t>(integer_matrix);
        std::cout << "Numeric Matrix: " << std::endl;
        print_matrix<double>(numeric_matrix);
    };
};


/**
 * Read the schema from a schema yaml file
 * @input file path to schema file
 * @return SchemaDescriptor object, nullptr in case of failure
 */
std::shared_ptr<SchemaDescriptor>
read_schema_descriptor(const std::string& file)
{
    std::shared_ptr<SchemaDescriptor> sd;
    sd.reset(new SchemaDescriptor());

    //@todo Handle error for LoadFile
    YAML::Node top = YAML::LoadFile(file);
    if (top["CategoricalFeatures"]) {
        YAML::Node catfeatures = top["CategoricalFeatures"];
        if (!catfeatures.IsSequence()) 
            return nullptr;
        for(size_t i=0; i < catfeatures.size(); ++i)
            sd->categorical_features.emplace_back(catfeatures[i].as<std::string>());
    }

    if (top["IntegerFeatures"]) {
        YAML::Node intfeatures = top["IntegerFeatures"];
        if (!intfeatures.IsSequence()) 
            return nullptr;
        for(size_t i=0; i < intfeatures.size(); ++i)
            sd->integer_features.emplace_back(intfeatures[i].as<std::string>());
    }

    if (top["NumericFeatures"]) {
        YAML::Node numfeatures = top["NumericFeatures"];
        if (!numfeatures.IsSequence()) 
            return nullptr;
        for(size_t i=0; i < numfeatures.size(); ++i)
            sd->numeric_features.emplace_back(numfeatures[i].as<std::string>());
    }
    
    return sd;
}

/**
 * read a dataset, given the schema
 * @input file path to data file
 * @input sd the pointer to schema object
 * @return pointer to Dataset object, nullptr in case of failure
 */
std::shared_ptr<Dataset>
read_dataset(
    const std::string& file,
    std::shared_ptr<SchemaDescriptor> sd)
{
    std::shared_ptr<Dataset> ds(new Dataset());

    std::set<std::string> catSet(sd->categorical_features.begin(),
        sd->categorical_features.end());
    std::set<std::string> intSet(sd->integer_features.begin(),
        sd->integer_features.end());
    std::set<std::string> numSet(sd->numeric_features.begin(),
        sd->numeric_features.end());
    
    rapidcsv::Document doc(file);
    size_t nrows = doc.GetRowCount();
    size_t ncols = doc.GetColumnCount();
    ds->nrows = nrows;
    ds->ncols = ncols;

    for(size_t i=0; i < ncols; ++i) {
        auto colName = doc.GetColumnName(i);
        if (catSet.count(colName)) {
            auto col = doc.GetColumn<std::string>(i);
            ds->categorical_matrix.emplace_back(col);
            ds->catColNames.emplace_back(colName);
            ds->n_cat_features++;
        } else if (intSet.count(colName)) {
            ds->integer_matrix.emplace_back(doc.GetColumn<uint64_t>(colName));
            ds->intColNames.emplace_back(colName);
            ds->n_integer_features++;
        } else if (numSet.count(colName)) {
            ds->numeric_matrix.emplace_back(doc.GetColumn<double>(colName));
            ds->numColNames.emplace_back(colName);
            ds->n_numeric_features++;
        } else {
            std::cout << "Column " << colName << " not found in descriptor" << std::endl;
            return nullptr;
        }
    }

    return ds;
}

/**
 * Read the datahandle descriptor
 * @input data_handle_file path to file containing datahandle
 * @return pointer to DataHandle object, nullptr to indicate failure
 */
std::shared_ptr<DataHandle>
read_data_handle(const std::string& data_handle_file)
{
    std::shared_ptr<DataHandle> dhandle(new DataHandle());
    YAML::Node top = YAML::LoadFile(data_handle_file);
    std::vector<col_desc_t> categorical_features, integer_features;
    std::map<std::string, std::map<std::string, uint64_t>> levels_map;
    // read categorical features
    if (top["CategoricalFeatures"]) {
        YAML::Node cat_features_node = top["CategoricalFeatures"];
        if (cat_features_node.IsSequence()) {
            for(size_t i=0; i < cat_features_node.size(); ++i) {
                auto colName = cat_features_node[i][0].as<std::string>();
                auto colHash = cat_features_node[i][1].as<std::string>();
                categorical_features.emplace_back(col_desc_t(colName, colHash));
            }
        } else {
            std::cout << "Malformed datahandle" << std::endl;
            return nullptr;
        }
    } 

    if (top["IntegerFeatures"]) {
        YAML::Node int_features_node = top["IntegerFeatures"];
        if (int_features_node.IsSequence()) {
            for(size_t i=0; i < int_features_node.size(); ++i) {
                auto colName = int_features_node[i][0].as<std::string>();
                auto colHash = int_features_node[i][1].as<std::string>();
                integer_features.emplace_back(col_desc_t(colName, colHash));
            }
        } else {
            std::cout << "Malformed datahandle" << std::endl;
            return nullptr;
        }
    } 

    if (top["LevelsMap"]) {
        YAML::Node levelsMap = top["LevelsMap"];
        if (levelsMap.IsMap()) {
            for(auto it = levelsMap.begin(); it != levelsMap.end(); ++it) {
                auto colName = it->first.as<std::string>();
                std::map<std::string, uint64_t> levels;
                if (it->second.IsSequence()) {
                    // it is sequence of <string, string>
                    for(size_t i=0; i < it->second.size(); ++i) {
                        auto key = it->second[i][0].as<std::string>();
                        auto value = it->second[i][1].as<uint64_t>();
                        levels[key] = value;
                    }
                    levels_map[colName] = levels;
                } else {
                    std::cout << "Malformed datahandle" << std::endl;
                    return nullptr;
                }
            }
        } else {
            std::cout << "Malformed datahandle" << std::endl;
            return nullptr;
        }
    }

    dhandle->categorical_features = categorical_features;
    dhandle->integer_features = integer_features;
    dhandle->levels_map = levels_map;
    return dhandle;
}
    
/**
 * Computes datahandle descriptor for tabular data
 * A maximum of C categorical columns are considered part
 * of datahandle. If the dataset has fewer than C categorical
 * columns, the "dummy" categorical columns consisting of all 
 * 0s are appended to make C categorical columns. The hash is
 * then computed for each column. The order of existing columns
 * is preserved. For > C, columns, the first C columns are included.
 * For integer, columns, upto a maximum M+1 colums are considered
 * @input dataset the dataset representing csv data
 * @return pointer to DataHandle object as described above.
 */
std::shared_ptr<DataHandle>
compute_data_handle(const std::shared_ptr<Dataset> dataset)
{
    // currently we don't use numeric features for data-handle
    // this is beacuse, numeric features are expensive to support

    std::vector<std::vector<std::string>> cat_features =
        dataset->categorical_matrix;
    cat_features.resize(C, std::vector<std::string>(dataset->nrows, "NA"));
    auto catColNames = dataset->catColNames;
    catColNames.resize(C, "Dummy");
     
    std::vector<std::vector<uint64_t>> integer_features =
        dataset->integer_matrix;
    integer_features.resize(M+1, std::vector<uint64_t>(dataset->nrows, 0));
    auto intColNames = dataset->intColNames;
    intColNames.resize(M+1, "Dummy");

    snark_pp::init_public_params();
    protoboard<FieldT> pb;

    data_source<FieldT, N, C, M+1> ds(pb, dataset->nrows, "data-source");
    ds.allocate();
    // convert categorical features to levels
    // and compute the levels map
    std::vector<std::vector<uint64_t>> cat_features_levels;
    std::map<std::string, std::map<std::string, uint64_t>> levels_map;
    for(size_t i=0; i < cat_features.size(); ++i) {
        auto colName = catColNames[i];
        levels_map[colName] = compute_levels(cat_features[i]);
        cat_features_levels.emplace_back(
            apply_levels(cat_features[i], levels_map[colName]));
    }

    ds.set_values(cat_features_levels, integer_features);
    ds.generate_r1cs_witness();

    std::shared_ptr<DataHandle> dhandle(new DataHandle());
    for(size_t i=0; i < C; ++i) {
        auto colName = catColNames[i];
        mpz_t col_hash;
        mpz_init(col_hash);
        ds.cHashes_[i].as_bigint().to_mpz(col_hash);
        mpz_class colHash(col_hash);
        dhandle->categorical_features.emplace_back(
            col_desc_t(colName, colHash.get_str(16)));
        mpz_clear(col_hash);
    }
        
    for(size_t i=0; i < M+1; ++i) {
        auto colName = intColNames[i];
        mpz_t col_hash;
        mpz_init(col_hash);
        ds.iHashes_[i].as_bigint().to_mpz(col_hash);
        mpz_class colHash(col_hash);
        dhandle->integer_features.emplace_back(
            col_desc_t(colName, colHash.get_str(16)));
        mpz_clear(col_hash);
    }
    dhandle->levels_map = levels_map;

    return dhandle;
}

/**
 * Computes hash of a linear model
 * A model is expressed as M+1 coefficients (for configured value M)
 * i.e W_0, W_1,..., W_M. We use W_M as the offset term, instead of W_0
 * Thus, the prediction for x_0,...x_{M-1} is W_0.x_0 + ... W_M
 */
std::string 
compute_model_hash(const std::vector<double>& coefficients)
{
    snark_pp::init_public_params();
    protoboard<FieldT> pb;
   
    std::shared_ptr<signed_vector<FieldT, M+1>> model;
    pb_variable<FieldT> wsize;
    pb_variable_array<FieldT> w_selector;
    std::shared_ptr<size_selector_gadget<FieldT, M+1>> w_size_selector;
    std::shared_ptr<mimc_hash_signed<FieldT, M+1, 1>> w_hash;
    pb_variable<FieldT> model_hash;

    wsize.allocate(pb, "wsize");
    w_selector.allocate(pb, M+1, "w_selector");
    model_hash.allocate(pb, "model_hash");

    w_size_selector.reset(new size_selector_gadget<FieldT, M+1>(
        pb,
        wsize,
        w_selector,
        "w_size_selector"));
    w_size_selector->allocate();
    
    model.reset(new signed_vector<FieldT, M+1>(
        pb,
        M+1,
        w_size_selector,
        "modelcoefficients"));
    model->allocate();
    
    w_hash.reset(new mimc_hash_signed<FieldT, M+1, 1>(
        pb,
        model,
        model_hash,
        "w_hash"));
    w_hash->allocate();

    pb.val(wsize) = M+1;
    w_size_selector->generate_r1cs_witness();
    // note that if size of coefficients is less than
    // M+1, it will be resized in set_values.
    model->set_values(coefficients);
    model->generate_r1cs_witness();
    w_hash->generate_r1cs_witness();
    
    // convert hash to mpz to hex string
    mpz_t mhash;
    mpz_init(mhash);
    pb.val(model_hash).as_bigint().to_mpz(mhash);
    mpz_class hash(mhash);
    mpz_clear(mhash);
    return hash.get_str(16);
}

// generate proving and verification keys for
// model provenance gadget
void generate_model_provenance_keys(
    const std::string& pkey_file, 
    const std::string& vkey_file)
{
    snark_pp::init_public_params();
    protoboard<FieldT> pb;

    model_provenance_gadget<FieldT, N, C, M> provenance_gadget(pb, 0, "provenance_gaadget");
    provenance_gadget.generate_r1cs_constraints();
    
    auto retval = r1cs_ppzksnark_generator<snark_pp>(pb.get_constraint_system());
    
    std::ofstream ofile_pk(pkey_file);
    std::ofstream ofile_vk(vkey_file);
    
    ofile_pk << retval.pk;
    ofile_vk << retval.vk;

    ofile_pk.close();
    ofile_vk.close();
    
}

// generate proving and verification keys for
// model inference gadget
void generate_model_inference_keys(
    const std::string& pkey_file, 
    const std::string& vkey_file)
{
    snark_pp::init_public_params();
    protoboard<FieldT> pb;

    model_inference_gadget<FieldT, B, C, M> inference_gadget(pb, 9, "inference_gadget");
    inference_gadget.generate_r1cs_constraints();
    assert(pb.primary_input().size() == (B*M+B+2));
    
    auto retval = r1cs_ppzksnark_generator<snark_pp>(pb.get_constraint_system());
    
    std::ofstream ofile_pk(pkey_file);
    std::ofstream ofile_vk(vkey_file);
    
    ofile_pk << retval.pk;
    ofile_vk << retval.vk;

    ofile_pk.close();
    ofile_vk.close();
}


/**
 * This function generates proof of performance
 * of a lineare model (model_file, model_schema) on
 * data (data_file, data_schema). We make some assumptions
 * on the format of data.
 * (1) The last integer column is assumed to be the target column
 * whose value is predicted in terms of remaining numeric
 * columns.
 * (2) Categorical columns explicitly do not take part in prediction,
 * if desired, they must be encoded to numeric columns. 
 */
void generate_performance_proof(
    const std::string& pkey_file,
    const std::string& data_schema_file,
    const std::string& data_file,
    const std::string& model_schema_file,
    const std::string& model_file,
    const std::string& output_file)
{
    snark_pp::init_public_params();
    protoboard<FieldT> pb;

    (void) pkey_file;
    auto sc_data = read_schema_descriptor(data_schema_file);
    auto ds = read_dataset(data_file, sc_data);
   
    // view model as dataset with one numeric column
    auto sc_model = read_schema_descriptor(model_schema_file);
    auto m_coeff = read_dataset(model_file, sc_model);

    // generate datahandle. Note that datahandle is returned
    // for extended dataset with C categorical features and
    // M+1 integer features.
    auto dhandle = compute_data_handle(ds);
    
    std::vector<std::vector<uint64_t>> cat_features, int_features, target;
    std::vector<double> model_coefficients = m_coeff->numeric_matrix[0];

    // convert categorical columns to numeric columns using the
    // levels map
    for(size_t i=0; i < ds->catColNames.size(); ++i) {
        auto col = ds->categorical_matrix[i];
        auto colName = ds->catColNames[i];
        cat_features.emplace_back(apply_levels(col, dhandle->levels_map[colName]));
    }

    // regard last but one integer columns of the (original) dataset as features
    for(size_t i=0; i < ds->intColNames.size() - 1; ++i)
         int_features.emplace_back(ds->integer_matrix[i]);

    cat_features.resize(C, std::vector<uint64_t>(N, 0));
    int_features.resize(M, std::vector<uint64_t>(N, 0));

    // regard the last integer column of dataset as the target variable
    target.emplace_back(ds->integer_matrix[ds->intColNames.size() - 1]);
    
    model_provenance_gadget<FieldT, N, C, M> provenance_gadget(pb, ds->nrows, "provenance_gadget");
    provenance_gadget.generate_r1cs_constraints();
    provenance_gadget.generate_r1cs_witness(
        cat_features, int_features, target, model_coefficients);

    std::cout << "R2: " << pb.val(provenance_gadget.R2_) << std::endl;
    print_protoboard_info(pb);
    assert(pb.is_satisfied());

    // Generating proof
    r1cs_ppzksnark_proving_key<snark_pp> pkey;
    auto t0 = libff::get_nsec_time();
    std::cout << "Reading proving key: [ " << t0/1000000000 << " ]" << std::endl;
    std::ifstream ifile(pkey_file);
    ifile >> pkey;
    t0 = libff::get_nsec_time();
    std::cout << "Finished deserializing proving key: [ " << t0/1000000000 << " ]" << std::endl;
    auto proof = r1cs_ppzksnark_prover<snark_pp>(pkey, pb.primary_input(), pb.auxiliary_input());
    t0 = libff::get_nsec_time();
    std::cout << "Finished proof generation: [ " << t0/1000000000 << " ]" << std::endl;

    // Write the proof to file 
    std::ofstream ofile(output_file);
    std::stringstream proofstr;
    proofstr << proof;

    YAML::Emitter yout;
    yout << YAML::BeginMap;
    yout << YAML::Key << "R2" << YAML::Value << double(pb.val(provenance_gadget.R2_).as_ulong())/float_precision_safe;
    yout << YAML::Key << "Proof" << YAML::Value << proofstr.str();
    yout << YAML::EndMap;

    ofile << yout.c_str();
    ofile.close();

}


/**
 * This function generates proof of scoring from
 * a lineare model (model_file, model_schema) on
 * batch data (data_file, data_schema). We make some assumptions
 * on the format of data.
 * If data has fewer than M integer columns, all-zero columns are
 * appended. The model coefficients should be set to 0 for those
 * columns.
 * (1) Categorical columns explicitly do not take part in prediction,
 * if desired, they must be encoded to numeric columns. 
 * @returns scores for each row
 */
std::vector<double>
generate_inference_proof(
    const std::string& pkey_file,
    const std::string& data_schema_file,
    const std::string& data_file,
    const std::string& model_schema_file,
    const std::string& model_file,
    const std::string& output_file)
{
    snark_pp::init_public_params();
    protoboard<FieldT> pb;

    (void) pkey_file;
    auto sc_data = read_schema_descriptor(data_schema_file);
    auto ds = read_dataset(data_file, sc_data);
    std::cout << ds->nrows << " " << ds->ncols << std::endl; 
    // view model as dataset with one numeric column
    auto sc_model = read_schema_descriptor(model_schema_file);
    auto m_coeff = read_dataset(model_file, sc_model);
    
    std::vector<std::vector<uint64_t>> cat_features, int_features;
    std::vector<double> model_coefficients = m_coeff->numeric_matrix[0];

    auto dhandle = compute_data_handle(ds);
    // convert categorical columns to numeric columns using the
    // levels map
    for(size_t i=0; i < ds->catColNames.size(); ++i) {
        auto col = ds->categorical_matrix[i];
        auto colName = ds->catColNames[i];
        cat_features.emplace_back(apply_levels(col, dhandle->levels_map[colName]));
    }

    // regard all integer columns as features
    for(size_t i=0; i < ds->intColNames.size(); ++i)
         int_features.emplace_back(ds->integer_matrix[i]);

    // suitably extend the matrices
    cat_features.resize(C, std::vector<uint64_t>(B, 0));
    int_features.resize(M, std::vector<uint64_t>(B, 0));
    
    model_inference_gadget<FieldT, B, C, M> inference_gadget(pb, ds->nrows, "inference_gadget");
    inference_gadget.generate_r1cs_constraints();
    inference_gadget.generate_r1cs_witness(
        cat_features, int_features, model_coefficients);

    print_protoboard_info(pb);
    assert(pb.is_satisfied());
    assert(pb.primary_input().size() == (B*M+B+2));

    // Generating proof
    r1cs_ppzksnark_proving_key<snark_pp> pkey;
    auto t0 = libff::get_nsec_time();
    std::cout << "Reading proving key: [ " << t0/1000000000 << " ]" << std::endl;
    std::ifstream ifile(pkey_file);
    ifile >> pkey;
    t0 = libff::get_nsec_time();
    std::cout << "Finished deserializing proving key: [ " << t0/1000000000 << " ]" << std::endl;
    auto proof = r1cs_ppzksnark_prover<snark_pp>(pkey, pb.primary_input(), pb.auxiliary_input());
    t0 = libff::get_nsec_time();
    std::cout << "Finished proof generation: [ " << t0/1000000000 << " ]" << std::endl;
    // Write the proof to file 
    std::ofstream ofile(output_file);
    std::stringstream proofstr;
    proofstr << proof;

    std::vector<double> scores;
    for(size_t i=0; i < B; ++i) {
        scores.emplace_back(double(pb.primary_input()[B*M+i].as_ulong())/float_precision_safe);
    }

    auto model_hash = compute_model_hash(model_coefficients);
    YAML::Emitter yout;
    yout << YAML::BeginMap;
    yout << YAML::Key << "ModelHash" << YAML::Value << model_hash;
    yout << YAML::Key << "Predictions";
    yout << YAML::Value << scores;
    yout << YAML::Key << "Proof" << YAML::Value << proofstr.str();
    yout << YAML::EndMap;

    ofile << yout.c_str();

    return scores;
}

/**
 * Verify the provenance of linear model performance claim
 * on a dataset. 
 * @input data_handle_file path to datahandle descriptor file
 * @input model_hash hash of the linear model
 * @input R2 Rsquared accuracy claimed on the dataset
 * @input proof_file path to file containing the proof
 */
bool verify_model_provenance_proof(
    const std::string& vkey_file,           // verification key file
    const std::string& data_handle_file,    // data handle for data
    const std::string& model_hash,          // hash of the model
    const double R2,                        // claimed performance
    const std::string& proof_file) // proof
{
    snark_pp::init_public_params();
    protoboard<FieldT> pb;

    auto dhandle = read_data_handle(data_handle_file);
    std::vector<FieldT> catHashes, intHashes;
    uint64_t intR2 = (R2 * float_precision_safe);
    // read the column hashes
    for(size_t i=0; i < dhandle->categorical_features.size(); ++i) {
        auto col_hash = std::get<1>(dhandle->categorical_features[i]);
        mpz_class cHash(col_hash, 16);
        FieldT hash(libff::bigint<FieldT::num_limbs>(cHash.get_mpz_t()));
        catHashes.emplace_back(hash);
    }

    for(size_t i=0; i < dhandle->integer_features.size(); ++i) {
        auto col_hash = std::get<1>(dhandle->integer_features[i]);
        mpz_class iHash(col_hash, 16);
        FieldT hash(libff::bigint<FieldT::num_limbs>(iHash.get_mpz_t()));
        intHashes.emplace_back(hash);
    }
    // convert model hash to field element
    mpz_class mHash(model_hash, 16); // 16 is the base
    FieldT hash(libff::bigint<FieldT::num_limbs>(mHash.get_mpz_t()));
    
    std::vector<FieldT> primary_input;
    primary_input.insert(primary_input.end(), catHashes.begin(), catHashes.end());
    primary_input.insert(primary_input.end(), intHashes.begin(), intHashes.end());
    primary_input.emplace_back(hash);
    primary_input.emplace_back(FieldT(intR2));
    
    r1cs_ppzksnark_verification_key<snark_pp> vkey;
    std::ifstream ifile(vkey_file);
    ifile >> vkey;
    ifile.close();
    
    r1cs_ppzksnark_proof<snark_pp> proof;
    std::ifstream pfile(proof_file);
    pfile >> proof;
    
    bool ret = r1cs_ppzksnark_verifier_strong_IC<snark_pp>(vkey, primary_input, proof);
    std::string status = (ret)?"OK":"FAIL";
    std::cout << "Proof Verification Status [ " << status << " ]" << std::endl;
    return ret;
}

bool verify_inference_proof(
    const std::string& vkey_file,
    const std::string& data_schema_file,
    const std::string& data_file,
    const std::string& scores_schema_file,
    const std::string& scores_file,
    const std::string& model_hash,
    const std::string& proof_file)
{
    snark_pp::init_public_params();
    protoboard<FieldT> pb;

    auto sc_data = read_schema_descriptor(data_schema_file);
    auto ds = read_dataset(data_file, sc_data);
    std::cout << ds->nrows << " " << ds->ncols << std::endl; 
    
    auto sc_scores = read_schema_descriptor(scores_schema_file);
    auto scores = read_dataset(scores_file, sc_scores);
    std::cout << scores->nrows << " " << scores->ncols << std::endl;

    std::vector<std::vector<uint64_t>> cat_features, int_features;
    std::vector<double> scores_vec;

    auto dhandle = compute_data_handle(ds);
    // convert categorical columns to numeric columns using the
    // levels map
    for(size_t i=0; i < ds->catColNames.size(); ++i) {
        auto col = ds->categorical_matrix[i];
        auto colName = ds->catColNames[i];
        auto col1 = apply_levels(col, dhandle->levels_map[colName]);
        col1.resize(B, 0);
        cat_features.emplace_back(col1);
    }

    // regard all integer columns as features
    for(size_t i=0; i < ds->intColNames.size(); ++i) {
        auto col = ds->integer_matrix[i];
        col.resize(B, 0);
        int_features.emplace_back(col);
    }

    // suitably extend the matrices
    cat_features.resize(C, std::vector<uint64_t>(B, 0));
    int_features.resize(M, std::vector<uint64_t>(B, 0));

    // read the scores
    scores_vec = scores->numeric_matrix[0];
    scores_vec.resize(B, 0);
    
    std::vector<FieldT> primary_input;
    for(size_t i=0; i < B; ++i)
        for(size_t j=0; j < M; ++j)
            primary_input.emplace_back(int_features[j][i]);

    for(size_t i=0; i < B; ++i) {
        uint64_t sval = scores_vec[i] * float_precision_safe;
        primary_input.emplace_back(sval);
    }

    // convert hash string to FieldT element
    mpz_class mHash(model_hash, 16);
    FieldT hash(libff::bigint<FieldT::num_limbs>(mHash.get_mpz_t()));
    primary_input.emplace_back(hash);
    
    // finally add the batch size
    primary_input.emplace_back(ds->nrows);
    
    r1cs_ppzksnark_verification_key<snark_pp> vkey;
    std::ifstream ifile(vkey_file);
    ifile >> vkey;
    ifile.close();
    
    r1cs_ppzksnark_proof<snark_pp> proof;
    std::ifstream pfile(proof_file);
    pfile >> proof;

    assert(primary_input.size() == (B*M+B+2));

    bool ret = r1cs_ppzksnark_verifier_strong_IC<snark_pp>(vkey, primary_input, proof);
    std::string status = (ret)?"OK":"FAIL";
    std::cout << "Proof Verification Status [ " << status << " ]" << std::endl;
    return ret;
}
   
void process_options(std::map<std::string, std::string>& opts)
{

    const std::string config_dir = getenv("TRUSTED_AI_CRYPTO_CONFIG_DIR");
    const std::string pkey_prov_file = config_dir + "/model_prov.pk";
    const std::string vkey_prov_file = config_dir + "/model_prov.vk";
    const std::string pkey_inf_file = config_dir + "/model_inf.pk";
    const std::string vkey_inf_file = config_dir + "/model_inf.vk";
    const std::string model_schema_file = config_dir + "/model_schema.yaml";
    const std::string scores_schema_file = config_dir + "/scores_schema.yaml";
    
    if (opts.find("gen-handle") != opts.end()) {
        // generate data handle
        auto data_schema_file = opts["data-schema"];
        auto data_file = opts["data-file"];
        auto output_file = opts["output"];
        std::cout << data_schema_file << " " << data_file << " " << output_file << std::endl;
        auto sd = read_schema_descriptor(data_schema_file);
        if (sd == nullptr) {
            std::cerr << "Failed to read schema";
            exit(1);
        }
        auto ds = read_dataset(data_file, sd);
        if (ds == nullptr) {
            std::cerr << "Failed to read dataset";
            exit(1);
        }

        auto dhandle = compute_data_handle(ds);
        std::ofstream outfile(output_file);
        dhandle->print(outfile);
        outfile.close();
        return;
    }

    if (opts.find("compute-hash") != opts.end()) {
        // compute model hash
        auto model_file = opts["model-file"];
        auto output_file = opts["output"];
        auto msd = read_schema_descriptor(model_schema_file);
        if (msd == nullptr) {
            std::cerr << "Failed to read model schema:";
            exit(1);
        }
        auto model = read_dataset(model_file, msd);
        if (model == nullptr) {
            std::cerr << "Failed to read the model";
            exit(1);
        }
        auto model_hash = compute_model_hash(model->numeric_matrix[0]);
        std::ofstream outfile(output_file);
        outfile << model_hash;
        outfile.close();
        return;
    }

    if (opts.find("prove-performance") != opts.end()) {
        // generate performance proof
        auto data_schema_file = opts["data-schema"];
        auto data_file = opts["data-file"];
        auto model_file = opts["model-file"];
        auto output_file = opts["output"];
        generate_performance_proof(pkey_prov_file,
            data_schema_file,
            data_file,
            model_schema_file,
            model_file,
            output_file);
        return; 
    } 
    
    if (opts.find("prove-inference") != opts.end()) {
        // generate inference proof
        auto data_schema_file = opts["data-schema"];
        auto data_file = opts["data-file"];
        auto model_file = opts["model-file"];
        auto output_file = opts["output"];
        (void) generate_inference_proof(pkey_inf_file,
            data_schema_file,
            data_file,
            model_schema_file,
            model_file,
            output_file);
        return;
    }

    if (opts.find("verify-performance") != opts.end()) {
        auto data_handle_file = opts["data-handle"];
        auto model_hash = opts["model-hash"];
        double R2 = std::stod(opts["r2"], NULL);
        auto proof_file = opts["proof"]; 
        bool ret = verify_model_provenance_proof(
            vkey_prov_file,
            data_handle_file,
            model_hash,
            R2,
            proof_file);

        if (ret)
            exit(0);
        else
            exit(1);
    
    }

    if (opts.find("verify-inference") != opts.end()) {
        auto data_schema_file = opts["data-schema"];
        auto data_file = opts["data-file"];
        auto scores_file = opts["predictions"];
        auto model_hash = opts["model-hash"];
        auto proof_file = opts["proof"];

        bool ret = verify_inference_proof(
            vkey_inf_file,
            data_schema_file,
            data_file,
            scores_schema_file,
            scores_file,
            model_hash,
            proof_file);

        if (ret)
            exit(0);
        else
            exit(1);
    }
            

}

void print_usage()
{
    std::cout << "Usage patterns for the utility:" << std::endl;
    std::cout << "Generate Datahandle:" << std::endl;
    std::cout << "--gen-handle --data-schema <data_schema_file> --data-file <data_file> --output <data_handle_file>" << std::endl << std::endl;
    std::cout << "Compute Model Hash:" << std::endl;
    std::cout << "--compute-hash --model-file <model_file> --output <model_hash_file>" << std::endl << std::endl;
    std::cout << "Prove Model Performance:" << std::endl;
    std::cout << "--prove-performance --data-schema <data_schema_file> --data-file <data_file> --model-file <model_file> --output <proof_file>" << std::endl << std::endl;
    std::cout << "Prove Model Inference:" << std::endl;
    std::cout << "--prove-inference --data-schema <batch_schema> --data-file <batch_file> --model-file <model_file> --output <predictions_proof_file>" << std::endl << std::endl;
    std::cout << "Verify Performance:" << std::endl;
    std::cout << "--verify-performance --data-handle <data_handle_file> --model-hash <model_hash> --r2 <r2_metric> --proof <proof_file>" << std::endl << std::endl;
    std::cout << "--verify-inference --data-schema <batch_schema> --data-file <batch_file> --predictions <predictions_file> --model-hash <model_hash> --proof <proof_file>" << std::endl;  
}

void process_cmd_options(int argc, char *argv[])
{
    const struct option longopts[] = {
        {"gen-handle",          no_argument,            0,      'g'},
        {"compute-hash",        no_argument,            0,      'c'},
        {"prove-performance",   no_argument,            0,      'p'},
        {"prove-inference",     no_argument,            0,      'i'},
        {"verify-performance",  no_argument,            0,      'v'},
        {"verify-inference",    no_argument,            0,      'w'},
        {"data-schema",         required_argument,      0,      's'},
        {"data-file",           required_argument,      0,      'f'},
        {"model-file",          required_argument,      0,      'm'},
        {"model-hash",          required_argument,      0,      'h'},
        {"data-handle",         required_argument,      0,      'd'},
        {"output",              required_argument,      0,      'o'},
        {"proof",               required_argument,      0,      'z'},
        {"r2",                  required_argument,      0,      'r'},
        {"predictions",         required_argument,      0,      'q'},
        {0, 0, 0, 0}
    };

    if (argc == 1) {
        print_usage();
        return;
    }

    // usage patterns
    // progname --gen-handle --data-schema <schema_file> --data-file <data-file> --output <output-file>
    // progname --compute-hash --model-file <model_file> --output <output-file>
    // progname --prove-performance --data-schema <schema_fiel> --data-file <data-file> 
    //      --model-file <model_file> --output <output>
    // progname --prove-inference --data-schema <schema_file> --data-file <data-file> --model-file <mode_file> --output <output>
    // progname --verify-performance --data-handle <data_handle> --model-hash <model_hash> --r2 <r2> --proof <proof_file>
    // progname --verify-inference  --model-hash <model_hash> --data-schema <data_schema> --data-file <data_file> 
    //      --predictions <predictions_file> --proof <proof_file>
    
 
    int index;
    int iarg=0;
    std::map<std::string, std::string> options_map;

    while(iarg != -1)
    {
        iarg = getopt_long(argc, argv, "gcpivws:f:m:h:d:o:z:r:", longopts, &index);
        switch(iarg)
        {
            case 'g':
                options_map["gen-handle"]="";
                break;
            case 'c':
                options_map["compute-hash"]="";
                break;
            case 'p':
                options_map["prove-performance"]="";
                break;
            case 'i':
                options_map["prove-inference"]="";
                break;
            case 'v':
                options_map["verify-performance"]="";
                break;
            case 'w':
                options_map["verify-inference"]="";
                break;
            case 's':
                options_map["data-schema"] = optarg;
                break;
            case 'f':
                options_map["data-file"] = optarg;
                break;
            case 'm':
                options_map["model-file"] = optarg;
                break;
            case 'h':
                options_map["model-hash"] = optarg;
                break;
            case 'd':
                options_map["data-handle"] = optarg;
                break;
            case 'o':
                options_map["output"] = optarg;
                break;
            case 'z':
                options_map["proof"] = optarg;
                break;
            case 'r':
                options_map["r2"] = optarg;
                break;
            case 'q':
                options_map["predictions"] = optarg;
                break;
        }  
    }

    process_options(options_map);
}
      
     

int main(int argc, char *argv[])
{
    const std::string test_data_dir = "/home/nitin/trustedAITestData";
    const std::string model_schema = test_data_dir + "/model_schema.yaml";
    const std::string model_file = test_data_dir + "/LinearModel.csv";
    const std::string data_schema = test_data_dir + "/housing_schema.yaml";
    const std::string data_file = test_data_dir + "/HousingData1K.dat";
    const std::string batch_data_file = test_data_dir + "/TestData.dat";
    const std::string batch_schema_file = test_data_dir + "/test_data_schema.yaml";
    const std::string data_handle_file = test_data_dir + "/housingDataHandle.yaml";
    const std::string score_schema_file = test_data_dir + "/scores_schema.yaml";
    const std::string score_file = test_data_dir + "/TestDataPredictions.csv";
    const std::string pkey_prov_file = test_data_dir + "/model_prov.pk";
    const std::string vkey_prov_file = test_data_dir + "/model_prov.vk";
    const std::string pkey_inf_file = test_data_dir + "/model_inf.pk";
    const std::string vkey_inf_file = test_data_dir + "/model_inf.vk";
    
    process_cmd_options(argc, argv);
    //generate_model_inference_keys(pkey_inf_file, vkey_inf_file);
    //generate_model_provenance_keys(pkey_prov_file, vkey_prov_file);
    //generate_performance_proof(pkey_prov_file, data_schema, data_file, model_schema, model_file, "proof.yaml");
    //generate_model_provenance_keys(argv[1], argv[2]);
    //auto scores = generate_inference_proof(pkey_inf_file, batch_schema_file,
    //    batch_data_file, model_schema, model_file;
    //auto sd = read_schema_descriptor(model_schema);
    //auto model = read_dataset(model_file, sd);
    //auto model_hash = compute_model_hash(model->numeric_matrix[0]);
    //std::cout << "Model Hash: " << model_hash << std::endl;
    //verify_model_provenance_proof(vkey_file, argv[1], argv[2], std::atof(argv[3]), argv[4]);
    //verify_model_provenance_proof(vkey_prov_file, data_handle_file, model_hash, 0.81, "./proof-inf.dat");
    //std::cout << "Predictions:" << std::endl;    
    //for(size_t i=0; i < scores.size(); ++i)
    //    std::cout << scores[i] << std::endl;
    
    
    /*
    verify_inference_proof(vkey_inf_file,
        batch_schema_file,
        batch_data_file,
        score_schema_file,
        score_file,
        "7c6f43fbadf17730852a74f1a4356fc5ba4b762f13555",
        "./proof_inf.dat");
    */
    return 0;
}
 
