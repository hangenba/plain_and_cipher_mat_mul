#include"../src/plain_and_cipher_mat_mul.h"

using namespace std;
using namespace seal;

void Cipher_plain_mul_example(){
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60,40,40,60 }));
    double scale = pow(2.0, 40);
    std::size_t matrix_rows_A=4;
    std::size_t matrix_cols_A=4;
    std::size_t matrix_rows_B=4;
    std::size_t matrix_cols_B=4;

    // create SEAL keys
    SEALContext context(parms);
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    print_parameters(context);

    std::cout<<"Matrix("<<matrix_rows_A<<"×"<<matrix_cols_A<<")×("<<matrix_rows_B<<"×"<<matrix_cols_B<<")"<<std::endl;
    matrix<double> A(matrix_rows_A, matrix_cols_A),B(matrix_rows_B, matrix_cols_B),C;
    vector<double> flat_a, flat_b;
    std::cout<<"Matrix A:"<<std::endl;
    A.generate_randon_data();
    A.print(4, 4);
    std::cout<<"Matrix B:"<<std::endl;
    B.generate_randon_data();
    B.print(4, 4);
    flat_b = B.flatten_matrix_to_cols_vector();
    // print_vector(flat_b);
    std::cout<<"Matrix C:"<<std::endl;
    C=A*B;
    C.print(4,4);

    //step1. Encrypte matrix data
    seal::Ciphertext matrix_b,matrix_change_b,matrix_c;
    encrypt_data(flat_b,scale, matrix_b, encoder, encryptor);

    //step2.preparing plain matrix A and cipher matrix B
    vector<vector<double>> encode_matrix_a;
    bool change_B_flag=false;
    change_row_and_resize(matrix_rows_A,matrix_cols_A,matrix_rows_B,matrix_cols_B,A,encode_matrix_a,change_B_flag);
    if(change_B_flag){
        // cout<<"     Change matrix B rows"<<endl;
        change_row_length(matrix_b,matrix_change_b,matrix_rows_B,matrix_rows_A,matrix_cols_B,evaluator,encoder,gal_keys,relin_keys);
        matrix_cols_A=matrix_rows_A;
        matrix_rows_B=matrix_rows_A;
        Multiply_plain_and_cipher(encode_matrix_a,matrix_change_b,matrix_rows_B,matrix_cols_B,0,scale,matrix_c,parms,evaluator,encoder,gal_keys,relin_keys,decryptor);
    }
    else{
        // cout<<"     No need for changing matrix B rows"<<endl;
        matrix_change_b=matrix_b;
        int step=matrix_cols_A-matrix_rows_A;
        matrix_rows_A=matrix_cols_A;
        // cout<<"step:"<<step<<endl;
        Multiply_plain_and_cipher(encode_matrix_a,matrix_change_b,matrix_rows_B,matrix_cols_B,step,scale,matrix_c,parms,evaluator,encoder,gal_keys,relin_keys,decryptor);
    }
    decrypte_result(matrix_c,decryptor,encoder);
}

void Cipher_plain_mul_example(matrix<double> &A,matrix<double> &B){
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60,40,40,60 }));
    double scale = pow(2.0, 40);
    std::size_t matrix_rows_A=A.get_rows();
    std::size_t matrix_cols_A=A.get_cols();
    std::size_t matrix_rows_B=B.get_rows();
    std::size_t matrix_cols_B=B.get_cols();

    // create SEAL keys
    SEALContext context(parms);
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    print_parameters(context);

    std::cout<<"Matrix("<<matrix_rows_A<<"×"<<matrix_cols_A<<")×("<<matrix_rows_B<<"×"<<matrix_cols_B<<")"<<std::endl;
    matrix<double> C;
    vector<double> flat_a, flat_b;
    std::cout<<"Matrix A:"<<std::endl;
    A.print(4, 4);
    std::cout<<"Matrix B:"<<std::endl;
    B.print(4, 4);
    flat_b = B.flatten_matrix_to_cols_vector();
    print_vector(flat_b);
    std::cout<<"Matrix C:"<<std::endl;
    C=A*B;
    C.print(4,4);

    //step1. Encrypte matrix data
    seal::Ciphertext matrix_b,matrix_change_b,matrix_c;
    encrypt_data(flat_b,scale, matrix_b, encoder, encryptor);

    //step2.preparing plain matrix A and cipher matrix B
    vector<vector<double>> encode_matrix_a;
    bool change_B_flag=false;
    change_row_and_resize(matrix_rows_A,matrix_cols_A,matrix_rows_B,matrix_cols_B,A,encode_matrix_a,change_B_flag);
    if(change_B_flag){
        cout<<"     Change matrix B rows"<<endl;
        change_row_length(matrix_b,matrix_change_b,matrix_rows_B,matrix_rows_A,matrix_cols_B,evaluator,encoder,gal_keys,relin_keys);
        matrix_cols_A=matrix_rows_A;
        matrix_rows_B=matrix_rows_A;
        Multiply_plain_and_cipher(encode_matrix_a,matrix_change_b,matrix_rows_B,matrix_cols_B,0,scale,matrix_c,parms,evaluator,encoder,gal_keys,relin_keys,decryptor);
    }
    else{
        cout<<"     No need for changing matrix B rows"<<endl;
        matrix_change_b=matrix_b;
        int step=matrix_cols_A-matrix_rows_A;
        matrix_rows_A=matrix_cols_A;
        // cout<<"step:"<<step<<endl;
        Multiply_plain_and_cipher(encode_matrix_a,matrix_change_b,matrix_rows_B,matrix_cols_B,step,scale,matrix_c,parms,evaluator,encoder,gal_keys,relin_keys,decryptor);
    }
    decrypte_result(matrix_c,decryptor,encoder);
}

void Cipher_plain_mul_example(int n,int m ,int p){
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60,40,40,60 }));
    double scale = pow(2.0, 40);
    std::size_t matrix_rows_A=n;
    std::size_t matrix_cols_A=m;
    std::size_t matrix_rows_B=m;
    std::size_t matrix_cols_B=p;

    // create SEAL keys
    SEALContext context(parms);
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    print_parameters(context);

    std::cout<<"Matrix("<<matrix_rows_A<<"×"<<matrix_cols_A<<")×("<<matrix_rows_B<<"×"<<matrix_cols_B<<")"<<std::endl;
    matrix<double> A(matrix_rows_A, matrix_cols_A),B(matrix_rows_B, matrix_cols_B),C;
    vector<double> flat_a, flat_b;
    std::cout<<"Matrix A:"<<std::endl;
    A.generate_randon_data();
    A.print(4, 4);
    std::cout<<"Matrix B:"<<std::endl;
    B.generate_randon_data();
    B.print(4, 4);
    flat_b = B.flatten_matrix_to_cols_vector();
    // print_vector(flat_b);
    std::cout<<"Matrix C:"<<std::endl;
    C=A*B;
    C.print(4,4);

    //step1. Encrypte matrix data
    seal::Ciphertext matrix_b,matrix_change_b,matrix_c;
    encrypt_data(flat_b,scale, matrix_b, encoder, encryptor);

    //step2.preparing plain matrix A and cipher matrix B
    vector<vector<double>> encode_matrix_a;
    bool change_B_flag=false;
    change_row_and_resize(matrix_rows_A,matrix_cols_A,matrix_rows_B,matrix_cols_B,A,encode_matrix_a,change_B_flag);
    if(change_B_flag){
        // cout<<"     Change matrix B rows"<<endl;
        change_row_length(matrix_b,matrix_change_b,matrix_rows_B,matrix_rows_A,matrix_cols_B,evaluator,encoder,gal_keys,relin_keys);
        matrix_cols_A=matrix_rows_A;
        matrix_rows_B=matrix_rows_A;
        Multiply_plain_and_cipher(encode_matrix_a,matrix_change_b,matrix_rows_B,matrix_cols_B,0,scale,matrix_c,parms,evaluator,encoder,gal_keys,relin_keys,decryptor);
    }
    else{
        // cout<<"     No need for changing matrix B rows"<<endl;
        matrix_change_b=matrix_b;
        int step=matrix_cols_A-matrix_rows_A;
        matrix_rows_A=matrix_cols_A;
        // cout<<"step:"<<step<<endl;
        Multiply_plain_and_cipher(encode_matrix_a,matrix_change_b,matrix_rows_B,matrix_cols_B,step,scale,matrix_c,parms,evaluator,encoder,gal_keys,relin_keys,decryptor);
    }
    decrypte_result(matrix_c,decryptor,encoder);
}

void test_iris_bayes_our(){
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60,40,40,60 }));
    double scale = pow(2.0, 40);
    std::size_t matrix_rows_A=3;
    std::size_t matrix_cols_A=20;
    std::size_t matrix_rows_B=20;
    std::size_t matrix_cols_B=30;
    int true_rows=matrix_rows_A;

    // create SEAL keys
    SEALContext context(parms);
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    print_parameters(context);

    matrix<double> client_matrix(matrix_cols_B, matrix_rows_B),model_matrix(matrix_rows_A, matrix_cols_A);
    vector<double> model_prior,flat_b;

    string filename="../data/Iris";
    string result_dir="../data/result/result_our_iris.txt";
    read_data(client_matrix,filename);
    client_matrix=client_matrix.transpose();
    read_model(model_matrix,filename);
    read_prior(model_prior,filename);

    std::cout<<"Matrix("<<matrix_rows_A<<"×"<<matrix_cols_A<<")×("<<matrix_rows_B<<"×"<<matrix_cols_B<<")"<<std::endl;
    std::cout<<"Model Matrix:"<<std::endl;
    model_matrix.print(4, 4);
    std::cout<<"Client Matrix:"<<std::endl;
    client_matrix.print(4, 4);
    flat_b=client_matrix.flatten_matrix_to_cols_vector();
    // print_vector(flat_b);

    //step1. Encrypte matrix data
    seal::Ciphertext matrix_b,matrix_change_b,matrix_c,result;
    encrypt_data(flat_b,scale, matrix_b, encoder, encryptor);

    //step2.preparing plain matrix A and cipher matrix B
    vector<vector<double>> encode_matrix_a;
    bool change_B_flag=false;
    change_row_and_resize(matrix_rows_A,matrix_cols_A,matrix_rows_B,matrix_cols_B,model_matrix,encode_matrix_a,change_B_flag);
    if(change_B_flag){
        // cout<<"     Change matrix B rows"<<endl;
        change_row_length(matrix_b,matrix_change_b,matrix_rows_B,matrix_rows_A,matrix_cols_B,evaluator,encoder,gal_keys,relin_keys);
        matrix_cols_A=matrix_rows_A;
        matrix_rows_B=matrix_rows_A;
        Multiply_plain_and_cipher(encode_matrix_a,matrix_change_b,matrix_rows_B,matrix_cols_B,0,scale,matrix_c,parms,evaluator,encoder,gal_keys,relin_keys,decryptor);
    }
    else{
        // cout<<"     No need for changing matrix B rows"<<endl;
        matrix_change_b=matrix_b;
        int step=matrix_cols_A-matrix_rows_A;
        matrix_rows_A=matrix_cols_A;
        // cout<<"step:"<<step<<endl;
        Multiply_plain_and_cipher(encode_matrix_a,matrix_change_b,matrix_rows_B,matrix_cols_B,step,scale,matrix_c,parms,evaluator,encoder,gal_keys,relin_keys,decryptor);
    }
    // decrypte_result(matrix_c,decryptor,encoder);
    //add noise and prior
    matrix_add_prior_and_noise(matrix_c,model_prior,matrix_rows_A,matrix_cols_B,result,evaluator,encoder);

    decrypte_bayes_result(result,matrix_rows_A,matrix_cols_B,true_rows,result_dir,decryptor,encoder);
    
}


void Cipher_plain_mul(matrix<double> A,seal::Ciphertext &matrix_b,int matrix_rows_B,int matrix_cols_B,
                      seal::Ciphertext &destination, double scale,seal::EncryptionParameters &parms,
                      seal::CKKSEncoder &encoder,seal::Encryptor &encryptor,seal::Evaluator &evaluator,
                      seal::RelinKeys &relin_keys,seal::GaloisKeys &gal_keys,seal::Decryptor &decryptor,
                      double &elapsed_time)
{
    int matrix_rows_A=A.get_rows();
    int matrix_cols_A=A.get_cols();
    
    //step1. Encrypte matrix data
    seal::Ciphertext matrix_change_b,matrix_c;

    //step2.preparing plain matrix A and cipher matrix B
    vector<vector<double>> encode_matrix_a;
    bool change_B_flag=false;
    change_row_and_resize(matrix_rows_A,matrix_cols_A,matrix_rows_B,matrix_cols_B,A,encode_matrix_a,change_B_flag);
    if(change_B_flag){
        // cout<<"     Change matrix B rows"<<endl;
        change_row_length(matrix_b,matrix_change_b,matrix_rows_B,matrix_rows_A,matrix_cols_B,evaluator,encoder,gal_keys,relin_keys);
        matrix_cols_A=matrix_rows_A;
        matrix_rows_B=matrix_rows_A;
        Multiply_plain_and_cipher(encode_matrix_a,matrix_change_b,matrix_rows_B,matrix_cols_B,0,scale,matrix_c,parms,evaluator,encoder,gal_keys,relin_keys,decryptor,elapsed_time);
    }
    else{
        // cout<<"     No need for changing matrix B rows"<<endl;
        matrix_change_b=matrix_b;
        int step=matrix_cols_A-matrix_rows_A;
        matrix_rows_A=matrix_cols_A;
        //cout<<"step:"<<step<<endl;
        Multiply_plain_and_cipher(encode_matrix_a,matrix_change_b,matrix_rows_B,matrix_cols_B,step,scale,matrix_c,parms,evaluator,encoder,gal_keys,relin_keys,decryptor,elapsed_time);
    }
    // decrypte_result(matrix_c,decryptor,encoder);
    destination=matrix_c;
}

void test_WBC_bayes_our(){
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60,40,40,60 }));
    double scale = pow(2.0, 40);
    std::size_t matrix_rows_A=2;
    std::size_t matrix_cols_A=90;
    std::size_t matrix_rows_B=90;
    std::size_t matrix_cols_B=205;
    std::size_t sub_col=22;
    int true_rows=matrix_rows_A;

    // create SEAL keys
    SEALContext context(parms);
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    print_parameters(context);

    matrix<double> client_matrix(matrix_cols_B, matrix_rows_B),model_matrix(matrix_rows_A, matrix_cols_A);
    vector<double> model_prior,flat_b;

    string filename="../data/WBC";
    string result_dir="../data/result/result_our_WBC.txt";
    const char* result_file=result_dir.c_str();
    std::remove(result_file);

    read_data(client_matrix,filename);
    client_matrix=client_matrix.transpose();
    read_model(model_matrix,filename);
    read_prior(model_prior,filename);

    split_matrix<double> split_B(client_matrix,matrix_rows_B,sub_col);

    seal::Ciphertext tmp,result;
    vector<seal::Ciphertext> matrix_b_vector,matrix_c_vector;
    double elapsed_time=0,size=0;
    for(int i=0;i<split_B.get_cols();i++){
        matrix<double> matrix_tmp=split_B.get_submatrix(0,i);
        flat_b=matrix_tmp.flatten_matrix_to_cols_vector();
        encrypt_data(flat_b,scale,tmp,encoder,encryptor,elapsed_time,size);
        matrix_b_vector.push_back(tmp);
    }
    print_line(__LINE__);
    cout<<"Encrypte Data"<<endl;
    cout << "        + time:" << elapsed_time << " μs" << endl;
    cout << "        + size:" << size / 1024 << " KB" << endl;

    elapsed_time=0;
    for(std::size_t i=0;i<matrix_b_vector.size();i++){
        Cipher_plain_mul(model_matrix,matrix_b_vector[i],matrix_rows_B,sub_col,tmp,scale,parms,encoder,encryptor,evaluator,relin_keys,gal_keys,decryptor,elapsed_time);
        matrix_rows_A=matrix_cols_A;
        matrix_c_vector.push_back(tmp);
    }
    print_line(__LINE__);
    cout<<"Plain Matrix Multiply Cipher Matrix"<<endl;
    cout << "        + time:" << elapsed_time/1000 << " ms" << endl;

    elapsed_time=0;
    for(std::size_t i=0;i<matrix_c_vector.size();i++){
        matrix_add_prior_and_noise(matrix_c_vector[i],model_prior,matrix_rows_A,sub_col,result,evaluator,encoder);
        decrypte_bayes_result(result,matrix_rows_A,sub_col,true_rows,result_dir,decryptor,encoder,elapsed_time);
    }
    print_line(__LINE__);
    cout<<"Decrypte Result"<<endl;
    cout << "        + time:" << elapsed_time << " μs" << endl;
}


void Jiang_example(){
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60,40,40,60 }));
    double scale = pow(2.0, 40);
    int matrix_cols = 4;
    int matrix_rows = 4;

    // create SEAL keys
    SEALContext context(parms);
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    print_parameters(context);
    //step0. generate two matrix
    matrix<double> A(matrix_rows, matrix_cols),B(matrix_rows, matrix_cols),C;
    vector<double> jiang_a,flat_b;
    vector<vector<double>> A_diag_matrix;
    std::cout<<"Matrix("<<matrix_rows<<"×"<<matrix_cols<<")×("<<matrix_rows<<"×"<<matrix_cols<<")"<<std::endl;
    std::cout<<"Matrix A:"<<std::endl;
    A.generate_randon_data();
    A.print(4, 4);
    std::cout<<"Matrix B:"<<std::endl;
    B.generate_randon_data();
    B.print(4, 4);
    flat_b = B.flatten_matrix_to_rows_vector();
    // print_vector(flat_b);
    std::cout<<"Matrix C:"<<std::endl;
    C=A*B;
    C.print(4,4);

    

    //step1. Encrypte matrix data
    Ciphertext matrix_b,matrix_change_b,matrix_c;
    encrypt_data(flat_b,scale, matrix_b, encoder, encryptor);
    //step2. change matrix ct.B to ct.B(0)
    change_matrix_B(matrix_b, matrix_change_b, matrix_rows, matrix_cols, parms, evaluator, gal_keys, relin_keys, decryptor, encoder);
    //step3. starting matrix multiply
    plain_matrix_multiply_cipher_matrix(A, matrix_change_b, matrix_rows, matrix_cols, matrix_c,scale, parms, evaluator, gal_keys, relin_keys, decryptor, encoder);
    //step6. decrypte matrix C result
    decrypte_result(matrix_c, decryptor, encoder);
}

void Jiang_example(matrix<double> &A,matrix<double> &B){
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60,40,40,60 }));
    double scale = pow(2.0, 40);

    // create SEAL keys
    SEALContext context(parms);
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    print_parameters(context);

    //step0. generate two matrix
    int col_sizeA=A.get_cols();
    int col_sizeB=B.get_cols();
    int row_sizeA=A.get_rows();
    int row_sizeB=B.get_rows();
    int max_matrix_size=std::max(std::max(col_sizeA,col_sizeB),std::max(row_sizeA,row_sizeB));

    if (max_matrix_size>=1 && max_matrix_size<=4){
        matrix<double> C;
        vector<double> flat_a, flat_b;
        std::size_t max_size=4;
        A.resize(max_size,max_size);
        B.resize(max_size,max_size);
        std::cout<<"Matrix("<<max_size<<"×"<<max_size<<")×("<<max_size<<"×"<<max_size<<")"<<std::endl;
        std::cout<<"Matrix A:"<<std::endl;
        A.print(4, 4);
        std::cout<<"Matrix B:"<<std::endl;
        B.print(4, 4);
        flat_b = B.flatten_matrix_to_rows_vector();
        // print_vector(flat_b);
        std::cout<<"Matrix C:"<<std::endl;
        C=A*B;
        C.print(4,4);
        //step1. Encrypte matrix data
        Ciphertext matrix_b,matrix_change_b,matrix_c;
        encrypt_data(flat_b,scale, matrix_b, encoder, encryptor);
        //step2. change matrix ct.B to ct.B(0)
        change_matrix_B(matrix_b, matrix_change_b, max_size, max_size, parms, evaluator, gal_keys, relin_keys, decryptor, encoder);
        //step3. starting matrix multiply
        plain_matrix_multiply_cipher_matrix(A, matrix_change_b, max_size, max_size, matrix_c,scale, parms, evaluator, gal_keys, relin_keys, decryptor, encoder);
        //step4. decrypte matrix C result
        decrypte_result(matrix_c, decryptor, encoder);
    }
    else if (max_matrix_size>4 && max_matrix_size<=16)
    {
        matrix<double> C;
        vector<double> flat_a, flat_b;
        std::size_t max_size=16;
        A.resize(max_size,max_size);
        B.resize(max_size,max_size);
        std::cout<<"Matrix("<<max_size<<"×"<<max_size<<")×("<<max_size<<"×"<<max_size<<")"<<std::endl;
        std::cout<<"Matrix A:"<<std::endl;
        A.print(4, 4);
        std::cout<<"Matrix B:"<<std::endl;
        B.print(4, 4);
        flat_b = B.flatten_matrix_to_rows_vector();
        // print_vector(flat_b);
        std::cout<<"Matrix C:"<<std::endl;
        C=A*B;
        C.print(4,4);
        //step1. Encrypte matrix data
        Ciphertext matrix_a,matrix_b,matrix_change_b,matrix_change_a,matrix_c;
        encrypt_data(flat_b,scale, matrix_b, encoder, encryptor);
        //step2. change matrix ct.B to ct.B(0)
        change_matrix_B(matrix_b, matrix_change_b, max_size, max_size, parms, evaluator, gal_keys, relin_keys, decryptor, encoder);
        //step3. starting matrix multiply
        plain_matrix_multiply_cipher_matrix(A, matrix_change_b, max_size, max_size, matrix_c,scale, parms, evaluator, gal_keys, relin_keys, decryptor, encoder);
        //step4. decrypte matrix C result
        decrypte_result(matrix_c, decryptor, encoder);
    }
    else if (max_matrix_size>16 && max_matrix_size<=64)
    {
        matrix<double> C;
        vector<double> flat_a, flat_b;
        std::size_t max_size=64;
        A.resize(max_size,max_size);
        B.resize(max_size,max_size);
        std::cout<<"Matrix("<<max_size<<"×"<<max_size<<")×("<<max_size<<"×"<<max_size<<")"<<std::endl;
        std::cout<<"Matrix A:"<<std::endl;
        A.print(4, 4);
        std::cout<<"Matrix B:"<<std::endl;
        B.print(4, 4);
        flat_b = B.flatten_matrix_to_rows_vector();
        // print_vector(flat_b);
        std::cout<<"Matrix C:"<<std::endl;
        C=A*B;
        C.print(4,4);
        //step1. Encrypte matrix data
        Ciphertext matrix_b,matrix_change_b,matrix_c;
        encrypt_data(flat_b,scale, matrix_b, encoder, encryptor);
        //step2. change matrix ct.B to ct.B(0)
        change_matrix_B_version64(matrix_b, matrix_change_b, max_size, max_size, parms, evaluator, gal_keys, relin_keys, decryptor, encoder);
        //step5. starting matrix multiply
        plain_matrix_multiply_cipher_matrix_version64(A, matrix_change_b, max_size, max_size, matrix_c,scale, parms, evaluator, gal_keys, relin_keys, decryptor, encoder);
        //step6. decrypte matrix C result
        decrypte_result(matrix_c, decryptor, encoder);
    }
    else{
        std::cout<<" Matrix exceeds dimension."<<std::endl;
    }
    
}

void Jiang_example(int n,int m ,int p){
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60,40,40,60 }));
    double scale = pow(2.0, 40);

    // create SEAL keys
    SEALContext context(parms);
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    print_parameters(context);

    //step0. generate two matrix
    int row_sizeA=n;
    int col_sizeA=m;
    int row_sizeB=m;
    int col_sizeB=p;
    int max_matrix_size=std::max(std::max(col_sizeA,col_sizeB),std::max(row_sizeA,row_sizeB));

    matrix<double> A(row_sizeA, col_sizeA),B(row_sizeB, col_sizeB);
    A.generate_randon_data();
    B.generate_randon_data();


    if (max_matrix_size>=1 && max_matrix_size<=4){
        matrix<double> C;
        vector<double> flat_a, flat_b;
        std::size_t max_size=4;
        A.resize(max_size,max_size);
        B.resize(max_size,max_size);
        std::cout<<"Matrix("<<max_size<<"×"<<max_size<<")×("<<max_size<<"×"<<max_size<<")"<<std::endl;
        std::cout<<"Matrix A:"<<std::endl;
        A.print(4, 4);
        std::cout<<"Matrix B:"<<std::endl;
        B.print(4, 4);
        flat_b = B.flatten_matrix_to_rows_vector();
        // print_vector(flat_b);
        std::cout<<"Matrix C:"<<std::endl;
        C=A*B;
        C.print(4,4);
        //step1. Encrypte matrix data
        Ciphertext matrix_b,matrix_change_b,matrix_c;
        encrypt_data(flat_b,scale, matrix_b, encoder, encryptor);
        //step2. change matrix ct.B to ct.B(0)
        change_matrix_B(matrix_b, matrix_change_b, max_size, max_size, parms, evaluator, gal_keys, relin_keys, decryptor, encoder);
        //step3. starting matrix multiply
        plain_matrix_multiply_cipher_matrix(A, matrix_change_b, max_size, max_size, matrix_c,scale, parms, evaluator, gal_keys, relin_keys, decryptor, encoder);
        //step4. decrypte matrix C result
        decrypte_result(matrix_c, decryptor, encoder);
    }
    else if (max_matrix_size>4 && max_matrix_size<=16)
    {
        matrix<double> C;
        vector<double> flat_a, flat_b;
        std::size_t max_size=16;
        A.resize(max_size,max_size);
        B.resize(max_size,max_size);
        std::cout<<"Matrix("<<max_size<<"×"<<max_size<<")×("<<max_size<<"×"<<max_size<<")"<<std::endl;
        std::cout<<"Matrix A:"<<std::endl;
        A.print(4, 4);
        std::cout<<"Matrix B:"<<std::endl;
        B.print(4, 4);
        flat_b = B.flatten_matrix_to_rows_vector();
        // print_vector(flat_b);
        std::cout<<"Matrix C:"<<std::endl;
        C=A*B;
        C.print(4,4);
        //step1. Encrypte matrix data
        Ciphertext matrix_a,matrix_b,matrix_change_b,matrix_change_a,matrix_c;
        encrypt_data(flat_b,scale, matrix_b, encoder, encryptor);
        //step2. change matrix ct.B to ct.B(0)
        change_matrix_B(matrix_b, matrix_change_b, max_size, max_size, parms, evaluator, gal_keys, relin_keys, decryptor, encoder);
        //step3. starting matrix multiply
        plain_matrix_multiply_cipher_matrix(A, matrix_change_b, max_size, max_size, matrix_c,scale, parms, evaluator, gal_keys, relin_keys, decryptor, encoder);
        //step4. decrypte matrix C result
        decrypte_result(matrix_c, decryptor, encoder);
    }
    else if (max_matrix_size>16 && max_matrix_size<=64)
    {
        matrix<double> C;
        vector<double> flat_a, flat_b;
        std::size_t max_size=64;
        A.resize(max_size,max_size);
        B.resize(max_size,max_size);
        std::cout<<"Matrix("<<max_size<<"×"<<max_size<<")×("<<max_size<<"×"<<max_size<<")"<<std::endl;
        std::cout<<"Matrix A:"<<std::endl;
        A.print(4, 4);
        std::cout<<"Matrix B:"<<std::endl;
        B.print(4, 4);
        flat_b = B.flatten_matrix_to_rows_vector();
        // print_vector(flat_b);
        std::cout<<"Matrix C:"<<std::endl;
        C=A*B;
        C.print(4,4);
        //step1. Encrypte matrix data
        Ciphertext matrix_b,matrix_change_b,matrix_c;
        encrypt_data(flat_b,scale, matrix_b, encoder, encryptor);
        //step2. change matrix ct.B to ct.B(0)
        change_matrix_B_version64(matrix_b, matrix_change_b, max_size, max_size, parms, evaluator, gal_keys, relin_keys, decryptor, encoder);
        //step5. starting matrix multiply
        plain_matrix_multiply_cipher_matrix_version64(A, matrix_change_b, max_size, max_size, matrix_c,scale, parms, evaluator, gal_keys, relin_keys, decryptor, encoder);
        //step6. decrypte matrix C result
        decrypte_result(matrix_c, decryptor, encoder);
    }
    else{
        std::cout<<" Matrix exceeds dimension."<<std::endl;
    }
}

void test_iris_bayes_jiang(){
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60,40,40,60 }));
    double scale = pow(2.0, 40);
    std::size_t matrix_rows_A=3;
    std::size_t matrix_cols_A=20;
    std::size_t matrix_rows_B=20;
    std::size_t matrix_cols_B=30;

    // create SEAL keys
    SEALContext context(parms);
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);

    print_parameters(context);

    matrix<double> client_matrix(matrix_cols_B, matrix_rows_B),model_matrix(matrix_rows_A, matrix_cols_A);
    vector<double> model_prior,flat_b;
    
    string filename="../data/Iris";
    string result_dir="../data/result/result_Jiangs_iris.txt";
    read_data(client_matrix,filename);
    client_matrix=client_matrix.transpose();
    read_model(model_matrix,filename);
    read_prior(model_prior,filename);

    std::size_t max_size = std::max(std::max(matrix_rows_A,matrix_cols_A),std::max(matrix_rows_B,matrix_cols_B));
    model_matrix.resize(max_size, max_size);
    client_matrix.resize(max_size, max_size);
    std::cout << "Matrix(" << max_size << "×" << max_size << ")×(" << max_size << "×" << max_size << ")" << std::endl;
    std::cout << "Matrix A:" << std::endl;
    model_matrix.print(4, 4);
    std::cout << "Matrix B:" << std::endl;
    client_matrix.print(4, 4);
    flat_b = client_matrix.flatten_matrix_to_rows_vector();
    // print_vector(flat_b);

    // matrix<double> C;
    // C=model_matrix*client_matrix;
    // C.print(4,4);
   
    // step1. Encrypte matrix data
    Ciphertext matrix_b, matrix_change_b, matrix_c,result;
    encrypt_data(flat_b, scale, matrix_b, encoder, encryptor);
    // step2. change matrix ct.B to ct.B(0)
    change_matrix_B(matrix_b, matrix_change_b, max_size, max_size, parms, evaluator, gal_keys, relin_keys, decryptor, encoder);
    // step3. starting matrix multiply
    plain_matrix_multiply_cipher_matrix(model_matrix, matrix_change_b, max_size, max_size, matrix_c, scale, parms, evaluator, gal_keys, relin_keys, decryptor, encoder);
    
    // step5. add noise and prior
    matrix_add_prior_and_noise_jiang(matrix_c,model_prior,max_size,max_size,matrix_cols_B,result,evaluator,encoder);
    // step6. result
    decrypte_bayes_result_jiang(result,matrix_rows_A,matrix_cols_B,max_size,result_dir,decryptor,encoder);
}

void Jiang_plain_mul_cipher(matrix<double> A,seal::Ciphertext &matrix_b,int max_size,
                            seal::Ciphertext &destination, double scale,seal::EncryptionParameters &parms,
                            seal::CKKSEncoder &encoder,seal::Encryptor &encryptor,seal::Evaluator &evaluator,
                            seal::RelinKeys &relin_keys,seal::GaloisKeys &gal_keys,seal::Decryptor &decryptor,
                            double &elapsed_time)
{

    // step1. Encrypte matrix data
    Ciphertext matrix_change_b, matrix_c;
    // step2. change matrix ct.B to ct.B(0)
    change_matrix_B_version64(matrix_b, matrix_change_b, max_size, max_size, parms, evaluator, gal_keys, relin_keys, decryptor, encoder,elapsed_time);
    // step5. starting matrix multiply
    plain_matrix_multiply_cipher_matrix_version64(A, matrix_change_b, max_size, max_size, matrix_c, scale, parms, evaluator, gal_keys, relin_keys, decryptor, encoder,elapsed_time);
    // step6. decrypte matrix C result
    //decrypte_result(matrix_c, decryptor, encoder);
    
    destination=matrix_c;
}

void test_WBC_bayes_Jiang(){
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60,40,40,60 }));
    double scale = pow(2.0, 40);
    std::size_t matrix_rows_A=2;
    std::size_t matrix_cols_A=90;
    std::size_t matrix_rows_B=90;
    std::size_t matrix_cols_B=205;
    int batch_size=64;

    // create SEAL keys
    SEALContext context(parms);
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    CKKSEncoder encoder(context);
    print_parameters(context);


    matrix<double> client_matrix(matrix_cols_B, matrix_rows_B),model_matrix(matrix_rows_A, matrix_cols_A),C;
    vector<double> model_prior,flat_b;

    /* Read data */
    string filename="../data/WBC";
    string result_dir="../data/result/result_Jiang_WBC.txt";
    const char* result_file=result_dir.c_str();
    std::remove(result_file);

    read_data(client_matrix,filename);
    client_matrix=client_matrix.transpose();
    read_model(model_matrix,filename);
    read_prior(model_prior,filename);
    // C=model_matrix*client_matrix;
    // C.print();

    /*split data*/
    split_matrix<double> split_A(model_matrix,batch_size,batch_size),split_B(client_matrix,batch_size,batch_size);
    int split_A_rows=split_A.get_rows();
    int split_A_cols=split_A.get_cols();
    int split_B_rows=split_B.get_rows();
    int split_B_cols=split_B.get_cols();
    
    vector<vector<seal::Ciphertext>>  matrix_b_vector(split_B_rows,std::vector<seal::Ciphertext>(split_B_cols));
    vector<vector<seal::Ciphertext>>  matrix_c_vector(split_A_rows,std::vector<seal::Ciphertext>(split_B_cols));
    seal::Ciphertext matrix_b,result,tmp,matrix_c;
    matrix<double> tmpB,tmpA;
    double elapsed_time=0,size=0;
    /* encrypte split matrix */
    for(int i=0;i<split_B_rows;i++){
        for(int j=0;j<split_B_cols;j++){
            //cout<<i<<"  "<<j<<endl;
            tmpB=split_B.get_submatrix(i,j);
            flat_b=tmpB.flatten_matrix_to_rows_vector();
            encrypt_data(flat_b,scale,matrix_b,encoder,encryptor,elapsed_time,size);
            matrix_b_vector[i][j]=matrix_b;
        }
    }
    print_line(__LINE__);
    cout<<"Encrypte Data"<<endl;
    cout << "        + time:" << elapsed_time << " μs" << endl;
    cout << "        + size:" << size / 1024 << " KB" << endl;

    elapsed_time=0;
    /* start plain matrix multiply cipher matrix */
    for(int i=0;i<split_A_rows;i++){
        for(int j=0;j<split_B_cols;j++){
            vector<seal::Ciphertext> result_vector;
            int k=0;
            while(k<split_A_cols){
                tmpA=split_A.get_submatrix(i,k);
                matrix_b=matrix_b_vector[k][j];
                Jiang_plain_mul_cipher(tmpA,matrix_b,batch_size,matrix_c,scale,parms,encoder,encryptor,evaluator,relin_keys,gal_keys,decryptor,elapsed_time);
                result_vector.push_back(matrix_c);
                k++;
            }
            evaluator.add_many(result_vector,matrix_c);
            matrix_c_vector[i][j]=matrix_c;
            //decrypte_result(result,decryptor,encoder);
        }
    }
    print_line(__LINE__);
    cout<<"Plain Matrix Multiply Cipher Matrix"<<endl;
    cout << "        + time:" << elapsed_time/1000 << " ms" << endl;

    elapsed_time=0;
    for(int i=0;i<split_A_rows;i++){
        for(int j=0;j<split_B_cols;j++){
            matrix_c=matrix_c_vector[i][j];
            // step5. add noise and prior
            matrix_add_prior_and_noise_jiang(matrix_c,model_prior,batch_size,batch_size,batch_size,result,evaluator,encoder);
            // step6. result
            decrypte_bayes_result_jiang(result,matrix_rows_A,batch_size,batch_size,result_dir,decryptor,encoder,elapsed_time);
        }
    }
    print_line(__LINE__);
    cout<<"Decrypte Result"<<endl;
    cout << "        + time:" << elapsed_time << " μs" << endl;
}


int main(){
    while(true){
        cout << "\nExamples:" << endl << endl;
        cout << " 1. Plain matrix multiply cipher matrix example" << endl;
        cout << " 2. Plain matrix multiply cipher matrix different size" << endl;
        cout << " 3. Plain matrix multiply cipher matrix square matrix" << endl;
        cout << " 4. Plain matrix multiply cipher matrix Iris" << endl;
        cout << " 5. Plain matrix multiply cipher matrix WBC" << endl;
        cout << " 6. Jiang plain matrix multiply cipher matrix example" << endl;
        cout << " 7. Jiang plain matrix multiply cipher matrix square matrix" << endl;
        cout << " 8. Jiang plain matrix multiply cipher matrix Iris" << endl;
        cout << " 9. Jiang plain matrix multiply cipher matrix WBC" << endl;
        cout << " 0. Exit" << endl;
        int selection = 0;
        cout << endl << "Run example: ";
        if (!(cin >> selection))
        {
            cout << "Invalid option." << endl;
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            continue;
        }
        
        switch (selection)
        {
        case 1:
            Cipher_plain_mul_example();
            break;
        case 2:
            Cipher_plain_mul_example(16,16,128);
            Cipher_plain_mul_example(16,16,256);
            Cipher_plain_mul_example(16,4,128);
            Cipher_plain_mul_example(16,4,256);
            break;
        case 3:
            Cipher_plain_mul_example(4,4,4);
            Cipher_plain_mul_example(16,16,16);
            Cipher_plain_mul_example(64,64,64);
            break;
        case 4:
            test_iris_bayes_our();
            break;
        case 5:
            test_WBC_bayes_our();
            break;
        case 6:
            Jiang_example();
            break;
        case 7:
            Jiang_example(4,4,4);
            Jiang_example(16,16,16);
            Jiang_example(64,64,64);
            break;
        case 8:
            test_iris_bayes_jiang();
            break;
        case 9:
            test_WBC_bayes_Jiang();
            break;
        case 0:
            return 0;
        default:
            cout << "Invalid option." << endl;
        }
    }
    return 0;
}