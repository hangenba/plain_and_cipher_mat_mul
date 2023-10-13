#include"matrix.h"
#include"seal/seal.h"
#include"iostream"
#include"helper.h"
#include <chrono>
#include"utils.h"

using namespace std;
using namespace seal;

/*
* 我们的方案
*/
//encoder matrix
template <typename T>
void encrypt_data(vector<T>& A,double scale, seal::Ciphertext& result, 
                  seal::CKKSEncoder& encoder, seal::Encryptor& encryptor) 
{
    auto start = std::chrono::high_resolution_clock::now();
    seal::Plaintext plain;
    encoder.encode(A, scale, plain);
    encryptor.encrypt(plain, result);

    auto end = std::chrono::high_resolution_clock::now();
    double elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    print_line(__LINE__);
    cout<<"Encrypte Data"<<endl;
    cout << "        + time:" << elapsed_time << " μs" << endl;

    auto size = result.save_size();
    cout << "        + size:" << size / 1024 << " KB" << endl;
}

template <typename T>
void encrypt_data(vector<T>& A,double scale, seal::Ciphertext& result, 
                  seal::CKKSEncoder& encoder, seal::Encryptor& encryptor,double &elapsed_time,double &size) 
{
    auto start = std::chrono::high_resolution_clock::now();
    seal::Plaintext plain;
    encoder.encode(A, scale, plain);
    encryptor.encrypt(plain, result);

    auto end = std::chrono::high_resolution_clock::now();
    elapsed_time += std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    // print_line(__LINE__);
    // cout<<"Encrypte Data"<<endl;
    // cout << "        + time:" << elapsed_time << " μs" << endl;

    size += result.save_size();
    // cout << "        + size:" << size / 1024 << " KB" << endl;
}

//change ciphertext matrix rows
void change_row_length(seal::Ciphertext& A, seal::Ciphertext& result, 
                       int old_row, int new_row, int col, seal::Evaluator& evaluator, 
                       seal::CKKSEncoder& encoder, seal::GaloisKeys& gal_keys, 
                       seal::RelinKeys& relin_keys) 
{
	int rotate_outside_size = ceil(sqrt(col));
	int rotate_inside_size = ceil(double(col) / double(rotate_outside_size));
	//cout << rotate_outside_size << "    " << rotate_inside_size << endl;
    int sum_rotate = 0;
    int sum_mul = 0;


	seal::Ciphertext tmp;
    auto start = std::chrono::high_resolution_clock::now();
	//进行计算之前，padding一下，缩减向右旋转，增加向左旋转
	if (old_row > new_row) {
		evaluator.rotate_vector(A, -old_row * rotate_inside_size * rotate_outside_size, gal_keys, tmp);
        sum_rotate++;
	}
	else
	{
		evaluator.rotate_vector(A, old_row * rotate_inside_size * rotate_outside_size, gal_keys, tmp);
        sum_rotate++;
	}
	evaluator.add_inplace(A, tmp);


	vector<seal::Ciphertext> rotate_vector;
	for (int i = 0; i < rotate_inside_size; i++) {
		evaluator.rotate_vector(A, i * (old_row - new_row), gal_keys, tmp);
		rotate_vector.push_back(tmp);
	}
	int sep = new_row < old_row ? new_row : old_row;
	//cout << sep << endl;
	vector<Ciphertext> result_vector;
	for (int i = 0; i < rotate_outside_size; i++) {
		Plaintext rotate_plain;
		vector<Ciphertext> compute_tmp;
		for (int j = 0; j < rotate_inside_size; j++) {
			vector<double> vec_tmp(4096, 0);
			int k = 0;
			int start_index = i * old_row * rotate_inside_size + j * new_row;
			while (k < sep) {
				vec_tmp[start_index + k] = 1;
				//cout << start_index + k << endl;
				k++;
			}
			encoder.encode(vec_tmp, pow(2.0, 40), rotate_plain);
			evaluator.mod_switch_to_inplace(rotate_plain, rotate_vector[j].parms_id());
			evaluator.multiply_plain(rotate_vector[j], rotate_plain, tmp);
			compute_tmp.push_back(tmp);
            sum_mul++;
		}
		evaluator.add_many(compute_tmp, tmp);
		evaluator.rescale_to_next_inplace(tmp);
		//cout << i * rotate_inside_size * (old_row - new_row) << endl;
		evaluator.rotate_vector_inplace(tmp, i * rotate_inside_size * (old_row - new_row), gal_keys);
		result_vector.push_back(tmp);
        sum_rotate++;
	}
	evaluator.add_many(result_vector, result);
    auto end = std::chrono::high_resolution_clock::now();
    double elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    print_line(__LINE__);
    cout<<"Change Matrix B Rows"<<endl;
    cout << "        + time:" << elapsed_time << " μs" << endl;
    cout << "        + Rotate: " << sum_rotate << "  Multiply: " << sum_mul << endl;
}

//generate encode matrix_A
template <typename T>
void generate_encode_A_plain(matrix<T> &A,vector<vector<T>>& Encode_A,int repeat,int left_step,int right_step)
{
    int cols = A.get_cols();
	int rows = A.get_rows();
    // cout<<rows<<"  "<<cols<<endl;

    for (int i = 1 - rows+right_step; i < 0; i++) {
		int j = 0;
		vector<T> sequence(rows, 0);
		while (j < rows) {
			if (i + j >= 0) {
				sequence[j] = A.get(j, i + j);
			}
			j++;
		}
		vector<T> repeated_sequence;
		for (int k = 0; k < repeat; ++k) {
			repeated_sequence.insert(repeated_sequence.end(), sequence.begin(), sequence.end());
		}
		Encode_A.push_back(repeated_sequence);
	}

	for (int i = 0; i < cols-left_step; i++) {
		vector<T> sequence(rows, 0);
		int j = 0;
		while (j < rows) {
			if (i + j < cols) {
				sequence[j] = A.get(j, i + j);
			}
			j++;
		}
		vector<T> repeated_sequence;
		for (int k = 0; k < repeat; ++k) {
			repeated_sequence.insert(repeated_sequence.end(), sequence.begin(), sequence.end());
		}
		Encode_A.push_back(repeated_sequence);
	}
}

//resize A and determine dimensional conversion
template <typename T>
void change_row_and_resize(std::size_t matrix_rows_A,std::size_t matrix_cols_A,
                           std::size_t matrix_rows_B,std::size_t matrix_cols_B,
                           matrix<T> &A,vector<vector<T>> &Encode_A,bool &flag)
{
    if(matrix_cols_A!=matrix_rows_B){
        std::cout<<"MatrixA and MatrixB not multiply"<<std::endl;
        std::abort();
    }
    if(matrix_rows_A<=matrix_cols_A){
        flag=false;
        A.resize(matrix_cols_A,matrix_cols_A);
        generate_encode_A_plain(A,Encode_A,matrix_cols_B,0,matrix_cols_A-matrix_rows_A);
    }
    else{
        flag=true;
        A.resize(matrix_rows_A,matrix_rows_A);
        generate_encode_A_plain(A,Encode_A,matrix_cols_B,matrix_rows_A-matrix_cols_A,0);
    }
    // cout<<Encode_A.size()<<"  "<<Encode_A[0].size()<<endl;
    // for(int i=0;i<Encode_A.size();i++){
    //     for(int j=0;j<Encode_A[0].size();j++){
    //         cout<<Encode_A[i][j]<<"  ";
    //     }
    //     cout<<endl;
    // }
}

//plain and cipher multiply
template <typename T>
void Multiply_plain_and_cipher(vector<vector<T>>& encode_matrix, seal::Ciphertext& cipher, int matrix_rows_B,int matrix_cols_B,int step,
                               double scale, seal::Ciphertext& destination,seal::EncryptionParameters &parms, seal::Evaluator& evaluator, 
                               seal::CKKSEncoder& encoder, seal::GaloisKeys& gal_keys, seal::RelinKeys& relin_keys,seal::Decryptor &decryptor)
{
	//padding cipher matrix B
	Ciphertext cipher_tmp;//save intermediate variables.
    vector<Ciphertext> cipher_rotate,cipher_result;//save rotate result vector
    Plaintext plain_tmp;
    vector<double> vec_tmp;
    int slot_size=parms.poly_modulus_degree()/2;

    //step0.padding
    if(matrix_cols_B*matrix_rows_B<=slot_size/2){
        evaluator.rotate_vector(cipher, -matrix_cols_B*matrix_rows_B, gal_keys, cipher_tmp);
	    evaluator.add_inplace(cipher, cipher_tmp);
    }else if (matrix_cols_B*matrix_rows_B>slot_size/2 &&matrix_cols_B*matrix_rows_B<slot_size)
    {
        std::cout<<"        Slots are not support padding"<<std::endl;
        std::abort();
    }else if (matrix_cols_B*matrix_rows_B==slot_size)
    {
        // std::cout<<"        No need for padding in slots."<<std::endl;
    }
    
    
    //step1.determining the dimensions
    int rotate_size = encode_matrix.size();
	int rotate_outside_size = ceil(sqrt(rotate_size));
	int rotate_inside_size = ceil(double(rotate_size) / double(rotate_outside_size));
    int sum_rotate = 0;
    int sum_mul = 0;
    // cout<<rotate_inside_size<<" "<<rotate_outside_size<<endl;

    // step2. pre-rotate ciphertext
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < rotate_inside_size; i++) {
        evaluator.rotate_vector(cipher, -matrix_rows_B+matrix_cols_B*matrix_rows_B+i+1+step, gal_keys, cipher_tmp);
        cipher_rotate.push_back(cipher_tmp);
        sum_rotate++;
        // decryptor.decrypt(cipher_tmp, plain_tmp);
        // encoder.decode(plain_tmp, vec_tmp);
        // for (int i = 0; i < 12; i++) {
        //     cout << vec_tmp[i] << "  ";
        // }
        // cout << endl;
    }

	//step3. starting step function 
    for (int i = 0; i < rotate_outside_size; i++) {
        vector<Ciphertext> cipher_vector;
        for (int j = 0; j < rotate_inside_size; j++) {
            if(i*rotate_inside_size+j>=rotate_size){
                continue;
            }
            vec_tmp = encode_matrix[i*rotate_inside_size+j];
            if (std::all_of(vec_tmp.begin(), vec_tmp.end(), [](double num) { return num == 0; }) == 1) {
                continue;
            }
            else {
                vec_tmp.resize(slot_size);
                std::rotate(vec_tmp.rbegin(), vec_tmp.rbegin() + i * rotate_inside_size, vec_tmp.rend());
                encoder.encode(vec_tmp, cipher.scale(), plain_tmp);
                evaluator.mod_switch_to_inplace(plain_tmp, cipher.parms_id());
                evaluator.multiply_plain(cipher_rotate[j], plain_tmp, cipher_tmp);
                cipher_vector.push_back(cipher_tmp);
                sum_mul++;
            }
        }
        evaluator.add_many(cipher_vector, cipher_tmp);
        evaluator.relinearize_inplace(cipher_tmp, relin_keys);
        evaluator.rescale_to_next_inplace(cipher_tmp);
        evaluator.rotate_vector_inplace(cipher_tmp, i * rotate_inside_size, gal_keys);
        cipher_result.push_back(cipher_tmp);
        sum_rotate++;
    }
    evaluator.add_many(cipher_result, destination);

    auto end = std::chrono::high_resolution_clock::now();
    double elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    print_line(__LINE__);
    cout<<"Plain Matrix Multiply Cipher Matrix"<<endl;
    cout << "        + time:" << elapsed_time << " μs" << endl;
    cout << "        + Rotate: " << sum_rotate << "  Multiply: " << sum_mul << endl;
}

template <typename T>
void Multiply_plain_and_cipher(vector<vector<T>>& encode_matrix, seal::Ciphertext& cipher, int matrix_rows_B,int matrix_cols_B,int step,
                               double scale, seal::Ciphertext& destination,seal::EncryptionParameters &parms, seal::Evaluator& evaluator, 
                               seal::CKKSEncoder& encoder, seal::GaloisKeys& gal_keys, seal::RelinKeys& relin_keys,seal::Decryptor &decryptor,
                               double &elapsed_time)
{
	//padding cipher matrix B
	Ciphertext cipher_tmp;//save intermediate variables.
    vector<Ciphertext> cipher_rotate,cipher_result;//save rotate result vector
    Plaintext plain_tmp;
    vector<double> vec_tmp;
    int slot_size=parms.poly_modulus_degree()/2;

    //step0.padding
    if(matrix_cols_B*matrix_rows_B<=slot_size/2){
        evaluator.rotate_vector(cipher, -matrix_cols_B*matrix_rows_B, gal_keys, cipher_tmp);
	    evaluator.add_inplace(cipher, cipher_tmp);
    }else if (matrix_cols_B*matrix_rows_B>slot_size/2 &&matrix_cols_B*matrix_rows_B<slot_size)
    {
        std::cout<<"        Slots are not support padding"<<std::endl;
        std::abort();
    }else if (matrix_cols_B*matrix_rows_B==slot_size)
    {
        // std::cout<<"        No need for padding in slots."<<std::endl;
    }
    
    
    //step1.determining the dimensions
    int rotate_size = encode_matrix.size();
	int rotate_outside_size = ceil(sqrt(rotate_size));
	int rotate_inside_size = ceil(double(rotate_size) / double(rotate_outside_size));
    int sum_rotate = 0;
    int sum_mul = 0;
    // cout<<rotate_inside_size<<" "<<rotate_outside_size<<endl;

    auto start = std::chrono::high_resolution_clock::now();
    // step2. pre-rotate ciphertext
    for (int i = 0; i < rotate_inside_size; i++) {
        evaluator.rotate_vector(cipher, -matrix_rows_B+matrix_cols_B*matrix_rows_B+i+1+step, gal_keys, cipher_tmp);
        cipher_rotate.push_back(cipher_tmp);
        sum_rotate++;
        // decryptor.decrypt(cipher_tmp, plain_tmp);
        // encoder.decode(plain_tmp, vec_tmp);
        // for (int i = 0; i < 12; i++) {
        //     cout << vec_tmp[i] << "  ";
        // }
        // cout << endl;
    }

	//step3. starting step function 
    for (int i = 0; i < rotate_outside_size; i++) {
        vector<Ciphertext> cipher_vector;
        for (int j = 0; j < rotate_inside_size; j++) {
            if(i*rotate_inside_size+j>=rotate_size){
                continue;
            }
            vec_tmp = encode_matrix[i*rotate_inside_size+j];
            vec_tmp.resize(slot_size);
            if (std::all_of(vec_tmp.begin(), vec_tmp.end(), [](double num) { return num == 0; }) == 1) {
                continue;
            }
            else {
                std::rotate(vec_tmp.rbegin(), vec_tmp.rbegin() + i * rotate_inside_size, vec_tmp.rend());
                encoder.encode(vec_tmp, cipher.scale(), plain_tmp);
                evaluator.mod_switch_to_inplace(plain_tmp, cipher.parms_id());
                evaluator.multiply_plain(cipher_rotate[j], plain_tmp, cipher_tmp);
                cipher_vector.push_back(cipher_tmp);
                sum_mul++;
            }
        }
        evaluator.add_many(cipher_vector, cipher_tmp);
        evaluator.relinearize_inplace(cipher_tmp, relin_keys);
        evaluator.rescale_to_next_inplace(cipher_tmp);
        evaluator.rotate_vector_inplace(cipher_tmp, i * rotate_inside_size, gal_keys);
        cipher_result.push_back(cipher_tmp);
        sum_rotate++;
    }
    evaluator.add_many(cipher_result, destination);

    auto end = std::chrono::high_resolution_clock::now();
    elapsed_time += std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    // print_line(__LINE__);
    // cout<<"Plain Matrix Multiply Cipher Matrix"<<endl;
    // cout << "        + time:" << elapsed_time << " μs" << endl;
    // cout << "        + Rotate: " << sum_rotate << "  Multiply: " << sum_mul << endl;
}
//decrypte matrix multiply result
void decrypte_result(Ciphertext& w_encrypted, seal::Decryptor& decryptor, seal::CKKSEncoder& encoder) {
    auto start = std::chrono::high_resolution_clock::now();
    Plaintext plain_tmp;
    vector<double> vec_tmp;

    decryptor.decrypt(w_encrypted, plain_tmp);
    encoder.decode(plain_tmp, vec_tmp);
    auto end = std::chrono::high_resolution_clock::now();
    double elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    print_line(__LINE__);
    cout<<"Decrypte Result"<<endl;
    cout << "        + time:" << elapsed_time << " μs" << endl;
    cout<<"Value: ";
    for (int i = 0; i < 10; i++) {
        cout << vec_tmp[i] << "  ";
    }
    cout<<endl;
}



/*
Jiang 的方案
*/

template<typename T>
void matrix_multiply_cipher_vector(matrix<T>& A, Ciphertext& v, int paddinglength, Ciphertext& destination, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys, seal::RelinKeys& relin_keys, seal::Decryptor& decryptor, seal::CKKSEncoder& encoder);

//change matrix_A from ct.A to ct.A(0)
void change_matrix_A(seal::Ciphertext& A, seal::Ciphertext& result, int rows, int cols, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys, seal::RelinKeys& relin_keys, seal::Decryptor& decryptor, seal::CKKSEncoder& encoder) {

    //generate u_sigma matrix
    matrix<double> u_sigma;
    u_sigma.generate_u_sigma(rows, cols);
    Ciphertext cipher_tmp;//save intermediate variables.
    vector<Ciphertext> cipher_rotate,cipher_result;//save rotate result vector
    Plaintext plain_tmp;
    vector<double> vec_tmp;
    int sum_rotate = 0;
    int sum_mul = 0;



    //start change matrixA
    // auto start = std::chrono::high_resolution_clock::now();
    //step0. padding
    evaluator.rotate_vector(A, -rows * cols, gal_keys, cipher_tmp);
    evaluator.add_inplace(A, cipher_tmp);
    //step1. determining the dimensions
    int rotate_size = 2 * rows - 1;
    int rotate_outside_size = ceil(sqrt(rotate_size));
    int rotate_inside_size = ceil(double(rotate_size) / double(rotate_outside_size));
    // step2. pre-rotate ciphertext
    for (int i = 0; i < rotate_inside_size; i++) {
        evaluator.rotate_vector(A, -rows+cols*rows+i+1, gal_keys, cipher_tmp);
        cipher_rotate.push_back(cipher_tmp);
        sum_rotate++;
    }

    //step3. starting step function 
    for (int i = 0; i < rotate_outside_size; i++) {
        vector<Ciphertext> cipher_vector;
        for (int j = 0; j < rotate_inside_size; j++) {
            vec_tmp = u_sigma.diag_vector(i * rotate_inside_size + j-rows+1);
            if (std::all_of(vec_tmp.begin(), vec_tmp.end(), [](double num) { return num == 0; }) == 1) {
                continue;
            }
            else {
                std::rotate(vec_tmp.rbegin(), vec_tmp.rbegin() + i * rotate_inside_size, vec_tmp.rend());
                encoder.encode(vec_tmp, A.scale(), plain_tmp);
                evaluator.mod_switch_to_inplace(plain_tmp, A.parms_id());
                evaluator.multiply_plain(cipher_rotate[j], plain_tmp, cipher_tmp);
                cipher_vector.push_back(cipher_tmp);
                sum_mul++;
            }
        }
        evaluator.add_many(cipher_vector, cipher_tmp);
        evaluator.relinearize_inplace(cipher_tmp, relin_keys);
        evaluator.rescale_to_next_inplace(cipher_tmp);
        evaluator.rotate_vector_inplace(cipher_tmp, i * rotate_inside_size, gal_keys);
        cipher_result.push_back(cipher_tmp);
        sum_rotate++;
    }
    evaluator.add_many(cipher_result, result);

    // auto end = std::chrono::high_resolution_clock::now();
    // double elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    // cout << "        + change_matrix_a to ct.A(0) time:" << elapsed_time << " μs" << endl;
    // cout << "           + Rotate: " << sum_rotate << "  Multiply: " << sum_mul << endl;
}
void change_matrix_A_version64(seal::Ciphertext& A, seal::Ciphertext& result, int rows, int cols, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys, seal::RelinKeys& relin_keys, seal::Decryptor& decryptor, seal::CKKSEncoder& encoder) {

    //generate u_sigma matrix
    matrix<double> u_sigma;
    u_sigma.generate_u_sigma(rows, cols);
    Ciphertext cipher_tmp;//save intermediate variables.
    vector<Ciphertext> cipher_rotate,cipher_result;//save rotate result vector
    Plaintext plain_tmp;
    vector<double> vec_tmp;
    int sum_rotate = 0;
    int sum_mul = 0;



    //start change matrixA
    // auto start = std::chrono::high_resolution_clock::now();
    //step1. determining the dimensions
    int rotate_size = 2 * rows - 1;
    int rotate_outside_size = ceil(sqrt(rotate_size));
    int rotate_inside_size = ceil(double(rotate_size) / double(rotate_outside_size));
    // step2. pre-rotate ciphertext
    for (int i = 0; i < rotate_inside_size; i++) {
        evaluator.rotate_vector(A, -rows+cols*rows+i+1, gal_keys, cipher_tmp);
        cipher_rotate.push_back(cipher_tmp);
        sum_rotate++;
    }

    //step3. starting step function 
    for (int i = 0; i < rotate_outside_size; i++) {
        vector<Ciphertext> cipher_vector;
        for (int j = 0; j < rotate_inside_size; j++) {
            vec_tmp = u_sigma.diag_vector(i * rotate_inside_size + j-rows+1);
            if (std::all_of(vec_tmp.begin(), vec_tmp.end(), [](double num) { return num == 0; }) == 1) {
                continue;
            }
            else {
                std::rotate(vec_tmp.rbegin(), vec_tmp.rbegin() + i * rotate_inside_size, vec_tmp.rend());
                encoder.encode(vec_tmp, A.scale(), plain_tmp);
                evaluator.mod_switch_to_inplace(plain_tmp, A.parms_id());
                evaluator.multiply_plain(cipher_rotate[j], plain_tmp, cipher_tmp);
                cipher_vector.push_back(cipher_tmp);
                sum_mul++;
            }
        }
        evaluator.add_many(cipher_vector, cipher_tmp);
        evaluator.relinearize_inplace(cipher_tmp, relin_keys);
        evaluator.rescale_to_next_inplace(cipher_tmp);
        evaluator.rotate_vector_inplace(cipher_tmp, i * rotate_inside_size, gal_keys);
        cipher_result.push_back(cipher_tmp);
        sum_rotate++;
    }
    evaluator.add_many(cipher_result, result);

    // auto end = std::chrono::high_resolution_clock::now();
    // double elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    // cout << "        + change_matrix_a to ct.A(0) time:" << elapsed_time << " μs" << endl;
    // cout << "           + Rotate: " << sum_rotate << "  Multiply: " << sum_mul << endl;
}


//change matrix_B from ct.B to ct.B(0)
void change_matrix_B(seal::Ciphertext& A, seal::Ciphertext& result, int rows, int cols, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys, seal::RelinKeys& relin_keys, seal::Decryptor& decryptor, seal::CKKSEncoder& encoder) {

    // generate u_tau matrix
    matrix<double> u_tau;
    u_tau.generate_u_tau(rows, cols);
    Ciphertext cipher_tmp;//save intermediate variables
    vector<Ciphertext> cipher_rotate, cipher_result;//save rotate result vector
    Plaintext plain_tmp;
    vector<double> vec_tmp;
    int sum_rotate = 0;
    int sum_mul = 0;


    //start change matrixB
    //step0. padding
    evaluator.rotate_vector(A, -rows * cols, gal_keys, cipher_tmp);
    evaluator.add_inplace(A, cipher_tmp);
    //step1. determining the dimensions
    int rotate_size = rows;
    int rotate_outside_size = ceil(sqrt(rotate_size));
    int rotate_inside_size = ceil(double(rotate_size) / double(rotate_outside_size));

    auto start = std::chrono::high_resolution_clock::now();
    // step2. pre-rotate ciphertext 
    for (int i = 0; i < rotate_inside_size; i++) {
        evaluator.rotate_vector(A, i*cols, gal_keys, cipher_tmp);
        cipher_rotate.push_back(cipher_tmp);
        sum_rotate++;
    }
    //step3. starting step function 
    for (int i = 0; i < rotate_outside_size; i++) {
        vector<Ciphertext> cipher_vector;
        for (int j = 0; j < rotate_inside_size; j++) {
            vec_tmp = u_tau.diag_vector((i*rotate_inside_size+j)*cols);
            if (std::all_of(vec_tmp.begin(), vec_tmp.end(), [](double num) { return num == 0; }) == 1) {
                continue;
            }
            else {
                std::rotate(vec_tmp.rbegin(), vec_tmp.rbegin() + i * rotate_inside_size*cols, vec_tmp.rend());
                encoder.encode(vec_tmp, A.scale(), plain_tmp);
                evaluator.mod_switch_to_inplace(plain_tmp, A.parms_id());
                evaluator.multiply_plain(cipher_rotate[j], plain_tmp, cipher_tmp);
                sum_mul++;
                cipher_vector.push_back(cipher_tmp);
            }
        }
        evaluator.add_many(cipher_vector, cipher_tmp);
        evaluator.relinearize_inplace(cipher_tmp, relin_keys);
        evaluator.rescale_to_next_inplace(cipher_tmp);
        evaluator.rotate_vector_inplace(cipher_tmp, i * rotate_inside_size*cols, gal_keys);
        sum_rotate++;
        cipher_result.push_back(cipher_tmp);
    }
    evaluator.add_many(cipher_result, result);
    auto end = std::chrono::high_resolution_clock::now();
    double elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    print_line(__LINE__);
    cout<<"Change Matrix B To Ct.B(0) "<<endl;
    cout << "        + time:" << elapsed_time << " μs" << endl;
    cout << "        + Rotate: " << sum_rotate << "  Multiply: " << sum_mul << endl;
}
void change_matrix_B_version64(seal::Ciphertext& A, seal::Ciphertext& result, int rows, int cols, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys, seal::RelinKeys& relin_keys, seal::Decryptor& decryptor, seal::CKKSEncoder& encoder) {

    // generate u_tau matrix
    matrix<double> u_tau;
    u_tau.generate_u_tau(rows, cols);
    Ciphertext cipher_tmp;//save intermediate variables
    vector<Ciphertext> cipher_rotate, cipher_result;//save rotate result vector
    Plaintext plain_tmp;
    vector<double> vec_tmp;
    int sum_rotate = 0;
    int sum_mul = 0;


    //start change matrixB
    auto start = std::chrono::high_resolution_clock::now();
    //step1. determining the dimensions
    int rotate_size = rows;
    int rotate_outside_size = ceil(sqrt(rotate_size));
    int rotate_inside_size = ceil(double(rotate_size) / double(rotate_outside_size));
    // step2. pre-rotate ciphertext 
    for (int i = 0; i < rotate_inside_size; i++) {
        evaluator.rotate_vector(A, i*cols, gal_keys, cipher_tmp);
        cipher_rotate.push_back(cipher_tmp);
        sum_rotate++;
    }
    //step3. starting step function 
    for (int i = 0; i < rotate_outside_size; i++) {
        vector<Ciphertext> cipher_vector;
        for (int j = 0; j < rotate_inside_size; j++) {
            vec_tmp = u_tau.diag_vector((i*rotate_inside_size+j)*cols);
            if (std::all_of(vec_tmp.begin(), vec_tmp.end(), [](double num) { return num == 0; }) == 1) {
                continue;
            }
            else {
                std::rotate(vec_tmp.rbegin(), vec_tmp.rbegin() + i * rotate_inside_size*cols, vec_tmp.rend());
                encoder.encode(vec_tmp, A.scale(), plain_tmp);
                evaluator.mod_switch_to_inplace(plain_tmp, A.parms_id());
                evaluator.multiply_plain(cipher_rotate[j], plain_tmp, cipher_tmp);
                sum_mul++;
                cipher_vector.push_back(cipher_tmp);
            }
        }
        evaluator.add_many(cipher_vector, cipher_tmp);
        evaluator.relinearize_inplace(cipher_tmp, relin_keys);
        evaluator.rescale_to_next_inplace(cipher_tmp);
        evaluator.rotate_vector_inplace(cipher_tmp, i * rotate_inside_size*cols, gal_keys);
        sum_rotate++;
        cipher_result.push_back(cipher_tmp);
    }
    evaluator.add_many(cipher_result, result);
    auto end = std::chrono::high_resolution_clock::now();
    double elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    print_line(__LINE__);
    cout<<"Change Matrix B To Ct.B(0) "<<endl;
    cout << "        + time:" << elapsed_time << " μs" << endl;
    cout << "        + Rotate: " << sum_rotate << "  Multiply: " << sum_mul << endl;
}
void change_matrix_B_version64(seal::Ciphertext& A, seal::Ciphertext& result, int rows, int cols, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys, seal::RelinKeys& relin_keys, seal::Decryptor& decryptor, seal::CKKSEncoder& encoder,double &elapsed_time) {

    // generate u_tau matrix
    matrix<double> u_tau;
    u_tau.generate_u_tau(rows, cols);
    Ciphertext cipher_tmp;//save intermediate variables
    vector<Ciphertext> cipher_rotate, cipher_result;//save rotate result vector
    Plaintext plain_tmp;
    vector<double> vec_tmp;
    int sum_rotate = 0;
    int sum_mul = 0;


    //start change matrixB
    auto start = std::chrono::high_resolution_clock::now();
    //step1. determining the dimensions
    int rotate_size = rows;
    int rotate_outside_size = ceil(sqrt(rotate_size));
    int rotate_inside_size = ceil(double(rotate_size) / double(rotate_outside_size));
    // step2. pre-rotate ciphertext 
    for (int i = 0; i < rotate_inside_size; i++) {
        evaluator.rotate_vector(A, i*cols, gal_keys, cipher_tmp);
        cipher_rotate.push_back(cipher_tmp);
        sum_rotate++;
    }
    //step3. starting step function 
    for (int i = 0; i < rotate_outside_size; i++) {
        vector<Ciphertext> cipher_vector;
        for (int j = 0; j < rotate_inside_size; j++) {
            vec_tmp = u_tau.diag_vector((i*rotate_inside_size+j)*cols);
            if (std::all_of(vec_tmp.begin(), vec_tmp.end(), [](double num) { return num == 0; }) == 1) {
                continue;
            }
            else {
                std::rotate(vec_tmp.rbegin(), vec_tmp.rbegin() + i * rotate_inside_size*cols, vec_tmp.rend());
                encoder.encode(vec_tmp, A.scale(), plain_tmp);
                evaluator.mod_switch_to_inplace(plain_tmp, A.parms_id());
                evaluator.multiply_plain(cipher_rotate[j], plain_tmp, cipher_tmp);
                sum_mul++;
                cipher_vector.push_back(cipher_tmp);
            }
        }
        evaluator.add_many(cipher_vector, cipher_tmp);
        evaluator.relinearize_inplace(cipher_tmp, relin_keys);
        evaluator.rescale_to_next_inplace(cipher_tmp);
        evaluator.rotate_vector_inplace(cipher_tmp, i * rotate_inside_size*cols, gal_keys);
        sum_rotate++;
        cipher_result.push_back(cipher_tmp);
    }
    evaluator.add_many(cipher_result, result);
    auto end = std::chrono::high_resolution_clock::now();
    elapsed_time += std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

}



//decrypte matrix multiply result
void decrypte_result_jiang(Ciphertext& w_encrypted, seal::Decryptor& decryptor, seal::CKKSEncoder& encoder) {
    // auto start = std::chrono::high_resolution_clock::now();
    Plaintext plain_tmp;
    vector<double> vec_tmp;

    decryptor.decrypt(w_encrypted, plain_tmp);
    encoder.decode(plain_tmp, vec_tmp);
    // auto end = std::chrono::high_resolution_clock::now();
    // double elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    // cout << "        + decrypte result data:" << elapsed_time << " μs" << endl;
    for (int i = 0; i < 10; i++) {
        cout << vec_tmp[i] << "  "<<vec_tmp[i+64]<<endl;
    }
    cout<<endl;
}

/*Function matrix multiply vector(Baby-Step-Giant-Step Method)
* Input: plaintext matrix A and ciphertext vector v
* Output: ciphertext A*v
*/
template<typename T>
void matrix_multiply_cipher_vector(matrix<T>& A, Ciphertext& v,int paddinglength, Ciphertext& destination, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys, seal::RelinKeys& relin_keys, seal::Decryptor& decryptor, seal::CKKSEncoder& encoder)
{
	//matrix multiply vector
	vector<vector<T>> diag_matrix_A;
	diag_matrix_A = A.diag_matrix();

	int rotate_size = diag_matrix_A.size();
	int rotate_outside_size = ceil(sqrt(rotate_size));
	int rotate_inside_size = ceil(double(rotate_size) / double(rotate_outside_size));

	int length = parms.poly_modulus_degree() / 2;
	int sum_rotate = 0;
	int sum_mul = 0;

	seal::Ciphertext tmp;
	seal::Ciphertext group_cipher;//group cipher result
	vector<seal::Ciphertext> rotate_vector;//rotate cipher result
	vector<seal::Ciphertext> result_vector;//matrix multiply vector

	/*tmp */
	seal::Plaintext plain_tmp;
	vector<T> vec_tmp,vec;

    /*padding*/
    evaluator.rotate_vector(v, -paddinglength, gal_keys, tmp);
    evaluator.add_inplace(v, tmp);
    //cout << paddinglength << endl;

	for (int j = 0; j < rotate_inside_size; j++) {
		evaluator.rotate_vector(v, j, gal_keys, tmp);
		sum_rotate += 1;
		rotate_vector.push_back(tmp);
		
		decryptor.decrypt(tmp, plain_tmp);
		encoder.decode(plain_tmp, vec_tmp);
	}


	/* start plain matrix multiply cipher vector*/
	for (int i = 0; i < rotate_outside_size; i++) {

		vector<seal::Ciphertext> cipher_tmp;
        bool flag = true;
		for (int j = 0; j < rotate_inside_size; j++) {
            if (std::all_of(diag_matrix_A[i * rotate_inside_size + j].begin(), diag_matrix_A[i * rotate_inside_size + j].end(), [](T num) { return num == 0; }) == 1) {
                continue;
            }
            else {
                flag = false;
                vec = diag_matrix_A[i * rotate_inside_size + j];
                std::rotate(vec.rbegin(), vec.rbegin() + i * rotate_inside_size, vec.rend());
                encoder.encode(vec, rotate_vector[j].scale(), plain_tmp);
                evaluator.mod_switch_to_inplace(plain_tmp, rotate_vector[j].parms_id());
                evaluator.multiply_plain(rotate_vector[j], plain_tmp, tmp);
                cipher_tmp.push_back(tmp);
                sum_mul += 1;
            }
		}
        if (flag == true) {
            continue;
        }
		evaluator.add_many(cipher_tmp, tmp);
		evaluator.relinearize_inplace(tmp, relin_keys);
		evaluator.rescale_to_next_inplace(tmp);
        evaluator.rotate_vector_inplace(tmp, i * rotate_inside_size, gal_keys);
		result_vector.push_back(tmp);
		sum_rotate += 1;
	}
	evaluator.add_many(result_vector, group_cipher);
    decryptor.decrypt(group_cipher, plain_tmp);
    encoder.decode(plain_tmp, vec_tmp);
    // for (int i = 0; i < paddinglength; i++) {
    //     cout << vec_tmp[i] << "  ";
    // }
    // cout << endl;
	destination = group_cipher;
	// cout << "           + Rotate: " << sum_rotate << "  Multiply: " << sum_mul << endl;
}


// function: rotating ct.A(0) to ct.A(k)
void rotate_ctA(seal::Ciphertext& ctA, int i, int cols, int rows, seal::Ciphertext& destination,seal::Evaluator &evaluator,seal::GaloisKeys &gal_keys, seal::RelinKeys& relin_keys, seal::CKKSEncoder& encoder) {
    // step1.1.1 generate vector
    if (i != 0) {
        vector<double> rotate_right(cols * rows), rotate_left(cols * rows);
        seal::Plaintext right_plain, left_plain;
        seal::Ciphertext right_cipher, left_cipher, result_cipher;
        for (int j = 0; j < rows; j++) {
            int k = 0;
            while (k < cols) {
                if (k >= cols-i) {
                    rotate_right[j * rows + k] = 1;
                }
                else {
                    rotate_left[j * rows + k] = 1;
                }
                k++;
            }
        }

        //step1.1.2 encode vector
        encoder.encode(rotate_right, ctA.scale(), right_plain);
        evaluator.mod_switch_to_inplace(right_plain, ctA.parms_id());
        encoder.encode(rotate_left, ctA.scale(), left_plain);
        evaluator.mod_switch_to_inplace(left_plain, ctA.parms_id());


        //step1.1.3 rotate and multiply
        evaluator.rotate_vector(ctA, rows * cols - rows + i, gal_keys, right_cipher);
        evaluator.rotate_vector(ctA, i, gal_keys, left_cipher);
        evaluator.multiply_plain_inplace(right_cipher, right_plain);
        evaluator.multiply_plain_inplace(left_cipher, left_plain);
        evaluator.add(right_cipher, left_cipher, result_cipher);
        evaluator.relinearize_inplace(result_cipher, relin_keys);
        evaluator.rescale_to_next_inplace(result_cipher);
        destination = result_cipher;
    }
    else {
        vector<double> rotate_all(cols * rows, 1);
        Plaintext plain_tmp;
        Ciphertext result_cipher;
        encoder.encode(rotate_all, ctA.scale(), plain_tmp);
        evaluator.mod_switch_to_inplace(plain_tmp, ctA.parms_id());
        evaluator.multiply_plain(ctA, plain_tmp, result_cipher);
        evaluator.relinearize_inplace(result_cipher, relin_keys);
        evaluator.rescale_to_next_inplace(result_cipher);
        destination = result_cipher;
    }
}


/*
* ciphertext matrix A multiply ciphertext matrix B (Jiangs' function )
* Input: ct.A(0) and ct.B(0)
* Output: ciphertext matrix C=A*B 
*/
void matrix_multiply_matrix(Ciphertext &ctA, Ciphertext& ctB,int rows,int cols, Ciphertext& destination, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys, seal::RelinKeys& relin_keys, seal::Decryptor& decryptor, seal::CKKSEncoder& encoder)
{
    vector<Ciphertext>  cipher_vector;
    Ciphertext cipher_tmpA,cipher_tmpB,cipher_tmp;//save intermediate variables
    Plaintext plain_tmp;
    vector<double> vec_tmp;
    int sum_rotate = 0;
    int sum_mul = 0;

    // start
    // auto start = std::chrono::high_resolution_clock::now();
    //step.0 padding Ciphertext ctA and ctB
    evaluator.rotate_vector(ctA, -rows * cols, gal_keys, cipher_tmpA);
    evaluator.add_inplace(ctA, cipher_tmpA);
    evaluator.rotate_vector(ctB, -rows*cols, gal_keys, cipher_tmpB);
    evaluator.add_inplace(ctB, cipher_tmpB);
    sum_rotate += 2;

    //step1. multiply
    for (int i = 0; i < rows; i++) {
        //step1.1 move ct.A(0)-->ct.A(i)
        rotate_ctA(ctA, i, cols, rows, cipher_tmpA, evaluator, gal_keys, relin_keys, encoder);
        evaluator.rotate_vector(ctB, rows*i, gal_keys,cipher_tmpB);
        evaluator.mod_switch_to_inplace(cipher_tmpB, cipher_tmpA.parms_id());
        evaluator.multiply(cipher_tmpA, cipher_tmpB, cipher_tmp);
        cipher_vector.push_back(cipher_tmp);
        sum_rotate += 3;
        sum_mul += 3;
    }
    evaluator.add_many(cipher_vector, destination);
    evaluator.relinearize_inplace(destination, relin_keys);
    evaluator.rescale_to_next_inplace(destination);
    sum_mul++;

    // auto end = std::chrono::high_resolution_clock::now();
    // double elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    // cout << "        + Multiply time:" << elapsed_time << " μs" << endl;
    // cout << "           + Rotate: " << sum_rotate << "  Multiply: " << sum_mul << endl;
}
void matrix_multiply_matrix_version64(Ciphertext &ctA, Ciphertext& ctB,int rows,int cols, Ciphertext& destination, seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys, seal::RelinKeys& relin_keys, seal::Decryptor& decryptor, seal::CKKSEncoder& encoder)
{
    vector<Ciphertext>  cipher_vector;
    Ciphertext cipher_tmpA,cipher_tmpB,cipher_tmp;//save intermediate variables
    Plaintext plain_tmp;
    vector<double> vec_tmp;
    int sum_rotate = 0;
    int sum_mul = 0;

    // start
    // auto start = std::chrono::high_resolution_clock::now();
    //step1. multiply
    for (int i = 0; i < rows; i++) {
        //step1.1 move ct.A(0)-->ct.A(i)
        rotate_ctA(ctA, i, cols, rows, cipher_tmpA, evaluator, gal_keys, relin_keys, encoder);
        evaluator.rotate_vector(ctB, rows*i, gal_keys,cipher_tmpB);
        evaluator.mod_switch_to_inplace(cipher_tmpB, cipher_tmpA.parms_id());
        evaluator.multiply(cipher_tmpA, cipher_tmpB, cipher_tmp);
        cipher_vector.push_back(cipher_tmp);
        sum_rotate += 3;
        sum_mul += 3;
    }
    evaluator.add_many(cipher_vector, destination);
    evaluator.relinearize_inplace(destination, relin_keys);
    evaluator.rescale_to_next_inplace(destination);
    sum_mul++;

    // auto end = std::chrono::high_resolution_clock::now();
    // double elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    // cout << "        + Multiply time:" << elapsed_time << " μs" << endl;
    // cout << "           + Rotate: " << sum_rotate << "  Multiply: " << sum_mul << endl;
}

/*
* plaintext matrix A multiply ciphertext matrix B (Jiangs' function )
* Input: A and ct.B(0)
* Output: ciphertext matrix C=A*B 
*/
void plain_matrix_multiply_cipher_matrix(matrix<double> matrix_A, Ciphertext& ctB,int rows,int cols, Ciphertext& destination, double scale,
                                         seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys, 
                                         seal::RelinKeys& relin_keys, seal::Decryptor& decryptor, seal::CKKSEncoder& encoder)
{
    std::vector<Ciphertext>  cipher_vector;
    seal::Ciphertext cipher_tmpA,cipher_tmpB,cipher_tmp;//save intermediate variables
    seal::Plaintext plain_tmp;
    std::vector<double> vec_tmp;
    int sum_rotate = 0;
    int sum_mul = 0;

    // start
    auto start = std::chrono::high_resolution_clock::now();
    //step.0 padding Ciphertext ctA and ctB
    // evaluator.rotate_vector(ctA, -rows * cols, gal_keys, cipher_tmpA);
    // evaluator.add_inplace(ctA, cipher_tmpA);
    evaluator.rotate_vector(ctB, -rows*cols, gal_keys, cipher_tmpB);
    evaluator.add_inplace(ctB, cipher_tmpB);
    sum_rotate += 1;

    //step1. multiply
    for (int i = 0; i < rows; i++) {
        //step1.1 move ct.A(0)-->ct.A(i)
        // rotate_ctA(ctA, i, cols, rows, cipher_tmpA, evaluator, gal_keys, relin_keys, encoder);
        vec_tmp=matrix_A.jiang_plain_matrix_a(i);
        encoder.encode(vec_tmp,scale,plain_tmp);
        evaluator.rotate_vector(ctB, rows*i, gal_keys,cipher_tmpB);
        evaluator.mod_switch_to_inplace(plain_tmp, cipher_tmpB.parms_id());
        evaluator.multiply_plain( cipher_tmpB,plain_tmp, cipher_tmp);
        evaluator.relinearize_inplace(cipher_tmp, relin_keys);
        evaluator.rescale_to_next_inplace(cipher_tmp);
        cipher_vector.push_back(cipher_tmp);
        sum_rotate += 1;
        sum_mul += 1;
    }
    evaluator.add_many(cipher_vector, destination);
    sum_mul++;

    auto end = std::chrono::high_resolution_clock::now();
    double elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    print_line(__LINE__);
    cout<<"Plain And Cipher Multiply "<<endl;
    cout << "        + time:" << elapsed_time << " μs" << endl;
    cout << "        + Rotate: " << sum_rotate << "  Multiply: " << sum_mul << endl;
}

void plain_matrix_multiply_cipher_matrix_version64(matrix<double> matrix_A, Ciphertext& ctB,int rows,int cols, Ciphertext& destination, double scale,
                                         seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys, 
                                         seal::RelinKeys& relin_keys, seal::Decryptor& decryptor, seal::CKKSEncoder& encoder)
{
    std::vector<Ciphertext>  cipher_vector;
    seal::Ciphertext cipher_tmpA,cipher_tmpB,cipher_tmp;//save intermediate variables
    seal::Plaintext plain_tmp;
    std::vector<double> vec_tmp;
    int sum_rotate = 0;
    int sum_mul = 0;

    // start
    auto start = std::chrono::high_resolution_clock::now();
    //step.0 padding Ciphertext ctA and ctB
    // evaluator.rotate_vector(ctA, -rows * cols, gal_keys, cipher_tmpA);
    // evaluator.add_inplace(ctA, cipher_tmpA);
    // evaluator.rotate_vector(ctB, -rows*cols, gal_keys, cipher_tmpB);
    // evaluator.add_inplace(ctB, cipher_tmpB);
    // sum_rotate += 1;

    //step1. multiply
    for (int i = 0; i < rows; i++) {
        //step1.1 move ct.A(0)-->ct.A(i)
        // rotate_ctA(ctA, i, cols, rows, cipher_tmpA, evaluator, gal_keys, relin_keys, encoder);
        vec_tmp=matrix_A.jiang_plain_matrix_a(i);
        encoder.encode(vec_tmp,scale,plain_tmp);
        evaluator.rotate_vector(ctB, rows*i, gal_keys,cipher_tmpB);
        evaluator.mod_switch_to_inplace(plain_tmp, cipher_tmpB.parms_id());
        evaluator.multiply_plain( cipher_tmpB,plain_tmp, cipher_tmp);
        cipher_vector.push_back(cipher_tmp);
        sum_rotate += 1;
        sum_mul += 1;
    }
    evaluator.add_many(cipher_vector, destination);
    evaluator.relinearize_inplace(destination, relin_keys);
    evaluator.rescale_to_next_inplace(destination);
    sum_mul++;

    auto end = std::chrono::high_resolution_clock::now();
    double elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    print_line(__LINE__);
    cout<<"Plain And Cipher Multiply "<<endl;
    cout << "        + time:" << elapsed_time << " μs" << endl;
    cout << "        + Rotate: " << sum_rotate << "  Multiply: " << sum_mul << endl;
}


void plain_matrix_multiply_cipher_matrix_version64(matrix<double> matrix_A, Ciphertext& ctB,int rows,int cols, Ciphertext& destination, double scale,
                                         seal::EncryptionParameters& parms, seal::Evaluator& evaluator, seal::GaloisKeys& gal_keys, 
                                         seal::RelinKeys& relin_keys, seal::Decryptor& decryptor, seal::CKKSEncoder& encoder,
                                         double &elapsed_time)
{
    std::vector<Ciphertext>  cipher_vector;
    seal::Ciphertext cipher_tmpA,cipher_tmpB,cipher_tmp;//save intermediate variables
    seal::Plaintext plain_tmp;
    std::vector<double> vec_tmp;
    int sum_rotate = 0;
    int sum_mul = 0;

    // start
    auto start = std::chrono::high_resolution_clock::now();
    //step.0 padding Ciphertext ctA and ctB
    // evaluator.rotate_vector(ctA, -rows * cols, gal_keys, cipher_tmpA);
    // evaluator.add_inplace(ctA, cipher_tmpA);
    // evaluator.rotate_vector(ctB, -rows*cols, gal_keys, cipher_tmpB);
    // evaluator.add_inplace(ctB, cipher_tmpB);
    // sum_rotate += 1;

    //step1. multiply
    for (int i = 0; i < rows; i++) {
        //step1.1 move ct.A(0)-->ct.A(i)
        // rotate_ctA(ctA, i, cols, rows, cipher_tmpA, evaluator, gal_keys, relin_keys, encoder);
        vec_tmp=matrix_A.jiang_plain_matrix_a(i);
        encoder.encode(vec_tmp,scale,plain_tmp);
        evaluator.rotate_vector(ctB, rows*i, gal_keys,cipher_tmpB);
        evaluator.mod_switch_to_inplace(plain_tmp, cipher_tmpB.parms_id());
        evaluator.multiply_plain( cipher_tmpB,plain_tmp, cipher_tmp);
        cipher_vector.push_back(cipher_tmp);
        sum_rotate += 1;
        sum_mul += 1;
    }
    evaluator.add_many(cipher_vector, destination);
    evaluator.relinearize_inplace(destination, relin_keys);
    evaluator.rescale_to_next_inplace(destination);
    sum_mul++;

    auto end = std::chrono::high_resolution_clock::now();
    elapsed_time += std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
}















