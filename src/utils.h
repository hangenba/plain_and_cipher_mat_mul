#include<iostream>
#include<fstream>
#include<iomanip>
#include"matrix.h"
#include<string>
#include"seal/seal.h"

using namespace std;
using namespace seal;

template<typename T>
void read_model(matrix<T>& Ma,string filename)
{
    fstream infile(filename+"/model.txt");
    if (!infile.is_open())
    {
        cout << "open .txt fail" << endl;
        return;
    }
    string line;
    int row = 0;
    int nSPos, nEPos;
    //循环读到文件尾
    while (!infile.eof()) {
        getline(infile, line);
        nSPos = 0;
        nEPos = 1;
        int col = 0;
        while (true) {
            nEPos = line.find('\t', nSPos);
            if (nEPos == -1 && nSPos == 0) { break; }
            if (nEPos == -1) {
                Ma(row, col) = stod(line.substr(nSPos, line.length() - nSPos));
                //cout  << stod(line.substr(nSPos, line.length() - nSPos)) << endl;
                break;
            }
            Ma(row, col) = stod(line.substr(nSPos, line.length() - nSPos));
            //cout  << stod(line.substr(nSPos, nEPos - nSPos)) << endl;
            nSPos = nEPos;
            nSPos++;
            col++;
        }
        row++;
    }
    infile.close();
    //Ma.print(3, 7);
    cout << "    + read model matrix already" << endl;
}


template<typename T>
void read_features(vector<T>& v,string filename)
{

    //读入特征信息，根据特征信息加密矩阵
    fstream infile(filename + "/features.txt");
    if (!infile.is_open())
    {
        cout << "open .txt fail" << endl;
        return;
    }
    string line;
    int nSPos, nEPos;
    getline(infile, line);
    nSPos = 0;
    nEPos = 1;
    while (true) {
        nEPos = line.find('\t', nSPos);
        if (nEPos == -1 && nSPos == 0) { break; }
        if (nEPos == -1) {
            v.push_back(stod(line.substr(nSPos, line.length() - nSPos)));
            break;
        }
        v.push_back(stod(line.substr(nSPos, nEPos - nSPos)));
        nSPos = nEPos;
        nSPos++;
    }
    infile.close();
}


template<typename T>
void read_data(matrix<T>& Ma,string filename)
{
    vector<int> v;
    read_features(v,filename);
    fstream infile(filename+"/x_test.txt");
    if (!infile.is_open())
    {
        cout << "open .txt fail" << endl;
        return;
    }
    string line;
    int row = 0;
    int nSPos, nEPos;
    int tmp;
    //循环读到文件尾
    while (!infile.eof()) {
        getline(infile, line);
        nSPos = 0;
        nEPos = 1;
        int col = 0;
        int features_num = 0;
        while (true) {
            nEPos = line.find('\t', nSPos);
            if (nEPos == -1 && nSPos == 0) { break; }
            if (nEPos == -1) {
                tmp = stod(line.substr(nSPos, line.length() - nSPos));
                Ma(row, col + tmp - 1) = 1;

                break;
            }
            tmp = stod(line.substr(nSPos, nEPos - nSPos));
            Ma(row, col + tmp - 1) = 1;
            nSPos = nEPos;
            nSPos++;
            col = col + v[features_num];
            features_num++;
        }
        row++;
    }
    infile.close();
    cout << "    + read client matrix already" << endl;
}

template<typename T>
void read_prior(vector<T>& v,string filename)
{
    fstream infile(filename+"/model_prior.txt");
    if (!infile.is_open())
    {
        cout << "open .txt fail" << endl;
        return;
    }
    string line;
    int nSPos, nEPos;
    getline(infile, line);
    nSPos = 0;
    nEPos = 1;
    while (true) {
        nEPos = line.find('\t', nSPos);
        if (nEPos == -1 && nSPos == 0) { break; }
        if (nEPos == -1) {
            v.push_back(stod(line.substr(nSPos, line.length() - nSPos)));
            break;
        }
        v.push_back(stod(line.substr(nSPos, nEPos - nSPos)));
        nSPos = nEPos;
        nSPos++;
    }
    infile.close();
    cout << "    + read model prior already" << endl;
}

template<typename T>
void matrix_add_prior_and_noise(seal::Ciphertext& C,vector<T> vec_prior,int matrix_rows,int matrix_cols, Ciphertext& destination, seal::Evaluator& evaluator,seal::CKKSEncoder &encoder)
{
	random_device rd;//获得随机数种子
	mt19937 gen(rd());//使用随机种子初始化 Mersenne Twister 引擎
	uniform_real_distribution<float> dis(0.0, 5.0);

	int true_row=vec_prior.size();
	vector<double> vec_noise;
	for (int i = 0; i < matrix_cols; i++) {
		double random_num = dis(gen);
		int j = 0;
		vector<double> vec_tmp(matrix_rows, 0);
		while (j < true_row) {
			vec_tmp[j] =vec_prior[j]+random_num;
			j++;
		}
		vec_noise.insert(vec_noise.end(), vec_tmp.begin(), vec_tmp.end());
	}

	//cout << vec_noise.size() << endl;
	/*for (int i = 0; i < vec_noise.size(); i++) {
		cout << vec_noise[i] << endl;
	}*/

	seal::Plaintext plain_tmp;
	encoder.encode(vec_noise, C.scale(), plain_tmp);
	evaluator.mod_switch_to_inplace(plain_tmp, C.parms_id());
	evaluator.add_plain(C, plain_tmp, destination);
}

template<typename T>
void matrix_add_prior_and_noise_jiang(seal::Ciphertext& C,vector<T> vec_prior,int matrix_rows,int matrix_cols,int true_col, Ciphertext& destination, seal::Evaluator& evaluator,seal::CKKSEncoder &encoder)
{
	random_device rd;//获得随机数种子
	mt19937 gen(rd());//使用随机种子初始化 Mersenne Twister 引擎
	uniform_real_distribution<float> dis(0.0, 5.0);

    vector<double> noise;
    for(int i=0;i<true_col;i++){
        double random_num = dis(gen);
        noise.push_back(random_num);
    }
	int true_row=vec_prior.size();
	vector<double> vec_noise;
	for(int i=0;i<true_row;i++){
        double value=vec_prior[i];
        vector<double> vec_tmp(true_col,value);
        int j=0;
        while(j<true_col){
            vec_tmp[j]+=noise[j];
            j++;
        }
        vec_tmp.resize(matrix_cols);
        vec_noise.insert(vec_noise.end(), vec_tmp.begin(), vec_tmp.end());
    }


	// cout << vec_noise.size() << endl;
	// for (int i = 0; i < vec_noise.size(); i++) {
	// 	cout << vec_noise[i] << endl;
	// }

	seal::Plaintext plain_tmp;
	encoder.encode(vec_noise, C.scale(), plain_tmp);
	evaluator.mod_switch_to_inplace(plain_tmp, C.parms_id());
	evaluator.add_plain(C, plain_tmp, destination);
}


void decrypte_bayes_result(seal::Ciphertext &C,int matrix_rows,int matrix_cols,int ture_rows,string filename,seal::Decryptor &decryptor,seal::CKKSEncoder &encoder){
    auto start = std::chrono::high_resolution_clock::now();
    Plaintext plain_tmp;
    vector<double> vec_tmp;

    ofstream MyFile(filename,std::ofstream::out|std::ofstream::trunc);

    decryptor.decrypt(C, plain_tmp);
    encoder.decode(plain_tmp, vec_tmp);
    for(int i=0;i<matrix_cols;i++){
        int j=0;
        int max_value=vec_tmp[i*matrix_rows];
        int max_index=0;
        while(j<ture_rows){
            if(vec_tmp[i*matrix_rows+j]>max_value){
                max_value=vec_tmp[i*matrix_rows+j];
                max_index=j;
            }
            j++;
        }
        MyFile << setprecision(10) << max_index << endl;
    }
    auto end = std::chrono::high_resolution_clock::now();
    double elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    print_line(__LINE__);
    cout<<"Decrypte Result"<<endl;
    cout << "        + time:" << elapsed_time << " μs" << endl;
}

void decrypte_bayes_result(seal::Ciphertext &C,int matrix_rows,int matrix_cols,int ture_rows,string filename,seal::Decryptor &decryptor,seal::CKKSEncoder &encoder,double &elapsed_time){
    auto start = std::chrono::high_resolution_clock::now();
    Plaintext plain_tmp;
    vector<double> vec_tmp;

    ofstream MyFile(filename,std::ofstream::out|std::ofstream::app);

    decryptor.decrypt(C, plain_tmp);
    encoder.decode(plain_tmp, vec_tmp);
    for(int i=0;i<matrix_cols;i++){
        int j=0;
        int max_value=vec_tmp[i*matrix_rows];
        int max_index=0;
        while(j<ture_rows){
            if(vec_tmp[i*matrix_rows+j]>max_value){
                max_value=vec_tmp[i*matrix_rows+j];
                max_index=j;
            }
            j++;
        }
        MyFile << setprecision(10) << max_index << endl;
    }
    auto end = std::chrono::high_resolution_clock::now();
    elapsed_time += std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
}
void decrypte_bayes_result_jiang(seal::Ciphertext &C,int matrix_rows,int matrix_cols,int max_size,string filename,seal::Decryptor &decryptor,seal::CKKSEncoder &encoder){
    auto start = std::chrono::high_resolution_clock::now();
    Plaintext plain_tmp;
    vector<double> vec_tmp;

    ofstream MyFile(filename,std::ofstream::out|std::ofstream::trunc);

    decryptor.decrypt(C, plain_tmp);
    encoder.decode(plain_tmp, vec_tmp);
    for(int i=0;i<matrix_cols;i++){
        int j=0;
        int max_value=vec_tmp[i];
        int max_index=0;
        while(j<matrix_rows){
            if(vec_tmp[i+max_size*j]>max_value){
                max_value=vec_tmp[i+max_size*j];
                max_index=j;
            }
            j++;
        }
        MyFile << setprecision(10) << max_index << endl;
    }
    auto end = std::chrono::high_resolution_clock::now();
    double elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    print_line(__LINE__);
    cout<<"Decrypte Result"<<endl;
    cout << "        + time:" << elapsed_time << " μs" << endl;
}
void decrypte_bayes_result_jiang(seal::Ciphertext &C,int matrix_rows,int matrix_cols,int max_size,string filename,seal::Decryptor &decryptor,seal::CKKSEncoder &encoder,double &elapsed_time){
    auto start = std::chrono::high_resolution_clock::now();
    Plaintext plain_tmp;
    vector<double> vec_tmp;

    ofstream MyFile(filename,std::ofstream::out|std::ofstream::app);

    decryptor.decrypt(C, plain_tmp);
    encoder.decode(plain_tmp, vec_tmp);
    for(int i=0;i<matrix_cols;i++){
        int j=0;
        int max_value=vec_tmp[i];
        int max_index=0;
        while(j<matrix_rows){
            if(vec_tmp[i+max_size*j]>max_value){
                max_value=vec_tmp[i+max_size*j];
                max_index=j;
            }
            j++;
        }
        MyFile << setprecision(10) << max_index << endl;
    }
    auto end = std::chrono::high_resolution_clock::now();
    elapsed_time += std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
}