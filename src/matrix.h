#pragma once
#ifndef MATRIX_H
#define MATRIX_H

#include<iomanip>
#include<iostream>
#include<vector>
#include<random>

template<typename T>
class matrix {
protected:
    std::size_t n, d;
    std::vector<std::vector<T> > M;

public:

    //matrix();

    // empty matrix
    matrix() : n(0), d(0) {}

    //~matrix();

    //  rows * cols, all elements are initialized with the default constructor of T
    matrix(std::size_t rows, std::size_t cols) : n(0), d(0) {
        resize(rows, cols);
    }



    void clear() {
        n = d = 0;
        M.clear();
    }

    void resize(std::size_t rows, std::size_t cols) {
        std::size_t j;
        n = rows;
        d = cols;
        M.resize(d);
        for (j = 0; j < d; j++) {
            M[j].resize(n);
        }
    }// resize

    //resize matrix size and value
    void resize(std::size_t rows, std::size_t cols, std::int64_t value) {
        std::size_t j;
        n = rows;
        d = cols;
        M.resize(d);
        for (j = 0; j < d; j++) {
            M[j].resize(n, value);
        }
    }// resize



    // return the number of rows
    int get_rows() const {
        return n;
    }

    // return the number of columns
    int get_cols() const {
        return d;
    }

    // a reference to the element (i, j)
    T& operator() (const std::size_t i, const std::size_t j) { return M[j][i]; }

    const T& operator() (const std::size_t i, const std::size_t j) const { return M[j][i]; }


    inline  T& get(const std::size_t i, const std::size_t j) { return M[j][i]; }

    inline  void set(const std::size_t i, const std::size_t j, const T a) { M[j][i] = a; }

    //operate +
    matrix operator+(const matrix& other) const {
        if (d != other.d || n != other.n) {
            throw std::runtime_error("Matrix dimensions do not match.");
        }

        matrix result(n, d);

        for (std::size_t i = 0; i < n; ++i) {
            for (std::size_t j = 0; j < d; ++j) {
                result.M[j][i] = M[j][i] + other.M[j][i];
            }
        }

        return result;
    }

     // operate *
    matrix operator*(const matrix& other) const {
        if (d != other.n) {
            throw std::runtime_error("Matrix dimensions are not compatible for multiplication.");
        }

        matrix result(n, other.d);

        for (std::size_t i = 0; i < n; ++i) {
            for (std::size_t j = 0; j < other.d; ++j) {
                for (std::size_t k = 0; k < d; ++k) {
                    result.M[j][i] += M[k][i] * other.M[j][k];
                }
            }
        }

        return result;
    }

    //the transpose of the matrix
    matrix<T> transpose() const {
        matrix<T> B(d, n);
        for (std::size_t i = 0; i < n; i++)
            for (std::size_t j = 0; j < d; j++)
                B(j, i) = M[j][i];
        return B;
    }

    // return the i-th row of the matrix; indices start from 0.
    std::vector<T> get_row(std::size_t i) {
        std::vector<T> v;
        v.resize(d);
        for (std::size_t j = 0; j < d; j++)
            v[j] = M[j][i];

        return v;
    }

    std::vector<T> get_row(std::size_t i) const {
        std::vector<T> v;
        v.resize(d);
        for (std::size_t j = 0; j < d; j++)
            v[j] = M[j][i];

        return v;
    }

    // return the last row of the matrix
    std::vector<T> get_last_row() {
        return get_row(n - 1);
    }

    std::vector<T> get_last_row() const {
        return get_row(n - 1);
    }

    // return the i-th column of the matrix; indices start from 0.
    std::vector<T> get_col(std::size_t j) {
        std::vector<T> v;
        v.resize(n);
        for (std::size_t i = 0; i < n; i++)
            v[i] = M[j][i];

        return v;
    }

    std::vector<T> get_col(std::size_t j) const {
        std::vector<T> v;
        v.resize(n);
        for (std::size_t i = 0; i < n; i++)
            v[i] = M[j][i];

        return v;
    }

    // return the last row of the matrix
    std::vector<T> get_last_col() {
        return get_col(d - 1);
    }

    std::vector<T> get_last_col() const {
        return get_col(d - 1);
    }

    // generate randon data of the matrix
    void generate_randon_data() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(1, 5); // 范围为 1 到 100 的随机整数


        for (std::size_t i = 0; i < n; i++) {
            for (std::size_t j = 0; j < d; j++) {
                M[j][i] = dis(gen);
            }
        }
    }

    void generate_order_data() {
        for (std::size_t i = 0; i < n; i++) {
            for (std::size_t j = 0; j < d; j++) {
                M[j][i] = i*d+j+1;
            }
        }
    }

    // flatten matrix to a vector by rows 
    std::vector<T> flatten_matrix_to_rows_vector() {
        std::vector<T> flat_vector(n*d);

        for (std::size_t i = 0; i < n; i++) {
            for (std::size_t j = 0; j < d; j++) {
                flat_vector[i*d+j] = M[j][i] ;
            }
        }
        return flat_vector;
    }

    // flatten matrix to a vector by cols 
    std::vector<T> flatten_matrix_to_cols_vector() {
        std::vector<T> flat_vector(n*d);

        for (std::size_t i = 0; i < d; i++) {
            for (std::size_t j = 0; j < n; j++) {
                flat_vector[i*n+j] = M[i][j] ;
            }
        }
        return flat_vector;
    }

    //diag matrix 
    std::vector<std::vector<T>> diag_matrix() {
        std::vector<std::vector<T>> diag_matrix;
        if (n != d) {
            std::cout << "matrix is not a squre" <<std::endl;
            return diag_matrix;
        }
        for (int i = 0; i < n; i++) {
            std::vector<T> diag_vector;
            for (int j = 0; j < d; j++) {
                diag_vector.push_back(M[(i + j) % d][j]);
            }
            diag_vector.resize(4096);
            diag_matrix.push_back(diag_vector);
        }
        return diag_matrix;
    }

    // get i-th diag vector
    std::vector<T> diag_vector(std::size_t i) {
        std::vector<T> diag_vector;
        if (n != d) {
            std::cout << "matrix is not a squre" << std::endl;
            return diag_vector;
        }
        for (std::size_t j = 0; j < n; j++) {
            diag_vector.push_back(M[(i + j) % d][j]);
        }
        diag_vector.resize(4096);
        return diag_vector;
    }

    // get matrix A i-th
    std::vector<T> jiang_plain_matrix_a(std::size_t i){
        std::vector<T> diag_vector;
        if (n != d) {
            std::cout << "matrix is not a squre" << std::endl;
            return diag_vector;
        }
        for (std::size_t j = 0; j < n; j++) {
            for(std::size_t k=0;k<d;k++){
                diag_vector.push_back(M[(i + j+ k) % d][j]);
            }
        }
        return diag_vector;
    }

    //generate u_sigma matrix
    void generate_u_sigma(std::size_t rows, std::size_t cols) {
        resize(rows * cols, rows * cols);
        for (std::size_t i = 0; i < cols; i++) {
            for (std::size_t j= 0; j < rows; j++) {
                M[i * rows + (j + i) % rows][i * rows + j] = 1;
            }
        }
    }

    //generate u_tau matrix
    void generate_u_tau(std::size_t rows, std::size_t cols) {
        resize(rows * cols, rows * cols);
        for (std::size_t i = 0; i < cols; i++) {
            for (std::size_t j= 0; j < rows; j++) {
                M[((rows + 1) * j + cols * i) % (rows * cols)][i * rows + j] = 1;
            }
        }
    }

    //get submatrix
    matrix<T> getSubmatrix(std::size_t startRow, std::size_t startCol, std::size_t subRows, std::size_t subCols) {
        // std::cout<<startRow + subRows<<"  "<<startCol + subCols<<std::endl;
        if (startRow + subRows > n || startCol + subCols > d) {
            throw std::out_of_range("Submatrix dimensions are out of range.");
        }

        matrix<T> submatrix(subRows, subCols);

        for (std::size_t i = 0; i < subRows; i++) {
            for (std::size_t j = 0; j < subCols; j++) {
                submatrix(i, j) = M[startCol + j][startRow + i];
            }
        }

        return submatrix;
    }

    // submatrix value
    void assignSubmatrix(const matrix<T>& submatrix, std::size_t startRow, std::size_t startCol) {
        if (startRow + submatrix.get_rows() > n || startCol + submatrix.get_cols() > d) {
            throw std::out_of_range("Submatrix dimensions are out of range.");
        }

        for (std::size_t i = 0; i < submatrix.get_rows(); i++) {
            for (std::size_t j = 0; j < submatrix.get_cols(); j++) {
                M[startCol + j][startRow + i] = submatrix(i, j);
            }
        }
    }

    void print(std::size_t rows = 6, std::size_t cols = 6) {
        size_t r = rows / 2;
        size_t c = cols / 2;

        for (size_t i = 0; i < r; i++) {
            std::cout << "    [";
            for (size_t j = 0; j < c; j++) {
                std::cout << std::setw(6) << std::right << std::right << M[j][i] << ",";
            }
            std::cout << std::setw(6) << std::right << std::right << "..." << ",";
            for (size_t j = d - cols + c; j < d - 1; j++) {
                std::cout << std::setw(6) << std::right << std::right << M[j][i] << ",";
            }
            std::cout << std::setw(6) << std::right << std::right << M[d - 1][i] << "]" << std::endl;

        }

        std::cout << "    [";
        for (size_t j = 0; j < c; j++) {
            std::cout << std::right << std::setw(6) << std::right << "..." << ",";
        }
        std::cout << std::setw(6) << std::right << std::right << "..." << ",";
        for (size_t j = d - cols + c; j < d - 1; j++) {
            std::cout << std::setw(6) << std::right << std::right << "..." << ",";
        }
        std::cout << std::setw(6) << std::right << std::right << "..." << "]" << std::endl;

        for (size_t i = n - rows + r; i < n; i++) {
            std::cout << "    [";
            for (size_t j = 0; j < c; j++) {
                std::cout << std::setw(6) << std::right << std::right << M[j][i] << ",";
            }
            std::cout << std::setw(6) << std::right << std::right << "..." << ",";
            for (size_t j = d - cols + c; j < d - 1; j++) {
                std::cout << std::setw(6) << std::right << std::right << M[j][i] << ",";
            }
            std::cout << std::setw(6) << std::right << std::right << M[d - 1][i] << "]" << std::endl;
        }
    }

}; //end of class matrix


template<typename T>
class split_matrix
{
protected:
    int n,m;
    std::vector<std::vector<matrix<T>>> M;
public:
    split_matrix():n(0),m(0){};

    split_matrix(matrix<T> A,std::size_t subrows, std::size_t subcols) : n(0), m(0) {
        int rows=A.get_rows();
        int cols=A.get_cols();
        n=std::ceil((double (rows))/(double (subrows)));
        m=std::ceil((double (cols))/(double (subcols)));
        A.resize(n*subrows,m*subcols);
        M.resize(n);
        for(int i=0;i<n;i++){
            M[i].resize(m);
            for(int j=0;j<m;j++){
                M[i][j]=A.getSubmatrix(i*subrows,j*subcols,subrows,subcols);
            }
        }
    }

    void print_submatrix(std::size_t i,std::size_t j){
        M[i][j].print(4,4);
    }

    matrix<T> get_submatrix(std::size_t i,std::size_t j){
        return M[i][j];
    }

    matrix<T> merge_submatrix(){
        matrix<T> A;
        int subn=M[0][0].get_rows();
        int subm=M[0][0].get_cols();
        A.resize(n*subn,m*subm);
        for(int i=0;i<n;i++){
            for(int j=0;j<m;j++){
                A.assignSubmatrix(M[i][j],i*subn,j*subm);
            }
        }
        return A;
    }


    
    // return the number of rows
    int get_rows() const {
        return n;
    }

    // return the number of columns
    int get_cols() const {
        return m;
    }



    ~split_matrix(){};
};



#endif // matrix.h