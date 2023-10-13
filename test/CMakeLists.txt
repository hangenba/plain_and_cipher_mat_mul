# 设置cmake版本
cmake_minimum_required(VERSION 3.13)

# 设置项目名称
project(cipher_mat_mul)

# 设置默认版本
set(CMAKE_CXX_FLAGS "-Wall")
set(CMAKE_CXX_STANDARD 17)

# 配置文件路径
set(REAL_SOURCE_DIR ${PROJECT_SOURCE_DIR}/../src)
set(TEST_SOURCE_DIR ${PROJECT_SOURCE_DIR})

# 找到seal版本
find_package(SEAL 4.1 REQUIRED)
set(SEAL_LIBRARY "SEAL::seal")

#设置头文件
add_executable(CKKS_plain_and_cipher_mat_mul
               ${REAL_SOURCE_DIR}/matrix.h
               ${REAL_SOURCE_DIR}/helper.h
               ${REAL_SOURCE_DIR}/utils.h
               ${REAL_SOURCE_DIR}/plain_and_cipher_mat_mul.h
               ${TEST_SOURCE_DIR}/plain_and_cipher_mat_mul.cpp
               )


# 链接seal
target_link_libraries(CKKS_plain_and_cipher_mat_mul SEAL::seal)
target_link_libraries(CKKS_plain_and_cipher_mat_mul stdc++fs)
