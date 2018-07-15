工程目录如下所示:
dpdk  hyperscan  l2fwd-hyperscan

1. 安装hyperscan
sudo apt-get install cmake
sudo apt-get install libboost-all-dev
sudo apt-get install ragel
sudo apt-get install libpcap-dev
sudo apt-get install sqlite3

cmake CMakeLists.txt
make
2. 安装并编译DPDK
3. 绑定网卡

4. 编译工具
    export RTE_SDK=你的DPDK路径到x86_64-native-linuxapp-gcc级别：例如/home/user/work/dpdk/x86_64-native-linuxapp-gcc
    export HYPERSCAN_SDK=你的hyperscan路径:例如/home/user/work/hyperscan
    cd l2fwd-hyperscan
    cd src
    make

5. 启动工具
    cd ../
    ./l2fwd-hyperscan -c 1 -n 1 -- -p 1
