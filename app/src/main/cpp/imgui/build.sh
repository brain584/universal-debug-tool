export PATH=/data/data/com.tom.rv2ide/files/home/android-sdk/ndk/29.0.14033849:$PATH
echo "配置环境变量完成..."
echo "解析依赖中..."
time ndk-build -j$(nproc)
echo "构建程序完成..."
