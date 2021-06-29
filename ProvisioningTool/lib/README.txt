Instructions to build jsoncpp

https://github.com/open-source-parsers/jsoncpp/tree/0.y.z

unzip jsoncpp-0.y.z.zip
cd jsoncpp-0.y.z

$ mkdir -p build/debug
$ cd build/debug
$ cmake -DCMAKE_BUILD_TYPE=debug -DBUILD_STATIC_LIBS=ON -DBUILD_SHARED_LIBS=ON -DARCHIVE_INSTALL_DIR=. -G "Unix Makefiles" ../..
$ make
 // Check the generated static and dynamic link library
$ find . -name *.a
./src/lib_json/libjsoncpp.a
$ find . -name *.so
./src/lib_json/libjsoncpp.so
