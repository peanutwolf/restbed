find_library( ssl_LIBRARY_STATIC libssl.a  ssleay32.lib HINTS "${PROJECT_SOURCE_DIR}/dependency/openssl/out32" "${PROJECT_SOURCE_DIR}/dependency/openssl" "/usr/local/opt/openssl/lib" "/usr/lib" "/usr/local/lib" "/opt/local/lib" )
find_library( crypto_LIBRARY_STATIC libcrypto.a libeay32.lib HINTS "${PROJECT_SOURCE_DIR}/dependency/openssl/out32" "${PROJECT_SOURCE_DIR}/dependency/openssl" "/usr/local/opt/openssl/lib" "/usr/lib" "/usr/local/lib" "/opt/local/lib" )

find_library( ssl_LIBRARY_SHARED libssl.so libssl.dylib ssleay32.dll HINTS "${PROJECT_SOURCE_DIR}/dependency/openssl/out32dll" "${PROJECT_SOURCE_DIR}/dependency/openssl" "/usr/local/opt/openssl/lib" "/usr/lib" "/usr/local/lib" "/opt/local/lib" )
find_library( crypto_LIBRARY_SHARED libcrypto.so libcrypto.dylib libeay32.dll HINTS "${PROJECT_SOURCE_DIR}/dependency/openssl/out32dll" "${PROJECT_SOURCE_DIR}/dependency/openssl" "/usr/local/opt/openssl/lib" "/usr/lib" "/usr/local/lib" "/opt/local/lib" )
set(ssl_LIBRARY_SHARED  "${PROJECT_SOURCE_DIR}/dependency/openssl/out32dll/ssleay32.dll")
set(crypto_LIBRARY_SHARED  "${PROJECT_SOURCE_DIR}/dependency/openssl/out32dll/libeay32.dll")

find_path( ssl_INCLUDE openssl/ssl.h HINTS "${PROJECT_SOURCE_DIR}/dependency/openssl/inc32" "${PROJECT_SOURCE_DIR}/dependency/openssl/include" "/usr/local/opt/openssl/include" "/usr/include" "/usr/local/include" "/opt/local/include" )

if ( ssl_LIBRARY_STATIC AND ssl_LIBRARY_SHARED AND crypto_LIBRARY_STATIC AND crypto_LIBRARY_SHARED )
    set( OPENSSL_FOUND TRUE )
    add_definitions( -DBUILD_SSL=TRUE )

    if ( APPLE AND BUILD_SSL )
        set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated-declarations" )
    endif( )

    message( STATUS "Found OpenSSL include at: ${ssl_INCLUDE}" )
    message( STATUS "Found OpenSSL library at: ${ssl_LIBRARY_STATIC}" )
    message( STATUS "Found OpenSSL library at: ${ssl_LIBRARY_SHARED}" )
    message( STATUS "Found Crypto library at: ${crypto_LIBRARY_STATIC}" )
    message( STATUS "Found Crypto library at: ${crypto_LIBRARY_SHARED}" )
else ( )
	message( STATUS "Found OpenSSL include at: ${ssl_INCLUDE}" )
    message( STATUS "Found OpenSSL library at: ${ssl_LIBRARY_STATIC}" )
    message( STATUS "Found OpenSSL library at: ${ssl_LIBRARY_SHARED}" )
    message( STATUS "Found Crypto library at: ${crypto_LIBRARY_STATIC}" )
    message( STATUS "Found Crypto library at: ${crypto_LIBRARY_SHARED}" )
    message( FATAL_ERROR "Failed to locate OpenSSL dependency. see restbed/dependency/openssl; ./config shared; make all" )
	
endif ( )
