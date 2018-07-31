# Cryptopals
# common library

add_library (cryptopals
                cryptopals.c
                mt19937.c
            )
target_link_libraries (cryptopals ${OPENSSL_LIBRARIES} -fsanitize=address)
