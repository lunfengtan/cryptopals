# Cryptopals
# common library

add_library (cryptopals
                cryptopals.c
            )
target_link_libraries (cryptopals ${OPENSSL_LIBRARIES} -fsanitize=address)
