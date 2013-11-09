use std::libc::{c_char, c_int, c_ulong, c_void, size_t};

mod ll {
    // Opaque types, yay
    type RSA = c_void;
    type BIO_METHOD = c_void;
    type BIO = c_void;

    // Some constants
    static RSA_PKCS1_PADDING: c_int = 1;
    static RSA_SSLV23_PADDING: c_int = 2;
    static RSA_NO_PADDING: c_int = 3;
    static RSA_PKCS1_OAEP_PADDING: c_int = 4;
    static RSA_X931_PADDING: c_int = 5;

    extern {
        fn RSA_generate_key(n: c_int, e: c_ulong, _: *c_void, _: *c_void) -> *RSA;
        fn RSA_free(k: *RSA);
        fn RSA_size(k: *RSA) -> c_int;
        fn RSA_public_encrypt(flen: c_int, from: *c_char, to: *c_char, rsa: *RSA, padding: c_int) -> c_int;
        fn RSA_private_decrypt(flen: c_int, from: *c_char, to: *c_char, rsa: *RSA, padding: c_int) -> c_int;

        fn BIO_new(t: *BIO_METHOD) -> *BIO;
        fn BIO_free(a: *BIO);
        fn BIO_s_mem() -> *BIO_METHOD;
        fn BIO_pending(b: *BIO) -> c_int;
        fn BIO_read(b: *BIO, buf: *c_void, sz: c_int) -> c_int;
    }
}
