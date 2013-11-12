use std::libc::{c_int, c_ulong, c_void};
use std::{ptr, str, vec};

mod ll {
    use std::libc::{c_int, c_uchar, c_ulong, c_void, size_t};

    // Opaque types, yay
    pub type RSA = c_void;
    type BIO_METHOD = c_void;
    type BIO = c_void;

    // Some constants
    pub static RSA_PKCS1_PADDING: c_int = 1;
    pub static RSA_SSLV23_PADDING: c_int = 2;
    pub static RSA_NO_PADDING: c_int = 3;
    pub static RSA_PKCS1_OAEP_PADDING: c_int = 4;
    pub static RSA_X931_PADDING: c_int = 5;

    #[link_args = "-lssl -lcrypto"]
    extern {
        pub fn RSA_generate_key(n: c_int, e: c_ulong, _: *c_void, _: *c_void) -> *RSA;
        pub fn RSA_free(k: *RSA);
        pub fn RSA_size(k: *RSA) -> c_int;
        pub fn RSA_public_encrypt(flen: c_int, from: *c_uchar, to: *c_uchar, rsa: *RSA, padding: c_int) -> c_int;
        pub fn RSA_private_decrypt(flen: c_int, from: *c_uchar, to: *c_uchar, rsa: *RSA, padding: c_int) -> c_int;

        pub fn BIO_new(t: *BIO_METHOD) -> *BIO;
        pub fn BIO_free_all(a: *BIO);
        pub fn BIO_s_mem() -> *BIO_METHOD;
        pub fn BIO_ctrl_pending(b: *BIO) -> size_t;
        pub fn BIO_read(b: *BIO, buf: *c_void, sz: c_int) -> c_int;

        pub fn PEM_read_bio_RSAPublicKey(b: *BIO, x: **RSA, _: *c_void, _: *c_void) -> *RSA;
        pub fn PEM_write_bio_RSAPublicKey(b: *BIO, x: *RSA) -> c_int;
        pub fn PEM_write_bio_RSA_PUBKEY(b: *BIO, x: *RSA) -> c_int;
        pub fn PEM_read_bio_RSAPrivateKey(b: *BIO, x: **RSA, _: *c_void, _: *c_void) -> *RSA;
        pub fn PEM_write_bio_RSAPrivateKey(b: *BIO, x: *RSA, _: *c_void, _: *c_void, _: c_int, _: *c_void, _: *c_void) -> c_int;
    }
}

struct RSAPublicKey {
    priv k: *ll::RSA
}

impl RSAPublicKey {
    pub fn encrypt(&self, data: &[u8]) -> Result<~[u8], ~str> {
        unsafe {
            let sz = ll::RSA_size(self.k);

            let buf = vec::from_elem(sz as uint, 0u8);

            let elen = ll::RSA_public_encrypt(data.len() as c_int, &data[0], &buf[0],
                                              self.k, ll::RSA_PKCS1_OAEP_PADDING);

            if elen == -1 {
                return Err(~"unable to encrypt data");
            }

            Ok(buf)
        }
    }
}

impl Drop for RSAPublicKey {
    fn drop(&mut self) {
        unsafe {
            ll::RSA_free(self.k);
        }
    }
}

impl ToStr for RSAPublicKey {
    fn to_str(&self) -> ~str {
        unsafe {
            let bio = ll::BIO_new(ll::BIO_s_mem());
            ll::PEM_write_bio_RSA_PUBKEY(bio, self.k);

            let len = ll::BIO_ctrl_pending(bio);
            let buf = vec::from_elem(len as uint, 0u8);
            ll::BIO_read(bio, &buf[0] as *u8 as *c_void, len as c_int);

            ll::BIO_free_all(bio);

            str::from_utf8_owned(buf)
        }
    }
}

struct RSAPrivateKey {
    priv k: *ll::RSA
}

impl RSAPrivateKey {
    pub fn decrypt(&self, data: &[u8]) -> Result<~[u8], ~str> {
        unsafe {
            let mut buf = vec::from_elem(data.len(), 0u8);

            let dlen = ll::RSA_private_decrypt(data.len() as c_int, &data[0], &buf[0],
                                               self.k, ll::RSA_PKCS1_OAEP_PADDING);

            if dlen == -1 {
                return Err(~"unable to decrypt data");
            }

            vec::raw::set_len(&mut buf, dlen as uint);

            Ok(buf)
        }
    }
}

impl Drop for RSAPrivateKey {
    fn drop(&mut self) {
        unsafe {
            ll::RSA_free(self.k);
        }
    }
}

impl ToStr for RSAPrivateKey {
    fn to_str(&self) -> ~str {
        unsafe {
            let bio = ll::BIO_new(ll::BIO_s_mem());
            ll::PEM_write_bio_RSAPrivateKey(bio, self.k, ptr::null(), ptr::null(),
                                            0, ptr::null(), ptr::null());

            let len = ll::BIO_ctrl_pending(bio);
            debug!("len - {}", len);
            let buf = vec::from_elem(len as uint, 0u8);
            ll::BIO_read(bio, &buf[0] as *u8 as *c_void, len as c_int);

            ll::BIO_free_all(bio);

            str::from_utf8_owned(buf)
        }
    }
}

struct RSAKeyPair {
    pub_key: RSAPublicKey,
    pri_key: RSAPrivateKey,
}

impl RSAKeyPair {
    pub fn new(sz: uint, e: uint) -> Result<RSAKeyPair, ~str> {
        unsafe {
            let kp = ll::RSA_generate_key(sz as c_int, e as c_ulong, ptr::null(), ptr::null());
            if kp.is_null() {
                return Err(~"unable to generate keypair");
            }

            let pub_bio = ll::BIO_new(ll::BIO_s_mem());
            let pri_bio = ll::BIO_new(ll::BIO_s_mem());

            ll::PEM_write_bio_RSAPublicKey(pub_bio, kp);
            ll::PEM_write_bio_RSAPrivateKey(pri_bio, kp, ptr::null(), ptr::null(),
                                            0, ptr::null(), ptr::null());

            let pub_key = ll::PEM_read_bio_RSAPublicKey(pub_bio, ptr::null(), ptr::null(), ptr::null());
            let pri_key = ll::PEM_read_bio_RSAPrivateKey(pri_bio, ptr::null(), ptr::null(), ptr::null());

            ll::BIO_free_all(pub_bio);
            ll::BIO_free_all(pri_bio);

            ll::RSA_free(kp);

            Ok(RSAKeyPair {
                pub_key: RSAPublicKey { k: pub_key },
                pri_key: RSAPrivateKey { k: pri_key },
            })
        }
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<~[u8], ~str> {
        self.pub_key.encrypt(data)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<~[u8], ~str> {
        self.pri_key.decrypt(data)
    }
}

impl ToStr for RSAKeyPair {
    fn to_str(&self) -> ~str {
        format!("{}\n{}", self.pub_key.to_str(), self.pri_key.to_str())
    }
}
