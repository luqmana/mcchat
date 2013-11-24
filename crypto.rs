use std::libc::{c_int, c_long, c_ulong, c_void, size_t};
use std::io::{Decorator, Reader, Stream, Writer};
use std::io::mem::MemWriter;
use std::{fmt, ptr, str, vec};

struct SHA1 {
    priv ctx: *ll::EVP_MD_CTX
}

impl SHA1 {
    pub fn new() -> SHA1 {
        unsafe {
            let ctx = ll::EVP_MD_CTX_create();
            ll::EVP_DigestInit(ctx, ll::EVP_sha1());

            SHA1 {
                ctx: ctx
            }
        }
    }

    pub fn init(buf: &[u8]) -> SHA1 {
        let mut s = SHA1::new();
        s.update(buf);
        s
    }

    pub fn update(&mut self, buf: &[u8]) {
        unsafe {
            let bufp = vec::raw::to_ptr(buf);
            ll::EVP_DigestUpdate(self.ctx, bufp, buf.len() as size_t);
        }
    }

    pub fn final(self) -> ~[u8] {
        unsafe {
            let mut buf = vec::from_elem(ll::EVP_MAX_MD_SIZE as uint, 0u8);
            let len = 0;

            let bufp = vec::raw::to_ptr(buf);
            ll::EVP_DigestFinal(self.ctx, bufp, &len);

            vec::raw::set_len(&mut buf, len as uint);

            buf
        }
    }

    pub fn digest(self) -> ~str {
        let buf = self.final();
        SHA1::hex(buf)
    }

    pub fn hex(buf: ~[u8]) -> ~str {
        let mut out = MemWriter::new();

        for x in buf.move_iter() {
            format_args!(|a| fmt::write(&mut out as &mut Writer, a), "{:02x}", x);
        }

        let out = out.inner();
        str::from_utf8(out.slice_to(40))
    }
}

impl Drop for SHA1 {
    fn drop(&mut self) {
        unsafe {
            ll::EVP_MD_CTX_destroy(self.ctx);
        }
    }
}

struct AES {
    priv encrypt_ctx: *ll::EVP_CIPHER_CTX,
    priv decrypt_ctx: *ll::EVP_CIPHER_CTX,
    priv key: ~[u8],
    priv iv: ~[u8]
}

impl AES {
    pub fn new(key: ~[u8], iv: ~[u8]) -> Result<AES, ~str> {
        unsafe {
            if key.len() != iv.len() {
                return Err(~"key and iv length mismatch.");
            }

            if key.len() != 16 {
                return Err(~"wrong key length.");
            }

            let ectx = ll::EVP_CIPHER_CTX_new();
            let e = ll::EVP_EncryptInit_ex(ectx, ll::EVP_aes_128_cfb8(),
                                           ptr::null(), &key[0], &iv[0]);
            if e == 0 {
                return Err(~"unable to init encrypt context.");
            }

            let dctx = ll::EVP_CIPHER_CTX_new();
            let d = ll::EVP_DecryptInit_ex(dctx, ll::EVP_aes_128_cfb8(),
                                           ptr::null(), &key[0], &iv[0]);
            if d == 0 {
                return Err(~"unable to init decrypt context.");
            }

            Ok(AES {
                encrypt_ctx: ectx,
                decrypt_ctx: dctx,
                key: key,
                iv: iv
            })
        }
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<~[u8], ~str> {
        unsafe {
            let (blen, mut elen) = (0, 0);
            let mut emsg = vec::from_elem(data.len() + ll::AES_BLOCK_SIZE as uint, 0u8);

            let outp = vec::raw::to_ptr(emsg);
            let inp = vec::raw::to_ptr(data);
            ll::EVP_EncryptUpdate(self.encrypt_ctx, outp, &blen, inp, data.len() as c_int);

            elen += blen;

            ll::EVP_EncryptFinal_ex(self.encrypt_ctx, outp.offset(elen as int), &blen);

            vec::raw::set_len(&mut emsg, (elen + blen) as uint);

            Ok(emsg)
        }
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<~[u8], ~str> {
        unsafe {
            let (blen, mut dlen) = (0, 0);
            let mut dmesg = vec::from_elem(data.len(), 0u8);

            let outp = vec::raw::to_ptr(dmesg);
            let inp = vec::raw::to_ptr(data);
            ll::EVP_DecryptUpdate(self.decrypt_ctx, outp, &blen, inp, data.len() as c_int);
            dlen += blen;

            ll::EVP_DecryptFinal_ex(self.decrypt_ctx, outp.offset(dlen as int), &blen);
            dlen += blen;

            vec::raw::set_len(&mut dmesg, dlen as uint);

            Ok(dmesg)
        }
    }
}

impl Drop for AES {
    fn drop(&mut self) {
        unsafe {
            ll::EVP_CIPHER_CTX_cleanup(self.encrypt_ctx);
            ll::EVP_CIPHER_CTX_free(self.encrypt_ctx);

            ll::EVP_CIPHER_CTX_cleanup(self.decrypt_ctx);
            ll::EVP_CIPHER_CTX_free(self.decrypt_ctx);
        }
    }
}

struct AesStream<T> {
    priv stream: T,
    priv cipher: AES
}

impl<T: Stream> AesStream<T> {
    pub fn new(s: T, c: AES) -> AesStream<T> {
        AesStream {
            stream: s,
            cipher: c
        }
    }
}

impl<T: Reader> Reader for AesStream<T> {
    fn read(&mut self, buf: &mut [u8]) -> Option<uint> {
        let ein = self.stream.read_bytes(buf.len());
        let din = match self.cipher.decrypt(ein) {
            Ok(d) => d,
            Err(_) => return None
        };
        let l = din.len();
        buf.move_from(din, 0, l);

        Some(buf.len())
    }

    fn eof(&mut self) -> bool {
        self.stream.eof()
    }
}

impl<T: Writer> Writer for AesStream<T> {
    fn write(&mut self, buf: &[u8]) {
        self.stream.write(self.cipher.encrypt(buf).unwrap());
    }

    fn flush(&mut self) {
        self.stream.flush();
    }
}

struct RSAPublicKey {
    priv k: *ll::RSA
}

impl RSAPublicKey {
    pub fn from_bytes(b: &[u8]) -> Result<RSAPublicKey, ~str> {
        unsafe {
            let p = vec::raw::to_ptr(b);

            let k = ll::d2i_RSA_PUBKEY(ptr::null(), &p, b.len() as c_long);
            if k.is_null() {
                return Err(~"unable to RSA public key");
            }

            Ok(RSAPublicKey {
                k: k
            })
        }
    }

    pub fn to_bytes(&self) -> ~[u8] {
        unsafe {
            let l = ll::i2d_RSA_PUBKEY(self.k, ptr::null());
            let buf = vec::from_elem(l as uint, 0u8);
            let p = vec::raw::to_ptr(buf);
            ll::i2d_RSA_PUBKEY(self.k, &p);

            buf
        }
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<~[u8], ~str> {
        unsafe {
            let sz = ll::RSA_size(self.k);

            let buf = vec::from_elem(sz as uint, 0u8);

            let elen = ll::RSA_public_encrypt(data.len() as c_int, &data[0], &buf[0],
                                              self.k, ll::RSA_PKCS1_PADDING);

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
                                               self.k, ll::RSA_PKCS1_PADDING);

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

mod ll {
    use std::libc::{c_int, c_long, c_uchar, c_uint, c_ulong, c_void, size_t};

    // Opaque types, yay
    pub type EVP_CIPHER_CTX = c_void;
    pub type EVP_MD_CTX = c_void;
    pub type EVP_MD = c_void;
    pub type RSA = c_void;
    type BIO_METHOD = c_void;
    type BIO = c_void;
    type EVP_CIPHER = c_void;
    type ENGINE = c_void;

    // Some constants
    pub static RSA_PKCS1_PADDING: c_int = 1;

    pub static AES_BLOCK_SIZE: c_int = 16;

    pub static EVP_MAX_MD_SIZE: c_int = 36;

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

        pub fn d2i_RSA_PUBKEY(a: **RSA, pp: **c_uchar, len: c_long) -> *RSA;
        pub fn i2d_RSA_PUBKEY(a: *RSA, pp: **c_uchar) -> c_int;

        pub fn EVP_CIPHER_CTX_new() -> *EVP_CIPHER_CTX;
        pub fn EVP_CIPHER_CTX_free(x: *EVP_CIPHER_CTX);
        pub fn EVP_CIPHER_CTX_cleanup(x: *EVP_CIPHER_CTX) -> c_int;

        pub fn EVP_EncryptInit_ex(c: *EVP_CIPHER_CTX, t: *EVP_CIPHER, e: *ENGINE, k: *c_uchar, i: *c_uchar) -> c_int;
        pub fn EVP_EncryptUpdate(c: *EVP_CIPHER_CTX, o: *c_uchar, ol: *c_int, i: *c_uchar, il: c_int) -> c_int;
        pub fn EVP_EncryptFinal_ex(c: *EVP_CIPHER_CTX, o: *c_uchar, ol: *c_int) -> c_int;
        pub fn EVP_DecryptInit_ex(c: *EVP_CIPHER_CTX, t: *EVP_CIPHER, e: *ENGINE, k: *c_uchar, i: *c_uchar) -> c_int;
        pub fn EVP_DecryptUpdate(c: *EVP_CIPHER_CTX, o: *c_uchar, ol: *c_int, i: *c_uchar, il: c_int) -> c_int;
        pub fn EVP_DecryptFinal_ex(c: *EVP_CIPHER_CTX, o: *c_uchar, ol: *c_int) -> c_int;

        pub fn EVP_aes_128_cfb8() -> *EVP_CIPHER;

        pub fn EVP_MD_CTX_create() -> *EVP_MD_CTX;
        pub fn EVP_MD_CTX_destroy(x: *EVP_MD_CTX);

        pub fn EVP_DigestInit(c: *EVP_MD_CTX, t: *EVP_MD) -> c_int;
        pub fn EVP_DigestUpdate(c: *EVP_MD_CTX, d: *c_uchar, l: size_t) -> c_int;
        pub fn EVP_DigestFinal(c: *EVP_MD_CTX, md: *c_uchar, s: *c_uint) -> c_int;

        pub fn EVP_sha1() -> *EVP_MD;
    }

    #[cfg(windows)]
    #[link_args = "-lgdi32"]
    extern {}
}
